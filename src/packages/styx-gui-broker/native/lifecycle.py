"""Crash-injection acceptance tests for the isolated native host, no GUI grants."""
import pathlib,tempfile,subprocess,time,json,os,signal,shutil,hashlib,sys
base=pathlib.Path(sys.argv[1]).resolve()
exe=base/'Styx.app/Contents/MacOS/Styx'
driver=pathlib.Path(sys.argv[2]).resolve()
assert hashlib.sha256(driver.read_bytes()).hexdigest()=='87c7e782e69703d95524e4ceb7ceba03c8a159caabf1f1ce2c118eade7d2a5ec'
def alive(pid):
 try:os.kill(pid,0);return True
 except ProcessLookupError:return False
def wait(pred,seconds=10):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  if pred():return True
  time.sleep(.02)
 return False
def group(pgid):
 lines=subprocess.check_output(['/bin/ps','-axo','pid=,pgid=,comm='],text=True).splitlines()
 return [{'pid':int(p[0]),'pgid':int(p[1]),'exe':p[2]} for line in lines if len(p:=line.split(None,2))==3 and p[1]==str(pgid)]
records=[]
phases=['before_guard','guard_spawned','guard_armed','spawn_returned','child_registered','socket_created']
modes=['kill_at_'+p for p in phases]+['orderly_host_exit','forced_host_exit','daemon_crash','guard_crash',
 'driver_spawn_failure','existing_socket_refusal','symlink_socket_refusal','replacement_file_preserved']
try:
 for mode in modes:
  root=pathlib.Path(tempfile.mkdtemp(prefix='styx-gb-',dir='/private/tmp'));p=None;receipt=None;guard=None;members=[]
  try:
   if mode.startswith('kill_at_'):(root/'test-config.json').write_text(json.dumps({'pause_at':mode[8:]}))
   if mode=='existing_socket_refusal':(root/'driver.sock').write_text('owned-sentinel')
   if mode=='symlink_socket_refusal':(root/'driver.sock').symlink_to(root/'missing')
   selected=driver
   if mode=='driver_spawn_failure':
    selected=root/'not-executable';selected.write_text('not an executable');selected.chmod(0o600)
   with (root/'host-output.log').open('w') as log:
    p=subprocess.Popen([str(exe),str(root),str(selected)],stdout=log,stderr=log)
   if mode.endswith('_refusal'):
    p.wait(timeout=8);assert p.returncode==65
    assert (root/'driver.sock').is_symlink() if mode.startswith('symlink') else (root/'driver.sock').read_text()=='owned-sentinel'
    records.append({'test':mode,'pass':True,'exit':p.returncode});continue
   marker='stage-'+mode[8:]+'.json' if mode.startswith('kill_at_') else 'failed.json' if mode=='driver_spawn_failure' else 'ready.json'
   assert wait(lambda:(root/marker).exists()),'no stage receipt: '+mode
   if (root/'guard-ready.json').exists():guard=json.loads((root/'guard-ready.json').read_text())
   elif (root/'stage-guard_spawned.json').exists():guard=json.loads((root/'stage-guard_spawned.json').read_text())
   if (root/'ready.json').exists():receipt=json.loads((root/'ready.json').read_text())
   members=group(p.pid)
   if mode in ['kill_at_spawn_returned','kill_at_child_registered','kill_at_socket_created']:
    assert any(m['pid']!=p.pid and m['exe']==str(driver) for m in members),'driver not in owned group'
   if receipt:assert receipt['process_group']==p.pid and os.getpgid(receipt['daemon_pid'])==p.pid
   if mode.startswith('kill_at_') or mode=='forced_host_exit':p.kill()
   elif mode in ['orderly_host_exit','replacement_file_preserved']:
    if mode=='replacement_file_preserved':
     (root/'driver.sock').unlink();(root/'driver.sock').write_text('replacement-sentinel')
    p.terminate()
   elif mode=='daemon_crash':os.kill(receipt['daemon_pid'],signal.SIGKILL)
   elif mode=='guard_crash':os.kill(guard['guard_pid'],signal.SIGKILL)
   p.wait(timeout=12)
   assert wait(lambda:not group(p.pid) and (not guard or not alive(guard['guard_pid']))),'process group/guard remains'
   preserved=mode=='replacement_file_preserved'
   assert (root/'driver.sock').read_text()=='replacement-sentinel' if preserved else not os.path.lexists(root/'driver.sock')
   cleanup=json.loads((root/'guard-cleanup.json').read_text()) if (root/'guard-cleanup.json').exists() else None
   records.append({'test':mode,'pass':True,'host_exit':p.returncode,'process_group_empty':True,
    'guard_exited':not guard or not alive(guard['guard_pid']),'socket_removed':not os.path.lexists(root/'driver.sock'),
    'replacement_preserved':preserved,'members_at_injection':members,'guard':guard,'receipt':receipt,'guard_cleanup':cleanup})
   print('PASS',mode,flush=True)
  except Exception as error:
   records.append({'test':mode,'pass':False,'error':str(error),'root':str(root),'host_pid':p.pid if p else None,'members':group(p.pid) if p else []})
   raise
  finally:
   if p and p.poll() is None:p.terminate();p.wait(timeout=10)
   if not p or (not group(p.pid) and (not guard or not alive(guard['guard_pid']))):shutil.rmtree(root)
finally:
 (base/'lifecycle-results-v2.json').write_text(json.dumps(records,indent=2))
print(json.dumps({'passed':sum(r['pass'] for r in records),'total':len(records)}))
