#!/usr/bin/env python3
"""Opt-in actual installed Styx embedded socket, exact owned AppKit window only.
No permission prompts, screenshots retained, or personal windows enumerated.
"""
import hashlib,json,os,struct,subprocess,sys,time,uuid
from pathlib import Path

def run(root):
    assert sys.platform=='darwin' and os.environ.get('STYX_MAC_OWNED_GUI')=='1'
    root=Path(root).resolve();assert root.name.startswith('styx-local-dev-')
    st=root.stat();assert st.st_uid==os.getuid() and not st.st_mode&0o077
    assert json.loads((root/'.styx-local-owner.json').read_text())['kind']=='styx-local-development-app-pilot'
    driver='/Applications/Styx.app/Contents/MacOS/cua-driver';socket=f'/tmp/styx-cua-{os.getuid()}/cua.sock'
    connection=json.loads(Path(f'/tmp/styx-cua-{os.getuid()}/connection.json').read_text())
    owner=connection['owner_pid']
    command=subprocess.check_output(['/bin/ps','-p',str(owner),'-o','comm='],text=True).strip()
    assert Path(command).resolve()==Path('/Applications/Styx.app/Contents/MacOS/Styx')
    fixture_binary=root/'OwnedGuiFixture';fst=fixture_binary.lstat()
    assert fixture_binary.is_file() and not fixture_binary.is_symlink() and fst.st_uid==os.getuid()
    session='styx-owned-'+uuid.uuid4().hex[:12]
    def call(tool,args):
        p=subprocess.run([driver,'call',tool,json.dumps(args),'--socket',socket],capture_output=True,text=True,timeout=12)
        assert p.returncode==0,'native_tool_refused';r=json.loads(p.stdout)
        assert not r.get('isError'), 'native_tool_error'
        return r
    permissions=call('check_permissions',{'prompt':False,'probe_direct_capture':False})
    receipt={'schema':1,'scope':'installed Styx embedded Cua socket; no Gateway/Exec integration claim',
             'status':'BLOCKED','screen_recording':permissions.get('screen_recording'),
             'accessibility':permissions.get('accessibility'),'gui':'NOT RUN','permission_prompt':'NOT RUN'}
    if not (permissions.get('accessibility') and permissions.get('screen_recording')):
        receipt['reason']='actual_host_grants_not_ready';return receipt
    run_dir=root/('owned-gui-'+uuid.uuid4().hex[:12]);run_dir.mkdir(mode=0o700)
    fixture=None;phase='fixture_start'
    try:
        title='STYX_OWNED_GUI_'+uuid.uuid4().hex[:12];readback=run_dir/'readback.json'
        fixture=subprocess.Popen([str(root/'OwnedGuiFixture'),title,str(readback)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        deadline=time.monotonic()+12;window=None
        while time.monotonic()<deadline:
            r=call('list_windows',{'pid':fixture.pid,'on_screen_only':False,'session':session})
            data=r.get('structuredContent',r)
            window=next((w for w in data.get('windows',[]) if w.get('pid')==fixture.pid and w.get('title')==title),None)
            if window:break
            assert fixture.poll() is None,'owned_fixture_exited';time.sleep(.2)
        assert window,'owned_window_not_found';window_id=int(window['window_id']);phase='observe'
        png=run_dir/'owned-window.png'
        r=call('get_window_state',{'pid':fixture.pid,'window_id':window_id,'tree_format':'elements',
            'include_screenshot':True,'screenshot_out_file':str(png),'max_elements':80,'session':session})
        data=r.get('structuredContent',r);elements=data.get('elements',[])
        button=next((e for e in elements if e.get('label')=='Styx Verify Click' and e.get('element_token')),None)
        assert button,'owned_button_not_observed'
        image=png.read_bytes();assert image[:8]==b'\x89PNG\r\n\x1a\n';width,height=struct.unpack('>II',image[16:24]);assert width>0 and height>0
        receipt.update({'screenshot':'PASS','screenshot_dimensions':[width,height],'screenshot_sha256':hashlib.sha256(image).hexdigest(),
                        'accessibility_tree':'PASS','element_count':len(elements)})
        png.unlink();phase='observed_click'
        call('click',{'pid':fixture.pid,'window_id':window_id,'element_token':button['element_token'],'session':session})
        fixture.wait(timeout=8);assert fixture.returncode==0 and readback.exists(),'owned_independent_readback_missing'
        result=json.loads(readback.read_text());assert result.get('pid')==fixture.pid and result.get('title')==title and result.get('status')=='PASS'
        receipt.update({'status':'PASS','gui':'PASS','observed_click':'PASS','independent_readback':'PASS'})
    except Exception:
        receipt.update({'status':'FAIL','gui':'FAIL','failed_phase':phase})
    finally:
        if fixture is not None and fixture.poll() is None:
            fixture.terminate()
            try:fixture.wait(timeout=5)
            except subprocess.TimeoutExpired:fixture.kill();fixture.wait(timeout=5)
        for p in run_dir.iterdir():
            assert p.is_file() and not p.is_symlink();p.unlink()
        run_dir.rmdir();receipt['owned_fixture_cleanup']='PASS'
    return receipt

if __name__=='__main__':
    result=run(sys.argv[1]);print(json.dumps(result));sys.exit(0 if result['status']=='PASS' else 2)
