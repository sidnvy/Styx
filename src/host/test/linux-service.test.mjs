import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {generateKeyPairSync,sign,createHash} from 'node:crypto';
import {stageSignedRelease,activateRelease,servicePlan} from '../installer.mjs';
import {linuxUserUnit,knownLinuxUserUnit,writeUserService,installLinuxService,
  removeLinuxService,statusUserService,systemdUser} from '../linux-service.mjs';

const linux=process.platform==='linux';
const sum=b=>createHash('sha256').update(b).digest('hex');
async function fixture(t){
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'styx-user-unit-'));
  t.after(()=>fs.rm(root,{recursive:true,force:true}));
  const home=path.join(root,'home');
  await fs.mkdir(home,{mode:0o700});
  const configFile=path.join(root,'host.json');
  await fs.writeFile(configFile,'{}\n',{mode:0o600});
  const {privateKey,publicKey}=generateKeyPairSync('ed25519',{
    publicKeyEncoding:{type:'spki',format:'pem'},
    privateKeyEncoding:{type:'pkcs8',format:'pem'}
  });
  const publisherFile=path.join(root,'publisher.pub');
  await fs.writeFile(publisherFile,publicKey,{mode:0o600});
  const source=path.join(root,'bundle');
  await fs.mkdir(path.join(source,'host'),{recursive:true});
  const bytes="process.stdout.write('test-only')\n";
  await fs.writeFile(path.join(source,'host','connect.mjs'),bytes);
  const manifest={schema:1,version:'0.1.0-test',platform:'linux',arch:process.arch,
    files:[{path:'host/connect.mjs',size:Buffer.byteLength(bytes),
      sha256:sum(bytes),executable:false}]};
  const manifestRaw=JSON.stringify(manifest)+'\n';
  await fs.writeFile(path.join(source,'manifest.json'),manifestRaw);
  await fs.writeFile(path.join(source,'manifest.sig'),
    sign(null,Buffer.from(manifestRaw),privateKey).toString('base64url')+'\n');
  const installRoot=path.join(root,'installed');
  stageSignedRelease({sourceDir:source,installRoot,publicKeyPem:publicKey});
  activateRelease(installRoot,'0.1.0-test',publicKey);
  const unitName='styx-vnext-pilot-test.service';
  const options={unitName,installRoot,hostConfigFile:configFile,
    trustPublicKeyFile:publisherFile,nodeBinary:process.execPath,restartSec:2};
  return {root,home,unitName,options,publisherFile,publicKey,installRoot};
}

test('Linux unit references a verified signed release; no hidden dependency on Coder',
  {skip:!linux},async t=>{
    const f=await fixture(t);
    const unit=linuxUserUnit(f.options);
    assert.ok(unit.startsWith('# Managed by Styx VNext'));
    assert.match(unit,/Type=exec/);
    assert.equal(knownLinuxUserUnit(unit,f.options),true);
    assert.equal(knownLinuxUserUnit(unit.replace('Type=exec','Type=simple'),f.options),true);
    assert.equal(knownLinuxUserUnit(unit.replace('Type=exec','Type=forking'),f.options),false);
    assert.equal(knownLinuxUserUnit(unit.replace('Restart=on-failure','Restart=always'),f.options),false);
    assert.match(unit,/Restart=on-failure/);
    assert.match(unit,/UMask=0077/);
    assert.match(unit,/WantedBy=default\.target/);
    assert.match(unit,/NoNewPrivileges=true/);
    assert.ok(unit.includes(f.installRoot+'/launch.mjs'));
    assert.ok(unit.includes(f.options.hostConfigFile));
    assert.ok(!unit.includes('coder'));
    assert.ok(!unit.includes('ssh'));
    assert.throws(()=>linuxUserUnit({...f.options,
      unitName:'coder-agent.service'}),/invalid_styx_unit_name/);
    assert.throws(()=>linuxUserUnit({...f.options,
      hostConfigFile:f.root+'/newline\ncommand'}),/unsafe_path/);
    await fs.chmod(f.options.hostConfigFile,0o644);
    assert.throws(()=>linuxUserUnit(f.options),/host_config_not_private/);
});
test('user unit installation and uninstall are restricted to Styx-owned files',
  {skip:!linux},async t=>{
    const f=await fixture(t);
    const calls=[];
    const mock=(binary,args)=>{
      assert.equal(binary,'/usr/bin/systemctl');
      assert.equal(args[0],'--user');
      calls.push(args.join(' '));
      if(args[1]==='show')return 'LoadState=loaded\nActiveState=inactive\nSubState=dead\nUnitFileState=disabled\nMainPID=0\nNRestarts=0\n';
      return '';
    };
    const created=installLinuxService(f.options,{home:f.home,run:mock});
    assert.equal(created.status,'installed_disabled');
    const unit=path.join(f.home,'.config/systemd/user',f.unitName);
    assert.match(await fs.readFile(unit,'utf8'),/Managed by Styx VNext/);
    assert.equal((await fs.stat(unit)).mode&0o077,0);
    assert.ok(calls.some(s=>s.includes('daemon-reload')));
    assert.throws(()=>writeUserService(f.options,{home:f.home}),/service_already_installed/);
    const removed=removeLinuxService(f.unitName,{home:f.home,run:mock});
    assert.equal(removed.status,'uninstalled');
    assert.equal(removed.preservedInstallRoot,true);
    await assert.rejects(fs.stat(unit),{code:'ENOENT'});
    assert.ok(calls.some(s=>s.includes('disable')));
    assert.ok(calls.some(s=>s.includes('stop')));
    assert.equal((await fs.stat(f.installRoot)).isDirectory(),true);
});
test('an untrusted existing unit cannot be overwritten or removed',
  {skip:!linux},async t=>{
    const f=await fixture(t);
    const folder=path.join(f.home,'.config/systemd/user');
    await fs.mkdir(folder,{recursive:true});
    const unit=path.join(folder,f.unitName);
    await fs.writeFile(unit,'[Service]\nExecStart=/bin/evil\n',{mode:0o644});
    assert.throws(()=>writeUserService(f.options,{home:f.home,overwrite:true}),
      /service_unit_not_owned/);
    assert.throws(()=>removeLinuxService(f.unitName,{home:f.home,run:()=>''}),
      /service_unit_not_owned/);
    assert.equal(await fs.readFile(unit,'utf8'),'[Service]\nExecStart=/bin/evil\n');
});
test('systemctl calls are strict argument arrays without shell expansion',
  {skip:!linux},async t=>{
    const f=await fixture(t);
    let args;
    const run=(bin,argv)=>{args=[bin,...argv];return '';};
    systemdUser(f.unitName,'restart',{run});
    assert.deepEqual(args,['/usr/bin/systemctl','--user','restart',f.unitName]);
    assert.throws(()=>systemdUser(f.unitName,'disable --now',{run}),
      /unsupported_service_verb/);
    assert.throws(()=>systemdUser('other.service','start',{run}),
      /invalid_styx_unit_name/);
    assert.throws(()=>linuxUserUnit({...f.options,
      installRoot:'/tmp/foo; touch /tmp/owned'}),/unsafe_path/);
});
test('existing servicePlan remains non-mutating, including Linux path',
  {skip:!linux},async t=>{
    const f=await fixture(t);
    const p=servicePlan({
      installRoot:f.installRoot,
      configFile:f.options.hostConfigFile,
      publicKeyFile:f.publisherFile,
      platform:'linux'
    });
    assert.equal(p.manager,'systemd-user');
    assert.equal(p.status,'NOT_INSTALLED');
    assert.equal((await fs.readdir(f.home)).length,0);
});

test('Linux user service remains independent of graphical login targets', {skip:!linux},async t=>{
  const f=await fixture(t),unit=linuxUserUnit(f.options);
  assert.doesNotMatch(unit,/graphical-session|DISPLAY|WAYLAND_DISPLAY|PartOf=|BindsTo=/);
});
test('installation rejects redirected user service parent directories',{skip:!linux},async t=>{
  const f=await fixture(t),redirect=path.join(f.root,'redirect');await fs.mkdir(redirect);
  await fs.symlink(redirect,path.join(f.home,'.config'));
  assert.throws(()=>writeUserService(f.options,{home:f.home}),/user_unit_dir_not_regular/);
  assert.deepEqual(await fs.readdir(redirect),[]);
});
test('read-only user manager diagnostics report headless persistence honestly',{skip:!linux},async()=>{
  const {linuxUserManagerStatus}=await import('../linux-service.mjs');
  const calls=[];
  for(const [value,expected] of [['yes','configured'],['no','not_configured'],['','unknown']]){
    const state=linuxUserManagerStatus({run:(bin,args)=>{calls.push([bin,...args]);return `Linger=${value}\nState=active\n`}});
    assert.equal(state.systemBootWithoutLogin,expected);assert.equal(state.graphicalSessionRequired,false);
  }
  assert.ok(calls.every(c=>c[1]==='show-user'));
});
test('recovery restarts only an enabled owned service and preserves identity',{skip:!linux},async t=>{
  const {recoverLinuxService}=await import('../linux-service.mjs');
  const f=await fixture(t);writeUserService(f.options,{home:f.home});
  const before=await fs.readFile(f.options.hostConfigFile);let active='failed',enabled='enabled';const calls=[];
  const run=(bin,args)=>{calls.push(args[1]);if(args[1]==='start')active='active';
    return `LoadState=loaded\nActiveState=${active}\nUnitFileState=${enabled}\nMainPID=${active==='active'?42:0}\n`};
  const recovered=recoverLinuxService(f.unitName,{home:f.home,run});
  assert.equal(recovered.active,'active');assert.equal(recovered.identityMutation,'NOT RUN');
  assert.deepEqual(calls,['show','reset-failed','start','show']);
  assert.deepEqual(await fs.readFile(f.options.hostConfigFile),before);
  enabled='disabled';calls.length=0;
  assert.throws(()=>recoverLinuxService(f.unitName,{home:f.home,run}),/requires_enabled/);
  assert.deepEqual(calls,['show']);
});
