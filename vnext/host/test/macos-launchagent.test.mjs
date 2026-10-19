import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {stageSignedRelease,activateRelease} from '../installer.mjs';
import {macLaunchAgent,writeMacLaunchAgent,controlMacLaunchAgent,
  removeMacLaunchAgent,statusMacLaunchAgent} from '../macos-launchagent.mjs';

const mac=process.platform==='darwin';
const hash=b=>createHash('sha256').update(b).digest('hex');
async function fixture(t) {
  const tmp=await fs.mkdtemp(path.join(os.tmpdir(),'styx-macos-launch-'));
  t.after(()=>fs.rm(tmp,{recursive:true,force:true}));
  const home=path.join(tmp,'home');
  const logs=path.join(tmp,'logs');
  await fs.mkdir(home,{mode:0o700});
  await fs.mkdir(logs,{mode:0o700});
  const {privateKey,publicKey}=generateKeyPairSync('ed25519',{
    publicKeyEncoding:{format:'pem',type:'spki'},
    privateKeyEncoding:{format:'pem',type:'pkcs8'}
  });
  const source=path.join(tmp,'signed');
  await fs.mkdir(path.join(source,'host'),{recursive:true});
  const files={'host/connect.mjs':
    "process.on('SIGTERM',()=>process.exit(0));setInterval(()=>{},1000)"};
  for(const [f,content] of Object.entries(files)){
    await fs.writeFile(path.join(source,f),content);
  }
  const manifest={schema:1,version:'0.1.0-mac-fixture',platform:'darwin',
    arch:process.arch,files:Object.entries(files).map(([f,c])=>({
      path:f,size:Buffer.byteLength(c),sha256:hash(c),executable:false
    }))};
  const raw=JSON.stringify(manifest)+'\n';
  await fs.writeFile(path.join(source,'manifest.json'),raw);
  await fs.writeFile(path.join(source,'manifest.sig'),
    sign(null,Buffer.from(raw),privateKey).toString('base64url')+'\n');
  const installRoot=path.join(tmp,'installed');
  stageSignedRelease({sourceDir:source,installRoot,publicKeyPem:publicKey});
  activateRelease(installRoot,manifest.version,publicKey);
  const hostConfigFile=path.join(tmp,'host.json');
  await fs.writeFile(hostConfigFile,'{}\n',{mode:0o600});
  const trustPublicKeyFile=path.join(tmp,'publisher.pub');
  await fs.writeFile(trustPublicKeyFile,publicKey,{mode:0o600});
  const label='app.styx.host-pilot.ci';
  const options={label,installRoot,hostConfigFile,trustPublicKeyFile,
    nodeBinary:process.execPath,logDir:logs};
  return {tmp,home,logs,options,label,installRoot,hostConfigFile,trustPublicKeyFile};
}
test('macOS LaunchAgent config includes only signed Styx runtime and user paths',
  {skip:!mac},async t=>{
  const f=await fixture(t);
  const xml=macLaunchAgent(f.options);
  assert.ok(xml.includes('Managed-by: Styx-VNext-user-launchagent-v1'));
  assert.ok(xml.includes('<key>RunAtLoad</key><true/>'));
  assert.ok(xml.includes('<key>KeepAlive</key>'));
  assert.ok(xml.includes('<key>SuccessfulExit</key><false/>'));
  assert.ok(xml.includes(f.installRoot+'/launch.mjs'));
  assert.ok(!xml.includes('coder'));
  assert.ok(!xml.includes('sudo'));
  assert.ok(macLaunchAgent({...f.options,label:'app.styx.connector'}).includes('<string>app.styx.connector</string>'));
  assert.throws(()=>macLaunchAgent({...f.options,label:'app.styx.connector.foreign'}),/invalid_styx_launchagent_label/);
  assert.throws(()=>macLaunchAgent({...f.options,
    label:'com.chat-codex.tunnel'}),/invalid_styx_launchagent_label/);
  assert.throws(()=>macLaunchAgent({...f.options,
    hostConfigFile:f.hostConfigFile+'<unsafe>'}),/unsafe_path/);
});
test('macOS user domain service installs disabled and uninstalls only owned plist',
  {skip:!mac},async t=>{
  const f=await fixture(t);
  const created=writeMacLaunchAgent(f.options,{home:f.home});
  assert.equal(created.status,'installed_not_loaded');
  const stat=await fs.stat(created.plist);
  assert.equal(stat.mode&0o077,0);
  const calls=[];
  const mock=(file,args)=>{
    assert.equal(file,'/bin/launchctl');
    calls.push(args);
    if(args[0]==='print')return 'state = running\npid = 922\n';
    return '';
  };
  const started=controlMacLaunchAgent('start',f.label,{
    home:f.home,uid:501,run:mock
  });
  assert.equal(started.loaded,true);
  assert.equal(started.pid,922);
  assert.deepEqual(calls[0],['enable','gui/501/'+f.label]);
  assert.deepEqual(calls[1],['bootstrap','gui/501',created.plist]);
  assert.deepEqual(calls[2],['print','gui/501/'+f.label]);
  const removed=removeMacLaunchAgent(f.label,{home:f.home,uid:501,run:mock});
  assert.equal(removed.preservedInstallRoot,true);
  await assert.rejects(fs.stat(created.plist),{code:'ENOENT'});
  assert.equal((await fs.stat(f.installRoot)).isDirectory(),true);
  assert.ok(calls.some(x=>x[0]==='bootout'));
  assert.ok(calls.some(x=>x[0]==='disable'));
});
test('macOS refuses unowned existing plist and keeps files untouched',
  {skip:!mac},async t=>{
  const f=await fixture(t);
  const plist=path.join(f.home,'Library','LaunchAgents',f.label+'.plist');
  await fs.mkdir(path.dirname(plist),{recursive:true});
  await fs.writeFile(plist,'<plist>untrusted</plist>');
  assert.throws(()=>writeMacLaunchAgent(f.options,{home:f.home}),
    /launchagent_already_installed/);
  assert.throws(()=>removeMacLaunchAgent(f.label,{home:f.home,
    uid:501,run:()=>''}),/launchagent_not_owned/);
  assert.equal(await fs.readFile(plist,'utf8'),'<plist>untrusted</plist>');
});
