import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {createHash,generateKeyPairSync,sign,randomBytes,createPublicKey} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {hostServiceAction,serviceIds,observeHostService,observeUnenrolledHostService} from '../service-lifecycle.mjs';
import {ensurePrivateDirectory} from '../../host/private-storage.mjs';
import {stageSignedRelease,activateRelease,refreshVerifiedBootstrap} from '../../host/installer.mjs';
import {prepareNativeSetup} from '../../host/setup-native.mjs';
import {removeLinuxService} from '../../host/linux-service.mjs';
const linux=process.platform==='linux';
const sum=b=>createHash('sha256').update(b).digest('hex');
function fixture(t){
 const root=path.join(os.tmpdir(),'styx-owner-service-'+randomBytes(6).toString('hex'));ensurePrivateDirectory(root);t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const source=path.join(root,'source');fs.mkdirSync(path.join(source,'host'),{recursive:true,mode:0o700});fs.mkdirSync(path.join(source,'bin'),{mode:0o700});
 for(const file of ['installer.mjs','private-storage.mjs'])fs.copyFileSync(new URL('../../host/'+file,import.meta.url),path.join(source,'host',file));
 fs.writeFileSync(path.join(source,'host','launch.mjs'),'setInterval(()=>{},1000);\n');fs.copyFileSync(process.execPath,path.join(source,'bin','node'));
 const keys=generateKeyPairSync('ed25519');const pub=keys.publicKey.export({format:'pem',type:'spki'});
 const names=['host/installer.mjs','host/private-storage.mjs','host/launch.mjs','bin/node'];
 const manifest={schema:1,version:'0.1.0-owner-service-fixture',platform:'linux',arch:process.arch,files:names.map(name=>{const bytes=fs.readFileSync(path.join(source,name));return {path:name,sha256:sum(bytes),size:bytes.length,executable:name.startsWith('bin/')}})};
 const raw=JSON.stringify(manifest)+'\n';fs.writeFileSync(path.join(source,'manifest.json'),raw);fs.writeFileSync(path.join(source,'manifest.sig'),sign(null,Buffer.from(raw),keys.privateKey).toString('base64url'));
 const installed=path.join(root,'installed');stageSignedRelease({sourceDir:source,installRoot:installed,publicKeyPem:pub});activateRelease(installed,manifest.version,pub);refreshVerifiedBootstrap(installed,pub,manifest.version);
 const host=path.join(root,'host.json'),trust=path.join(root,'publisher.pub'),token=path.join(root,'host.token'),config=path.join(root,'service.json');
 fs.writeFileSync(trust,pub,{mode:0o600});fs.writeFileSync(token,'private_fixture_token',{mode:0o600});fs.writeFileSync(host,JSON.stringify({host_id:'owned-fixture',token_file:token,exec:{binary:process.execPath}}),{mode:0o600});
 const id='styx-rc20261019-owned-'+randomBytes(4).toString('hex')+'.service';
 const service={unitName:id,installRoot:installed,hostConfigFile:host,trustPublicKeyFile:trust,nodeBinary:path.join(installed,'node')};fs.writeFileSync(config,JSON.stringify(service),{mode:0o600});
 const request=action=>({action,role:'host',serviceConfigFile:config,authorization:{approved:true,action,role:'host',serviceConfigFile:config,serviceId:id,installRoot:installed,hostConfigFile:host,trustPublicKeyFile:trust,nodeBinary:service.nodeBinary}});
 const home=path.join(root,'home');fs.mkdirSync(home,{mode:0o700});
 return {root,home,id,config,host,installed,request,service,source,keys,pub};
}
function manager(){let enabled=false,active=false,installed=false;const calls=[];return {calls,run(binary,args){assert.equal(binary,'/usr/bin/systemctl');assert.equal(args[0],'--user');calls.push([...args]);if(args[1]==='daemon-reload')installed=true;if(args[1]==='enable')enabled=true;if(args[1]==='disable')enabled=false;if(args[1]==='start')active=true;if(args[1]==='stop')active=false;return 'LoadState='+(installed?'loaded':'not-found')+'\nActiveState='+(active?'active':'inactive')+'\nSubState='+(active?'running':'dead')+'\nUnitFileState='+(enabled?'enabled':'disabled')+'\nMainPID='+(active?123:0)+'\nNRestarts=0\n'}}}
test('gateway persistence is explicitly not implemented; no native command',async()=>{
 const result=await hostServiceAction({action:'install',role:'gateway',authorization:{approved:true,action:'install',role:'gateway'}},{run(){throw Error('unexpected')}});
 assert.equal(result.status,'not_implemented');assert.equal(serviceIds.win32,'Styx-Host');assert.equal(serviceIds.darwin,'app.styx.connector');
});
test('missing authorization or arbitrary action cannot reach native commands',async()=>{
 for(const request of [{action:'start'},{action:'restart',authorization:{approved:true,action:'restart',role:'host'}},{action:'stop',authorization:{approved:false,action:'stop',role:'host'}}])assert.equal((await hostServiceAction(request,{run(){throw Error('unexpected')}})).status,'blocked');
});
test('signed config-bound Linux install/status/start/stop produce only redacted observed state',{skip:!linux},async t=>{
 const f=fixture(t),native=manager();const options={home:f.home,run:native.run};
 for(const [action,state] of [['install','stopped'],['status','stopped'],['start','running'],['stop','stopped']]){
  const result=await hostServiceAction(f.request(action),options);assert.equal(result.status,'reported');assert.equal(result.state,state);assert.equal(result.health,'not_checked');assert.ok(!JSON.stringify(result).includes(f.root));assert.ok(!JSON.stringify(result).includes('private_fixture_token'));
 }
 const commands=native.calls.map(c=>c[1]);assert.ok(commands.indexOf('disable')<commands.indexOf('stop'));assert.deepEqual(commands.filter(c=>c==='enable'||c==='start'),['enable','start']);
});
test('changed owner scope/config/runtime or foreign service definition is refused before mutation',{skip:!linux},async t=>{
 const f=fixture(t),native=manager(),options={home:f.home,run:native.run};
 const wrong=f.request('install');wrong.authorization.installRoot=f.root;assert.equal((await hostServiceAction(wrong,options)).status,'blocked');assert.equal(native.calls.length,0);
 assert.equal((await hostServiceAction(f.request('install'),options)).status,'reported');
 const unit=path.join(f.home,'.config/systemd/user',f.id);fs.appendFileSync(unit,'# changed binding\n');native.calls.length=0;
 assert.equal((await hostServiceAction(f.request('start'),options)).status,'blocked');assert.equal(native.calls.length,0);
 fs.appendFileSync(path.join(f.installed,'launch.mjs'),'// unsigned change\n');assert.equal((await hostServiceAction(f.request('status'),options)).status,'blocked');
});
test('native mutation errors are uncertain with fixed redacted reason, never auto-replayed',{skip:!linux},async t=>{
 const f=fixture(t);let calls=0;const result=await hostServiceAction(f.request('install'),{home:f.home,run(){calls++;throw Error('SECRET_PATH_AND_TOKEN')}});
 assert.equal(result.status,'uncertain');assert.equal(calls,1);assert.ok(!JSON.stringify(result).includes('SECRET'));assert.ok(fs.existsSync(path.join(f.home,'.config/systemd/user',f.id)));
});
test('opt-in actual isolated Linux user service lifecycle',{skip:!linux||process.env.STYX_RUN_ONBOARDING_SERVICE_PILOT!=='1',timeout:45000},async t=>{
 const f=fixture(t);assert.equal(execFileSync('/usr/bin/systemctl',['--user','show',f.id,'-p','LoadState','--value'],{encoding:'utf8',timeout:5000}).trim(),'not-found');
 t.after(()=>{if(fs.existsSync(path.join(os.homedir(),'.config/systemd/user',f.id)))removeLinuxService(f.id)});
 assert.equal((await hostServiceAction(f.request('install'))).status,'reported');
 assert.equal((await hostServiceAction(f.request('start'))).state,'running');
 assert.equal((await hostServiceAction(f.request('status'))).state,'running');
 const stopped=await hostServiceAction(f.request('stop'));assert.equal(stopped.state,'stopped');assert.equal(stopped.persistence,'disabled');
 t.diagnostic('exact owned unit '+f.id+' observed running, then stopped and disabled');
 removeLinuxService(f.id);t.diagnostic('exact owned unit removed; signed fixture is not a native Host tool health claim');assert.equal(execFileSync('/usr/bin/systemctl',['--user','show',f.id,'-p','LoadState','--value'],{encoding:'utf8'}).trim(),'not-found');
});

test('read-only service observation constructs fixed scope and never mutates native service',{skip:!linux},async t=>{
 const f=fixture(t),native=manager();
 const result=await observeHostService({serviceConfigFile:f.config},{home:f.home,run:native.run});
 assert.equal(result.status,'reported');assert.equal(result.installed,false);
 assert.deepEqual(native.calls.map(c=>c[1]),['show']);
});
test('known legacy simple unit remains manageable without rewriting its installed definition',{skip:!linux},async t=>{
 const f=fixture(t),native=manager(),options={home:f.home,run:native.run};
 assert.equal((await hostServiceAction(f.request('install'),options)).status,'reported');
 const unit=path.join(f.home,'.config/systemd/user',f.id),legacy=fs.readFileSync(unit,'utf8').replace('Type=exec\n','Type=simple\n');fs.writeFileSync(unit,legacy);
 assert.equal((await hostServiceAction(f.request('start'),options)).state,'running');
 assert.equal((await hostServiceAction(f.request('stop'),options)).state,'stopped');
 assert.equal(fs.readFileSync(unit,'utf8'),legacy);
});


test('actual native preparation without credentials observes only raw native service absence; normal lifecycle stays credential-gated',{skip:!linux},async t=>{
 const f=fixture(t),names=['enroll.mjs','setup-native.mjs','doctor.mjs','linux-service.mjs'];
 for(const name of names)fs.copyFileSync(new URL('../../host/'+name,import.meta.url),path.join(f.source,'host',name));
 for(const name of ['codex','cua-driver'])fs.writeFileSync(path.join(f.source,'bin',name),'fixture; never executed');
 const manifest=JSON.parse(fs.readFileSync(path.join(f.source,'manifest.json')));
 for(const name of [...names.map(n=>'host/'+n),'bin/codex','bin/cua-driver']){const b=fs.readFileSync(path.join(f.source,name));manifest.files.push({path:name,sha256:sum(b),size:b.length,executable:name.startsWith('bin/')})}
 const raw=JSON.stringify(manifest)+'\n';fs.writeFileSync(path.join(f.source,'manifest.json'),raw);fs.writeFileSync(path.join(f.source,'manifest.sig'),sign(null,Buffer.from(raw),f.keys.privateKey).toString('base64url'));
 const base=path.join(f.root,'fresh'),key=path.join(f.root,'publisher.pub');
 prepareNativeSetup({bundle:f.source,publisherKeyFile:key,publisherSha256:sum(createPublicKey(f.pub).export({type:'spki',format:'der'})),baseDir:base,gatewayUrl:'https://127.0.0.1:1',label:'join-recovery',computer:false});
 const serviceConfigFile=path.join(base,'service.json');assert.equal(fs.existsSync(path.join(base,'setup-state.json')),true);
 for(const n of ['host.json','host.token','pending.json'])assert.equal(fs.existsSync(path.join(base,'device',n)),false);
 let calls=0,mode='absent';const run=(binary,args)=>{calls++;assert.equal(binary,'/usr/bin/systemctl');assert.deepEqual(args.slice(0,3),['--user','show','styx-host.service']);if(mode==='unavailable')throw Error('manager unavailable');return `LoadState=${mode==='absent'?'not-found':'loaded'}\nActiveState=${mode==='running'?'active':'inactive'}\nMainPID=${mode==='running'?123:0}\n`;};
 assert.equal((await observeHostService({serviceConfigFile},{home:f.home,run})).status,'blocked');assert.equal(calls,0);
 const observed=await observeUnenrolledHostService({serviceConfigFile},{home:f.home,run});assert.equal(observed.state,'not_installed');assert.equal(observed.scope,'unenrolled_host_absence_only');assert.equal(calls,1);
 for(mode of ['stopped','running','unavailable'])assert.equal((await observeUnenrolledHostService({serviceConfigFile},{home:f.home,run})).status,'blocked');
 mode='absent';const unit=path.join(f.home,'.config/systemd/user');fs.mkdirSync(unit,{recursive:true,mode:0o700});fs.writeFileSync(path.join(unit,'styx-host.service'),'foreign definition');const before=calls;assert.equal((await observeUnenrolledHostService({serviceConfigFile},{home:f.home,run})).status,'blocked');assert.equal(calls,before);
 fs.rmSync(path.join(unit,'styx-host.service'));fs.appendFileSync(path.join(base,'install/launch.mjs'),'unsigned');assert.equal((await observeUnenrolledHostService({serviceConfigFile},{home:f.home,run})).status,'blocked');assert.equal(calls,before);
});
