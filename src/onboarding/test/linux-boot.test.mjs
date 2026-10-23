import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createDeployment,readDeployment} from '../core.mjs';
import {observeDeploymentBackground} from '../background.mjs';
import {main} from '../cli.mjs';
import {linuxUserManagerStatus} from '../../host/linux-service.mjs';
import {readDeploymentLinuxBoot,projectLinuxBoot} from '../linux-boot.mjs';
async function project(state,{manager,observe,uid}={}){return projectLinuxBoot(state,readDeployment(state),await observe(),{manager:manager(),uid});}
function fixture(t,{host=true,join=false}={}){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-boot-'));fs.chmodSync(root,0o700);t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const runtime={bundle:path.join(root,'bundle'),publisherKeyFile:path.join(root,'publisher.pem'),publisherSha256:'a'.repeat(64),baseDir:path.join(root,'gateway-runtime')};
 const config={schema:1,mode:join?'join-existing':'create-local',gateway:join?{url:'https://127.0.0.1:8443'}:{url:'https://127.0.0.1:8443',openssl:'/usr/bin/openssl',...(!host?{runtime}:{})},...(host?{host:{...runtime,baseDir:path.join(root,'host'),label:'test',computer:false}}:{})};
 const file=path.join(root,'input.json');fs.writeFileSync(file,JSON.stringify(config),{mode:0o600});const state=path.join(root,'state');createDeployment(file,{stateDir:state});return state;
}
function manager(linger){return ()=>linuxUserManagerStatus({uid:1000,run:(bin,args)=>{
 assert.equal(bin,'/usr/bin/loginctl');assert.deepEqual(args,['show-user','1000','-p','Linger','-p','State','-p','RuntimePath','--no-pager']);
 if(linger==='error')throw Error('unavailable');return `Linger=${linger}\nState=active\n`;
}})}
const enabled={host:'running',hostPersistence:'enabled',gateway:'running',gatewayPersistence:'enabled'};
test('linger is a separate prerequisite from healthy enabled services; reviewed plan does not mutate', {skip:process.platform!=='linux'},async t=>{
 const state=fixture(t);const before=fs.readFileSync(path.join(state,'state.json'));
 const value=await project(state,{manager:manager('no'),uid:1000,observe:async()=>enabled});
 assert.equal(value.status,'not_configured');assert.deepEqual(value.plan[0].command,['loginctl','enable-linger','1000']);assert.equal(value.plan[0].scope,'all_services_of_this_user');assert.equal(value.physicalPreloginAcceptance,'NOT RUN');
 assert.deepEqual(fs.readFileSync(path.join(state,'state.json')),before);
});
test('existing linger plus verified enabled roles is configured_unverified, never boot acceptance',{skip:process.platform!=='linux'},async t=>{
 const value=await project(fixture(t),{manager:manager('yes'),observe:async()=>enabled});
 assert.equal(value.status,'configured_unverified');assert.deepEqual(value.plan,[]);assert.equal(value.roles.host.toolHealth,'not_checked');assert.match(value.desktop.computerUse,/graphical/);
});
test('disabled, absent and unknown units are distinct; never propose adopting unknown services',{skip:process.platform!=='linux'},async t=>{
 const state=fixture(t);
 for(const [host,persistence,wanted] of [['not_installed','unknown','not_installed'],['not_running','disabled','disabled'],['unknown','enabled','unknown'],['unknown','disabled','unknown']]){
  const v=await project(state,{manager:manager('yes'),observe:async()=>({...enabled,host,hostPersistence:persistence})});
  assert.equal(v.roles.host.startup,wanted);assert.equal(v.status,wanted==='unknown'?'unknown':'not_configured');
  assert.equal(v.plan.length,wanted==='unknown'?0:wanted==='disabled'?1:2);
 }
 const v=await project(state,{manager:manager('error'),observe:async()=>enabled});assert.equal(v.status,'unknown');assert.deepEqual(v.plan,[]);
});
test('Gateway-only and external Gateway derive roles from authoritative Core; default observation is read-only',{skip:process.platform!=='linux'},async t=>{
 const gateway=await project(fixture(t,{host:false}),{manager:manager('yes'),observe:async()=>enabled});assert.equal(gateway.roles.host.startup,'not_applicable');
 const state=fixture(t,{join:true});const before=fs.readdirSync(state).sort();
 const joined=await project(state,{manager:manager('yes'),observe:async()=>enabled});assert.equal(joined.roles.gateway.startup,'not_applicable');
 const fresh=await readDeploymentLinuxBoot(state,{linuxUserManager:manager('yes')});assert.equal(fresh.roles.host.startup,'unknown');assert.equal(fresh.status,'unknown');assert.deepEqual(fresh.plan,[]);assert.deepEqual(fs.readdirSync(state).sort(),before);
});

test('CLI and background share one read-only projection; no contradictory boot field',{skip:process.platform!=='linux'},async t=>{
 const state=fixture(t,{join:true});
 const background=await observeDeploymentBackground(state,{linuxUserManager:manager('yes')});
 assert.equal(background.systemBootWithoutLogin,background.linuxBoot.status);
 assert.equal(background.startup,'user_manager_at_boot');
 const actual=await main(['linux-boot',state]);
 assert.deepEqual(actual,await readDeploymentLinuxBoot(state));
 assert.equal(actual.physicalPreloginAcceptance,'NOT RUN');
});

test('slow native logind observation times out without blocking UI timers or claiming configuration',{skip:process.platform!=='linux'},async()=>{
 const {observeLinuxBootManager}=await import('../linux-boot.mjs');
 const {execFile}=await import('node:child_process');
 let ticks=0;const timer=setInterval(()=>ticks++,10),start=performance.now();
 try{
  const result=await observeLinuxBootManager({timeout:80,run(binary,args,options,callback){
   assert.equal(binary,'/usr/bin/loginctl');assert.equal(options.killSignal,'SIGKILL');
   return execFile(process.execPath,['-e','setInterval(()=>{},1000)'],options,callback);
  }});
  assert.equal(result.systemBootWithoutLogin,'unknown');assert.equal(result.status,'unavailable');assert.ok(ticks>1,'event loop must stay responsive');assert.ok(performance.now()-start<2000);
 }finally{clearInterval(timer);}
});
