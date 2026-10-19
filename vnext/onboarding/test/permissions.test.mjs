import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {observeMacAppPermissions,readDeploymentPermissions} from '../permissions.mjs';
function fixture(t){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-permission-observation-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const file=path.join(root,'connection.json'),uid=1001;
 const d={schema:1,bundle_id:'app.styx.host',generation:'12345678-1234-1234-1234-123456789012',transport:'socket_accepting',socket:path.join(root,'cua.sock'),owner_pid:12345,host_accessibility:true,host_screen_recording:false};
 const put=()=>fs.writeFileSync(file,JSON.stringify(d),{mode:0o600});put();
 const run=(command,args)=>{assert.equal(command,'/bin/ps');assert.deepEqual(args,['-p','12345','-o','uid=','-o','comm=']);return {status:0,stdout:uid+' /Applications/Styx.app/Contents/MacOS/Styx\n'}};
 const observe=patch=>observeMacAppPermissions({appPath:'/Applications/Styx.app',descriptorFile:file,runtimeRoot:root,uid,run,...patch});
 return {root,file,d,put,observe};
}
test('read-only App preflight preserves separate grants and never claims desktop or responsibility',t=>{
 const f=fixture(t),p=f.observe();assert.equal(p.source,'current_native_app_preflight');assert.equal(p.accessibility,'granted');assert.equal(p.screenRecording,'denied');assert.equal(p.automation,'not_required');assert.equal(p.tccResponsibility,'NOT RUN');assert.equal(p.desktop,undefined);
 f.d.host_screen_recording=true;f.put();assert.equal(f.observe().screenRecording,'granted');
});
test('stale, redirected, wrong-identity or vanished App observations cannot grant permissions',t=>{
 const f=fixture(t);assert.equal(f.observe({now:Date.now()+10000}).source,'not_observed');
 for(const run of [()=>({status:1}),()=>({status:0,stdout:'1001 /usr/bin/other'}),()=>({status:0,stdout:'1002 /Applications/Styx.app/Contents/MacOS/Styx'})])assert.equal(f.observe({run}).source,'not_observed');
 f.d.socket='/other/socket';f.put();assert.equal(f.observe().source,'not_observed');
 f.d.socket=path.join(f.root,'cua.sock');f.put();fs.chmodSync(f.file,0o644);assert.equal(f.observe().source,'not_observed');
});
test('no requested desktop never requires native grants; unknown state never claims granted',t=>{
 const f=fixture(t),state=path.join(f.root,'state');fs.mkdirSync(state,{mode:0o700});
 fs.writeFileSync(path.join(state,'deployment.json'),JSON.stringify({mode:'create-local'}),{mode:0o600});assert.equal(readDeploymentPermissions(state).accessibility,'not_required');
 fs.writeFileSync(path.join(state,'deployment.json'),JSON.stringify({host:{computer:true}}));assert.equal(readDeploymentPermissions(state).accessibility,'not_observed');
 const base=path.join(f.root,'host');fs.mkdirSync(base,{mode:0o700});fs.mkdirSync(path.join(base,'device'),{mode:0o700});
 fs.writeFileSync(path.join(base,'device/host.json'),JSON.stringify({computer:{enabled:true}}),{mode:0o600});
 fs.writeFileSync(path.join(state,'deployment.json'),JSON.stringify({host:{baseDir:base,computer:false}}));assert.equal(readDeploymentPermissions(state).accessibility,'not_observed');
 fs.writeFileSync(path.join(base,'device/host.json'),JSON.stringify({computer:{enabled:false}}));assert.equal(readDeploymentPermissions(state).accessibility,'not_required');
});
