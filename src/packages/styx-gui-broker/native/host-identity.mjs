import {spawn,execFileSync} from 'node:child_process';
import {mkdtempSync,readFileSync,writeFileSync,existsSync,rmSync} from 'node:fs';
import {setTimeout as sleep} from 'node:timers/promises';import assert from 'node:assert/strict';
import {SdkClient} from '../sdk-client.mjs';
const [base,driver,python,pythonPath]=process.argv.slice(2);
const root=mkdtempSync('/private/tmp/styx-gb-'),socket=root+'/driver.sock';
const identity=pid=>execFileSync(base+'/Styx.app/Contents/MacOS/Styx',['--identity',String(pid)],{encoding:'utf8'}).trim();
const wait=async f=>{for(let i=0;i<160;i++){if(f())return true;await sleep(50);}return false;};
const launch=spawn('/usr/bin/open',['-n','-g','-a',base+'/Styx.app','--args',root,driver],{stdio:'ignore'});
let receipt,client,record;
try{
 assert.ok(await wait(()=>existsSync(root+'/ready.json')));
 receipt=JSON.parse(readFileSync(root+'/ready.json','utf8'));
 client=new SdkClient({python,pythonPath,socket});
 const m=await client.call('metadata');assert.equal(m.pid,receipt.daemon_pid);assert.equal(m.embedded,true);
 const h=(await client.call('health_report',{include:['bundle_identity']})).structuredContent;
 const item=h.checks.find(x=>x.name==='bundle_identity');
 assert.equal(item.status,'pass');assert.equal(item.data.parent_process_id,receipt.host_pid);
 const p=(await client.call('check_permissions',{prompt:false})).structuredContent;
 assert.equal(p.source.attribution,'host');assert.equal(p.source.responsible_ppid,receipt.host_pid);
 assert.equal(p.source.host_bundle_id,'com.styx.prototype.guibroker20261017');
 record={test:'new_styx_host_embedded_identity',pass:true,metadata:m,health:h,permissions:p,receipt};
}finally{
 await client?.close();
 if(receipt&&identity(receipt.host_pid)===receipt.host_identity)process.kill(receipt.host_pid,'SIGTERM');
 if(receipt)assert.ok(await wait(()=>identity(receipt.host_pid)==='absent'&&identity(receipt.daemon_pid)==='absent'&&identity(receipt.guard_pid)==='absent'&&!existsSync(socket)));
 rmSync(root,{recursive:true,force:true});
}
writeFileSync(base+'/host-identity-results.json',JSON.stringify(record,null,2));
console.log(JSON.stringify({test:record.test,pass:record.pass,host_permissions:{accessibility:record.permissions.accessibility,screen_recording:record.permissions.screen_recording},cleanup:true}));
