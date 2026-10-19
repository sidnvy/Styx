import test from 'node:test';
import assert from 'node:assert/strict';
import {sessionFromEvidence,createWindowsSessionProbe} from '../scripts/lib/windows-session.mjs';
const evidence=()=>({supported:true,same_user:true,input_receiving:true,thread_receiving:true,process_session:1,console_session:1,reported_session:1,state:0,flags:1,station:'WinSta0',input_desktop:'Default',thread_desktop:'Default',generation:'a'.repeat(64)});
test('Windows console proof requires complete native unlocked same-user input evidence twice',()=>{
 const sample=evidence();assert.deepEqual(sessionFromEvidence([sample,sample]),{ready:true,session_id:sample.generation});
 for(const [key,value] of Object.entries({supported:false,same_user:false,input_receiving:false,thread_receiving:false,process_session:0,console_session:0xffffffff,reported_session:2,state:4,flags:0,station:'Service',input_desktop:'Winlogon',thread_desktop:'Other',generation:'invalid'})){
  for(const index of [0,1]){const pair=[evidence(),evidence()];pair[index][key]=value;assert.equal(sessionFromEvidence(pair).ready,false,key);}
 }
 for(const key of Object.keys(sample)){
  const pair=[evidence(),evidence()];delete pair[1][key];assert.equal(sessionFromEvidence(pair).ready,false,'missing '+key);
 }
 for(const flags of [-1,4294967295,'1',true])assert.equal(sessionFromEvidence([sample,{...sample,flags}]).ready,false);
 assert.equal(sessionFromEvidence([sample,{...sample,generation:'b'.repeat(64)}]).ready,false);
 for(const value of [null,true,{},[sample],[sample,sample,sample]])assert.equal(sessionFromEvidence(value).ready,false);
});
test('Windows probe is platform-gated, bounded, uses fixed script and fails closed on execution/parse errors',async()=>{
 let calls=0;const never=async()=>{calls++;throw Error('never');};
 assert.equal((await createWindowsSessionProbe(never,{platform:'linux'})()).ready,false);assert.equal(calls,0);
 for(const value of ['bad','null','true','[]'])assert.equal((await createWindowsSessionProbe(async()=>value,{platform:'win32'})()).ready,false);
 assert.equal((await createWindowsSessionProbe(never,{platform:'win32'})()).ready,false);
 const proof=await createWindowsSessionProbe(async(command,args,options)=>{
  assert.equal(command,'powershell.exe');assert.deepEqual(args.slice(0,4),['-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand']);
  const source=Buffer.from(args[4],'base64').toString('utf16le');assert.ok(source.includes('[StyxConsoleProbe]::Read()'));assert.ok(args[4].length<32000);assert.equal(options.timeout_ms,10000);
  assert.ok(!args.includes('-ExecutionPolicy'));return JSON.stringify([evidence(),evidence()]);
 },{platform:'win32'})();assert.equal(proof.ready,true);
});
