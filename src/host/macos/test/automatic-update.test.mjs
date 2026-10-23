import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import {fileURLToPath} from 'node:url';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';

test('native bootstrap automatically hands off once; failures and cancelled work retain recovery', {skip:process.platform!=='darwin',timeout:180000},async t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-auto-update-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const run=promisify(execFile),mac=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
 const binary=path.join(root,'model-test'),entry=path.join(root,'main.swift');fs.copyFileSync(path.join(mac,'Styx.swift'),entry);
 const sources=fs.readdirSync(path.join(mac,'product-ui')).filter(n=>n.endsWith('.swift')).sort().map(n=>path.join(mac,'product-ui',n));
 await run('xcrun',['swiftc','-O','-warnings-as-errors','-target',(process.arch==='arm64'?'arm64':'x86_64')+'-apple-macosx13.0','-D','STYX_PRODUCT_UI','-D','STYX_TESTING','-module-cache-path',path.join(root,'modules'),entry,path.join(mac,'BrandGlyph.swift'),...sources,'-o',binary,'-framework','AppKit','-framework','ApplicationServices','-framework','CoreGraphics','-framework','SwiftUI','-framework','WebKit'],{timeout:120000});
 const token='b'.repeat(43),csrf='c'.repeat(43),ticketId='a'.repeat(32);
 for(const mode of ['success','previous-success','disabled','malformed','not-native','prepare-failed','launch-failed','raced-cancel']){
  const writes=[];let current=mode==='previous-success'?'applied_stopped':mode==='raced-cancel'?'cancelled':'not_started';
  const server=http.createServer((req,res)=>{
   if(req.headers.authorization!=='Bearer '+token){res.writeHead(401);res.end();return}
   const send=(body,status=200)=>{res.writeHead(status,{'Content-Type':'application/json'});res.end(JSON.stringify(body))};
   if(req.url==='/api/session')return send({csrf,nativeAppLifecycleSupported:mode!=='not-native'});
   if(req.url==='/api/snapshot')return send({status:{nativeStartup:{status:'reconciliation_required',reason:'host_payload_update_required',automaticUpdate:mode==='malformed'?'true':mode!=='disabled'}}});
   if(req.method!=='POST'||req.headers['x-styx-csrf']!==csrf)return send({},403);
   writes.push(req.url);
   if(req.url.endsWith('/status'))return send({handoff:{status:current,ticketId}});
   if(req.url.endsWith('/prepare')){
    if(mode==='prepare-failed')return send({error:'work_state_unknown'},409);
    current='awaiting_exit';return send({handoff:{status:current,ticketId}});
   }
   if(req.url.endsWith('/cancel')){current='cancelled';return send({handoff:{status:current,ticketId}})}
   send({},404);
  });
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  try{
   const input=path.join(root,mode+'.url');fs.writeFileSync(input,'http://127.0.0.1:'+server.address().port+'/#session='+token,{mode:0o600});
   const result=await run(binary,['--automatic-update-self-test',input,mode],{timeout:15000});assert.match(result.stdout,/PASS: automatic Host update/);
   const expected=['disabled','malformed','not-native'].includes(mode)?[]:mode==='raced-cancel'?['status']:mode==='launch-failed'?['status','prepare','cancel']:['status','prepare'];
   assert.deepEqual(writes,expected.map(s=>'/api/host-payload/handoff/'+s),mode);
  }finally{server.closeAllConnections();await new Promise(r=>server.close(r))}
 }
});
