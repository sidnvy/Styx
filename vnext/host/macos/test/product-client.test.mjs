import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import {fileURLToPath} from 'node:url';
import {execFile,execFileSync} from 'node:child_process';
import {promisify} from 'node:util';

test('native ZIP transport shares authenticated session and rejects redirects, MIME errors and invalid archives', {skip:process.platform!=='darwin',timeout:120000}, async t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-native-client-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const here=path.dirname(fileURLToPath(import.meta.url)),run=promisify(execFile),binary=path.join(root,'client-test');
 const sdk=process.env.STYX_MACOS_SDK??execFileSync('xcrun',['--sdk','macosx','--show-sdk-path'],{encoding:'utf8'}).trim();
 await run('xcrun',['swiftc','-O','-warnings-as-errors','-sdk',sdk,'-module-cache-path',path.join(root,'modules'),path.join(here,'ProductClientAcceptance.swift'),path.join(here,'../product-ui/ProductCoreClient.swift'),'-o',binary]);
 const token='a'.repeat(43),csrf='b'.repeat(43),archive=Buffer.from([0x50,0x4b,0x03,0x04,1,2,3]);
 for(const mode of ['valid','redirect','wrong-mime','not-zip','oversize','denied']){
  let exports=0,traps=0;const requests=[];
  const server=http.createServer((req,res)=>{
   requests.push({url:req.url,auth:req.headers.authorization,origin:req.headers.origin,csrf:req.headers['x-styx-csrf'],method:req.method});
   if(req.headers.authorization!=='Bearer '+token){res.writeHead(401);res.end();return}
   if(req.url==='/api/session'){res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify({csrf}));return}
   if(req.url==='/redirect-target'){traps++;res.writeHead(200,{'Content-Type':'application/zip'});res.end(archive);return}
   if(req.url!=='/api/plugin/export'||req.method!=='POST'||req.headers['x-styx-csrf']!==csrf||req.headers.origin!==origin){res.writeHead(403);res.end();return}
   let body='';req.on('data',chunk=>body+=chunk);req.on('end',()=>{
    assert.deepEqual(JSON.parse(body),{authorize:true});exports++;
    if(mode==='redirect'){res.writeHead(302,{Location:origin+'/redirect-target'});res.end();return}
    if(mode==='denied'){res.writeHead(403,{'Content-Type':'application/json'});res.end('{}');return}
    res.writeHead(200,{'Content-Type':mode==='wrong-mime'?'application/json':'application/zip'});
    const large=Buffer.alloc(2*1024*1024+1);archive.copy(large);
    res.end(mode==='not-zip'?Buffer.from('not a ZIP'):mode==='oversize'?large:archive);
   });
  });
  await new Promise(r=>server.listen(0,'127.0.0.1',r));const origin='http://127.0.0.1:'+server.address().port;
  try{
   const input=path.join(root,mode+'.url');fs.writeFileSync(input,origin+'/#session='+token+'\n',{mode:0o600});
   const result=await run(binary,[input,mode==='valid'?'accept':'reject'],{timeout:15000});
   assert.match(result.stdout,/PASS: native private-session ZIP transport case/);assert.equal(result.stderr,'');
   assert.equal(exports,1);assert.equal(traps,0,'The client followed a redirect with its private session');
   assert.deepEqual(requests.map(r=>r.url),['/api/session','/api/plugin/export']);
   for(const request of requests){assert.equal(request.auth,'Bearer '+token);assert.equal(request.origin,origin)}
  }finally{server.closeAllConnections();await new Promise(r=>server.close(r))}
 }
});
