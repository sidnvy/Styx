import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawn,execFileSync} from 'node:child_process';
import {once} from 'node:events';
import http from 'node:http';
const repository=fileURLToPath(new URL('../../../',import.meta.url));
const manifest=JSON.parse(fs.readFileSync(path.join(repository,'package.json')));
function entry(name){const command=manifest.scripts[name];assert.ok(command.startsWith('node '));const file=path.join(repository,command.slice(5));assert.ok(file.startsWith(path.join(repository,'src')+path.sep));return file;}
test('repository commands reach the sole shared Core and retired root entrypoints cannot remain active',()=>{
 const result=JSON.parse(execFileSync(process.execPath,[entry('styx'),'help'],{cwd:repository,encoding:'utf8'}));
 assert.ok(result.commands.includes('capabilities STATE [computer-on|computer-off|browser-on|browser-off --authorize]'));
 assert.ok(result.commands.includes('runtime-plan STATE BUNDLE'));
 for(const relative of ['vnext','src/server.mjs','plugin.json','mcp.json','.github/workflows/ci.yml'])assert.equal(fs.existsSync(path.join(repository,relative)),false,relative);
 assert.equal(manifest.exports,undefined);assert.equal(manifest.dependencies,undefined);
});
test('root Gateway command starts the current authenticated listener instead of importing an inert module',async t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'styx-root-gateway-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const token=path.join(dir,'token'),catalog=path.join(dir,'targets.json');fs.writeFileSync(token,'source-layout-fixture-token-1234567890',{mode:0o600});fs.writeFileSync(catalog,JSON.stringify({version:1,targets:[]}),{mode:0o600});
 const env=Object.fromEntries(Object.entries(process.env).filter(([name])=>!name.startsWith('STYX_')));
 const child=spawn(process.execPath,[entry('gateway'),catalog],{cwd:repository,env:{...env,STYX_MCP_TOKEN_FILE:token,STYX_LISTEN_PORT:'0',STYX_ALLOWED_HOSTS:'styx-layout.invalid'},stdio:['ignore','pipe','pipe']});
 const exited=once(child,'exit');t.after(async()=>{if(child.exitCode===null)child.kill('SIGTERM');await exited;});
 let timer;const listening=await new Promise((resolve,reject)=>{let output='';timer=setTimeout(()=>reject(Error('root_gateway_not_listening')),7000);child.once('error',reject);child.stdout.on('data',chunk=>{output+=chunk;if(output.includes('\n')){try{resolve(JSON.parse(output.split('\n')[0]));}catch(error){reject(error);}}});});clearTimeout(timer);
 assert.equal(listening.status,'listening');assert.ok(listening.port>0);
 const status=await new Promise((resolve,reject)=>{const request=http.get({hostname:'127.0.0.1',port:listening.port,path:'/mcp',headers:{Host:'styx-layout.invalid'}},response=>{response.resume();response.once('end',()=>resolve(response.statusCode));});request.once('error',reject);});assert.equal(status,401);
 child.kill('SIGTERM');const [code]=await exited;if(process.platform!=='win32')assert.equal(code,0);
});
