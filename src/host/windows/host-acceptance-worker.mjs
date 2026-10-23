// Explicit acceptance child only. Owns real native Host connectors; no mock executor.
import fs from 'node:fs';
import readline from 'node:readline';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {verifySignedRelease} from '../installer.mjs';
const lines=readline.createInterface({input:process.stdin,crlfDelay:Infinity});
const iterator=lines[Symbol.asyncIterator]();
const initial=await iterator.next();
let abort,tasks=[];
try{
 if(initial.done||Buffer.byteLength(initial.value)>65536)throw Error('private_start_required');
 const {releaseRoot,publisherKeyFile,config}=JSON.parse(initial.value);
 verifySignedRelease(releaseRoot,fs.readFileSync(publisherKeyFile),{platform:process.platform,arch:process.arch});
 const {runHostConnector}=await import(pathToFileURL(path.join(releaseRoot,'host/connect.mjs')));
 const {runBrowserConnector}=await import(pathToFileURL(path.join(releaseRoot,'host/browser.mjs')));
 abort=new AbortController();
 const ready=lane=>()=>process.stdout.write(JSON.stringify({type:'ready',lane})+'\n');
 tasks=[runHostConnector(config,{signal:abort.signal,retryMinMs:200,retryMaxMs:1000,onReady:ready('exec')}),runBrowserConnector(config,{signal:abort.signal,retryMinMs:200,retryMaxMs:1000,onReady:ready('browser')})];
 for(const task of tasks)task.catch(()=>{});
 process.stdout.write(JSON.stringify({type:'started',signedReleaseVerified:true})+'\n');
 for(;;){const item=await iterator.next();if(item.done)break;const command=JSON.parse(item.value);if(command.operation==='stop')break;}
}catch{process.exitCode=2;process.stdout.write(JSON.stringify({type:'failed',reason:'native_host_fixture_failed'})+'\n');}
finally{abort?.abort();const results=await Promise.allSettled(tasks);if(results.some(x=>x.status==='rejected'))process.exitCode=2;lines.close();process.stdout.write(JSON.stringify({type:'stopped',connectorsSettled:true})+'\n');}
