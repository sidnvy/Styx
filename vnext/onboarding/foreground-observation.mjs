import {deploymentConnectionHash} from '../shared/deployment-scope.mjs';
// Ephemeral cross-process observation, never an authoritative role/config store.
// Challenge authentication avoids disclosing the shared secret to a reused port.
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import {createHash,createHmac,randomBytes,timingSafeEqual} from 'node:crypto';
import {requirePrivateDirectory,requirePrivateFile,openPrivateFile} from '../host/private-storage.mjs';
const fail=code=>{throw Error(code)};
const sha=value=>createHash('sha256').update(value).digest('hex');
const mac=(key,value)=>createHmac('sha256',key).update(value).digest('hex');
const hex=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
const same=(a,b)=>hex(a)&&hex(b)&&timingSafeEqual(Buffer.from(a,'hex'),Buffer.from(b,'hex'));
const receiptFile=d=>path.join(d,'foreground-observer.json');
function privateSnapshot(file){
 requirePrivateFile(file);const stat=fs.lstatSync(file,{bigint:true});
 if(!stat.isFile()||stat.isSymbolicLink())fail('foreground_observation_file_not_regular');
 if(stat.size>32768n)fail('foreground_observation_file_too_large');
 return {bytes:fs.readFileSync(file,'utf8'),ino:stat.ino.toString(),dev:stat.dev.toString()};
}
const equalSnapshot=(a,b)=>a.bytes===b.bytes&&a.ino===b.ino&&a.dev===b.dev;
function lockIdentity(d){const value=privateSnapshot(path.join(d,'foreground.lock'));return {ino:value.ino,dev:value.dev,sha256:sha(value.bytes)}}
const lockMatches=(d,expected)=>{const actual=lockIdentity(d);return actual.ino===expected.ino&&actual.dev===expected.dev&&actual.sha256===expected.sha256};
// NTFS file IDs routinely exceed Number.MAX_SAFE_INTEGER. New receipts use
// decimal strings; legacy numbers are accepted only when still lossless.
function fileIdentity(value){
 if(typeof value==='number'&&Number.isSafeInteger(value)&&value>=0)return String(value);
 if(typeof value==='string'&&/^(0|[1-9][0-9]{0,19})$/.test(value)&&BigInt(value)<=18446744073709551615n)return value;
 fail('foreground_observation_invalid');
}
function validateReceipt(value){
 if(!value||value.schema!==1||Object.keys(value).some(k=>!['schema','host','port','pid','generation','configurationHash','secret','lock'].includes(k))||value.host!=='127.0.0.1'||!Number.isInteger(value.port)||value.port<1||value.port>65535||!Number.isSafeInteger(value.pid)||value.pid<1||![value.generation,value.configurationHash,value.secret,value.lock?.sha256].every(hex)||!value.lock||Object.keys(value.lock).some(k=>!['ino','dev','sha256'].includes(k)))fail('foreground_observation_invalid');
 return {...value,lock:{ino:fileIdentity(value.lock.ino),dev:fileIdentity(value.lock.dev),sha256:value.lock.sha256}};
}
function missing(d,reason){return {schema:1,status:reason==='not_running'?'not_running':'needs_attention',observation:'cross_process',host:'not_owned',gateway:'not_owned',execConnection:'not_observed',desktopConnection:'not_observed',browserConnection:'not_observed',toolHealth:'not_verified',accountAcceptance:'NOT RUN',...(reason==='not_running'?{}:{reason})}}
function project(value){
 const keys=['schema','status','host','gateway','execConnection','desktopConnection','browserConnection','browserRequested','computerRequested','toolHealth','accountAcceptance','appExit','serviceMutation','reason'];
 const result=Object.fromEntries(keys.filter(k=>value[k]!==undefined).map(k=>[k,value[k]]));
 if(result.schema!==1||typeof result.status!=='string'||Object.values(result).some(v=>!['string','boolean','number'].includes(typeof v))||Object.values(result).some(v=>typeof v==='string'&&v.length>256))fail('foreground_projection_invalid');
 // The owner can report its own connector events. A reused service has a
 // separate lifecycle; its start-time connection sample is not a live probe.
 if(result.host==='service'){if(!['needs_attention','stopping'].includes(result.status))result.status='using_service';result.execConnection='not_observed';result.desktopConnection='not_observed';result.browserConnection='not_observed';}
 if(result.status==='needs_attention'){result.execConnection='not_observed';result.desktopConnection='not_observed';result.browserConnection='not_observed';}
 return {...result,observation:'authenticated_foreground_owner'};
}
export async function startForegroundObservation({stateDir,configurationHash,projection}={}){
 requirePrivateDirectory(stateDir);if(!hex(configurationHash)||typeof projection!=='function')fail('foreground_observation_scope_required');
 const file=receiptFile(stateDir),generation=randomBytes(32).toString('hex'),secret=randomBytes(32).toString('hex'),lock=lockIdentity(stateDir);
 let ownedReceipt,fd,closing=false;
 const server=http.createServer((req,res)=>{
  res.setHeader('Cache-Control','no-store');res.setHeader('Content-Type','application/json');
  const reject=status=>{res.writeHead(status);res.end('{"status":"unavailable"}')};
  if(closing||req.method!=='GET'||req.url!=='/status'||req.headers.origin||req.headers['transfer-encoding']||req.headers['content-length']&&req.headers['content-length']!=='0'){reject(403);return;}
  const challenge=req.headers['x-styx-challenge'],authorization=req.headers.authorization;
  if(!hex(challenge)||typeof authorization!=='string'||!same(authorization,mac(secret,'request\0'+generation+'\0'+challenge))){reject(401);return;}
  try{
   if(!ownedReceipt||!equalSnapshot(privateSnapshot(file),ownedReceipt)||!lockMatches(stateDir,lock)){reject(409);return;}
   const body={schema:1,generation,configurationHash,challenge,projection:project(projection())};
   const bytes=JSON.stringify(body);res.end(JSON.stringify({...body,mac:mac(secret,'response\0'+bytes)}));
  }catch{reject(409);}
 });
 server.requestTimeout=2000;server.headersTimeout=2000;server.keepAliveTimeout=1;server.maxHeadersCount=16;
 try{
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',()=>{server.off('error',reject);resolve()})});
  server.on('error',()=>{});
  if(!lockMatches(stateDir,lock))fail('foreground_observation_lock_changed');
  const value={schema:1,host:'127.0.0.1',port:server.address().port,pid:process.pid,generation,configurationHash,secret,lock};
  fd=openPrivateFile(file);const bytes=JSON.stringify(value)+'\n',stat=fs.fstatSync(fd,{bigint:true});
  fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);ownedReceipt={bytes,ino:stat.ino.toString(),dev:stat.dev.toString()};
  // The native Windows private-file helper already establishes SID ownership.
  if(process.platform!=='win32'){const dir=fs.openSync(stateDir,'r');try{fs.fsyncSync(dir)}finally{fs.closeSync(dir)}}
  return {generation,async close(){
   if(closing)return;closing=true;
   await new Promise(resolve=>{server.close(resolve);server.closeAllConnections()});
   try{if(!equalSnapshot(privateSnapshot(file),ownedReceipt))fail('foreground_observation_receipt_changed');fs.unlinkSync(file)}finally{fs.closeSync(fd)}
  }};
 }catch(error){closing=true;await new Promise(resolve=>{server.close(()=>resolve());server.closeAllConnections()});if(fd!==undefined)fs.closeSync(fd);throw error}
}
export async function observeForegroundOwner(stateDir){
 try{requirePrivateDirectory(stateDir)}catch{return missing(stateDir,'foreground_observation_directory_unavailable')}
 const file=receiptFile(stateDir);let saved,receipt;
 try{saved=privateSnapshot(file);receipt=validateReceipt(JSON.parse(saved.bytes));}
 catch(error){if(error.code==='ENOENT')return missing(stateDir,fs.existsSync(path.join(stateDir,'foreground.lock'))?'foreground_owned_or_interrupted_do_not_take_over':'not_running');return missing(stateDir,'foreground_observation_receipt_unavailable')}
 function unchanged(){
  if(!equalSnapshot(privateSnapshot(file),saved)||!lockMatches(stateDir,receipt.lock))fail('foreground_observation_owner_changed');
  const config=privateSnapshot(path.join(stateDir,'deployment.json'));if(deploymentConnectionHash(config.bytes)!==receipt.configurationHash)fail('foreground_scope_changed');
 }
 try{
  unchanged();const challenge=randomBytes(32).toString('hex');
  const response=await new Promise((resolve,reject)=>{
   const request=http.request({host:'127.0.0.1',port:receipt.port,path:'/status',method:'GET',agent:false,headers:{Authorization:mac(receipt.secret,'request\0'+receipt.generation+'\0'+challenge),'X-Styx-Challenge':challenge}},res=>{
    if(res.statusCode!==200){res.resume();reject(Error('foreground_owner_refused'));return;}
    let bytes='';res.setEncoding('utf8');res.on('data',data=>{bytes+=data;if(Buffer.byteLength(bytes)>16384){res.destroy();reject(Error('foreground_observation_response_too_large'))}});res.on('error',reject);res.on('end',()=>{try{resolve(JSON.parse(bytes))}catch{reject(Error('foreground_observation_invalid_response'))}});
   });
   const timer=setTimeout(()=>request.destroy(Error('foreground_owner_unreachable')),1500);
   request.on('close',()=>clearTimeout(timer));request.on('error',reject);request.end();
  });
  const {mac:signature,...body}=response;
  if(body.schema!==1||body.generation!==receipt.generation||body.configurationHash!==receipt.configurationHash||body.challenge!==challenge||!same(signature,mac(receipt.secret,'response\0'+JSON.stringify(body))))fail('foreground_owner_authentication_failed');
  unchanged();return {...project(body.projection),ownerGeneration:receipt.generation};
 }catch(error){return missing(stateDir,error.message==='foreground_scope_changed'?'foreground_scope_changed':'foreground_owner_unavailable_or_changed')}
}
