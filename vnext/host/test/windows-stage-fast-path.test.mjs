import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import cp from 'node:child_process';
import {syncBuiltinESMExports} from 'node:module';
import {generateKeyPairSync,createHash,sign} from 'node:crypto';
import {stageSignedRelease,verifySignedRelease} from '../installer.mjs';
import {openPrivatePayloadFiles,requirePrivatePaths,ensurePrivateDirectory} from '../private-storage.mjs';
const windows=process.platform==='win32';
const sha=value=>createHash('sha256').update(value).digest('hex');
function fixture(t,count=4){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-stage-fast-')),source=path.join(root,'source'),installRoot=path.join(root,'installed');
 fs.mkdirSync(source);fs.mkdirSync(path.join(source,'data'));
 const key=generateKeyPairSync('ed25519'),files=[];
 for(let i=0;i<count;i++){const name='data/file-'+i+'.txt',data=Buffer.from('PUBLIC SIGNED FIXTURE '+i);fs.writeFileSync(path.join(source,name),data);files.push({path:name,sha256:sha(data),size:data.length,executable:false});}
 const manifest={schema:1,version:'stage-fast-test',platform:process.platform,arch:process.arch,files},raw=JSON.stringify(manifest)+'\n';fs.writeFileSync(path.join(source,'manifest.json'),raw);fs.writeFileSync(path.join(source,'manifest.sig'),sign(null,Buffer.from(raw),key.privateKey).toString('base64url')+'\n');
 t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 return {root,source,installRoot,publicKeyPem:key.publicKey.export({type:'spki',format:'pem'}),version:manifest.version,manifest};
}
const stage=f=>stageSignedRelease({sourceDir:f.source,installRoot:f.installRoot,publicKeyPem:f.publicKeyPem});
const published=f=>fs.existsSync(path.join(f.installRoot,'releases',f.version));
function withFsPatch(method,hook,run){const original=fs[method];fs[method]=(...args)=>hook(original,...args);try{return run();}finally{fs[method]=original;}}
function scratchStage(f){try{return fs.readdirSync(path.join(f.installRoot,'releases')).find(x=>x.startsWith('.stage-'));}catch(error){if(error.code==='ENOENT')return;throw error;}}
function evidence(name,value){if(process.env.STYX_WINDOWS_STAGE_EVIDENCE){fs.writeFileSync(path.join(process.env.STYX_WINDOWS_STAGE_EVIDENCE,name+'.json'),JSON.stringify(value,null,2)+'\n');}}

test('payload batch is Windows-only and refuses existing files before repairing them',t=>{
 const f=fixture(t),directory=path.join(f.root,'private');ensurePrivateDirectory(directory);
 const file=path.join(directory,'existing');fs.writeFileSync(file,'foreign existing fixture');
 assert.throws(()=>openPrivatePayloadFiles([{path:file,mode:0o600}]),windows?/private_payload_creation_failed/:/windows_payload_batch_required/);
 assert.equal(fs.readFileSync(file,'utf8'),'foreign existing fixture');
});

test('private directory exact BigInt identities survive lossy Number stat values without changing default return type',t=>{
 const f=fixture(t),folder=path.join(f.root,'exact-directory'),original=fs.lstatSync;let lossyReads=0;
 fs.lstatSync=(file,options)=>{const info=original(file,options);if(file===folder&&!options?.bigint){lossyReads++;return Object.assign(Object.create(Object.getPrototypeOf(info)),info,{ino:Number.MAX_SAFE_INTEGER+3});}return info;};
 try{const created=ensurePrivateDirectory(folder,{exclusive:true,bigint:true});assert.equal(typeof created.ino,'bigint');assert.equal(created.ino,original(folder,{bigint:true}).ino);assert.equal(ensurePrivateDirectory(folder,{bigint:true}).ino,created.ino);assert.equal(typeof ensurePrivateDirectory(folder).ino,'number');assert(lossyReads>0);}finally{fs.lstatSync=original;}
});

test('native exact-directory ACL check refuses a replacement without deleting the foreign empty directory',{skip:!windows},t=>{
 const f=fixture(t),folder=path.join(f.root,'replace-exact-directory'),original=cp.execFileSync;let replacement;
 cp.execFileSync=(program,args,options)=>{
  if(program==='powershell.exe'&&options?.env?.STYX_PRIVATE_PATHS_TO_VERIFY&&!replacement&&JSON.parse(options.env.STYX_PRIVATE_PATHS_TO_VERIFY).includes(folder)){
   fs.renameSync(folder,folder+'.own-moved');fs.mkdirSync(folder);replacement=fs.lstatSync(folder,{bigint:true});
  }
  return original(program,args,options);
 };syncBuiltinESMExports();
 try{assert.throws(()=>ensurePrivateDirectory(folder,{exclusive:true,bigint:true}),/private_directory_creation_failed/);}finally{cp.execFileSync=original;syncBuiltinESMExports();}
 assert(replacement);assert.equal(fs.lstatSync(folder,{bigint:true}).ino,replacement.ino);assert.equal(fs.readdirSync(folder).length,0);
});

test('native signed public stage validates every actual DACL and signature with bounded ACL process count',{skip:!windows,timeout:600000},t=>{
 let f=fixture(t,64);
 if(process.env.STYX_WINDOWS_STAGE_BUNDLE){f={...f,source:process.env.STYX_WINDOWS_STAGE_BUNDLE,publicKeyPem:fs.readFileSync(process.env.STYX_WINDOWS_STAGE_PUBLISHER),version:JSON.parse(fs.readFileSync(path.join(process.env.STYX_WINDOWS_STAGE_BUNDLE,'manifest.json'))).version};}
 const before=verifySignedRelease(f.source,f.publicKeyPem),original=cp.execFileSync;let calls=0,batchGroups=[];
 cp.execFileSync=(program,args,options)=>{if(program==='powershell.exe'){calls++;if(options?.env?.STYX_NEW_PAYLOAD_FILES){const rows=JSON.parse(options.env.STYX_NEW_PAYLOAD_FILES);assert(rows.length<=32);batchGroups.push(rows.length);}}return original(program,args,options);};syncBuiltinESMExports();
 const started=Date.now();let result;
 try{result=stage(f);}finally{cp.execFileSync=original;syncBuiltinESMExports();}
 const elapsedMs=Date.now()-started,release=path.join(f.installRoot,'releases',f.version),after=verifySignedRelease(release,f.publicKeyPem);
 assert.equal(result.status,'staged');assert.equal(after.sha256,before.sha256);assert.equal(batchGroups.reduce((a,b)=>a+b,0),before.manifest.files.length+2);
 // The new file-owner path must actually be used, including under this NAB
 // account whose empty-file inherited owner failed the original probe.
 assert(batchGroups.some(n=>n>1));if(before.manifest.files.length===2200)assert(calls<1100);
 const paths=[];function walk(folder){paths.push({path:folder,kind:'directory'});for(const item of fs.readdirSync(folder,{withFileTypes:true})){const file=path.join(folder,item.name);if(item.isDirectory())walk(file);else paths.push({path:file,kind:'file'});}}walk(release);
 for(let i=0;i<paths.length;i+=32)requirePrivatePaths(paths.slice(i,i+32));
 assert(elapsedMs<300000,'native_stage_exceeds_five_minute_engineering_budget');
 evidence('stage-performance',{status:'PASS',payloadFiles:before.manifest.files.length,totalInstalledPaths:paths.length,elapsedMs,powershellInvocations:calls,emptyFileOwnerBatchGroups:batchGroups,manifestSha256:after.sha256,actualEveryInstalledPathDaclVerified:true,sourceBundle:f.source});
});

test('native staged public bytes tampered after copy fail signature hash before publication',{skip:!windows},t=>{
 const f=fixture(t);let injected=false;
 withFsPatch('fsyncSync',(original,fd)=>{const result=original(fd);if(!injected){const name=scratchStage(f);if(name){const file=path.join(f.installRoot,'releases',name,'data/file-0.txt');if(fs.existsSync(file)&&fs.statSync(file).size){injected=true;fs.writeFileSync(file,'TAMPERED PUBLIC FIXTURE');}}}return result;},()=>assert.throws(()=>stage(f),/release_file_(metadata|hash)_mismatch/));
 assert(injected);assert(!published(f));
});

test('native broad DACL added during public copy is refused before publication',{skip:!windows},t=>{
 const f=fixture(t);let injected=false;
 withFsPatch('fsyncSync',(original,fd)=>{const result=original(fd);if(!injected){const name=scratchStage(f);if(name){const file=path.join(f.installRoot,'releases',name,'data/file-0.txt');if(fs.existsSync(file)&&fs.statSync(file).size){injected=true;cp.execFileSync('icacls.exe',[file,'/grant','*S-1-1-0:(R)'],{stdio:'ignore',windowsHide:true,timeout:30000});}}}return result;},()=>assert.throws(()=>stage(f),/private_paths_acl_not_owner_only/));
 assert(injected);assert(!published(f));
});

test('native replaced just-created file is never registered as owned or deleted',{skip:!windows},t=>{
 const f=fixture(t);let foreign,observations=0;
 withFsPatch('lstatSync',(original,file,...args)=>{const info=original(file,...args);if(!foreign&&String(file).includes('.stage-')&&String(file).endsWith('file-0.txt')&&++observations===2){
  // The batch returns before remember(): replacement must be compared against
  // the still-open original FD identity, not captured as a newly owned inode.
  const moved=file+'.own-moved';try{fs.renameSync(file,moved);fs.writeFileSync(file,'FOREIGN SENTINEL');foreign=file;}catch{}
  return original(file,...args);
 }return info;},()=>assert.throws(()=>stage(f),/private_payload_creation_(failed|binding_changed)|stage_path_identity_changed/));
 assert(foreign);assert.equal(fs.readFileSync(foreign,'utf8'),'FOREIGN SENTINEL');assert(!published(f));
});

test('native unknown child on failure preserves foreign sentinel and unpublished stage',{skip:!windows},t=>{
 const f=fixture(t);let sentinel;
 withFsPatch('fsyncSync',(original,fd)=>{const result=original(fd);if(!sentinel){const name=scratchStage(f);if(name){sentinel=path.join(f.installRoot,'releases',name,'foreign-unknown.txt');fs.writeFileSync(sentinel,'FOREIGN UNKNOWN SENTINEL');throw Error('controlled_public_stage_interruption');}}return result;},()=>assert.throws(()=>stage(f),/controlled_public_stage_interruption/));
 assert(sentinel);assert.equal(fs.readFileSync(sentinel,'utf8'),'FOREIGN UNKNOWN SENTINEL');assert(!published(f));
});

test('native redirected child directory is not traversed or recursively removed',{skip:!windows},t=>{
 const f=fixture(t),outside=path.join(f.root,'foreign-directory');fs.mkdirSync(outside);fs.writeFileSync(path.join(outside,'sentinel'),'FOREIGN DIRECTORY');let redirected;
 withFsPatch('lstatSync',(original,file,...args)=>{if(!redirected&&String(file).includes('.stage-')&&path.basename(String(file))==='data'){
  try{fs.renameSync(file,file+'.own-moved');fs.symlinkSync(outside,file,'junction');redirected=file;}catch{}
 }return original(file,...args);},()=>assert.throws(()=>stage(f),/private_directory_not_regular|private_payload_directory_creation_failed|stage_path_(not_regular|identity_changed)/));
 assert(redirected);assert.equal(fs.readFileSync(path.join(outside,'sentinel'),'utf8'),'FOREIGN DIRECTORY');assert.equal(fs.readdirSync(outside).length,1);assert(fs.lstatSync(redirected).isSymbolicLink());assert(!published(f));
});

test('native failed empty-file batch preserves original inode linked inside a replaced foreign parent',{skip:!windows},t=>{
 const f=fixture(t),original=cp.execFileSync;let foreignFile,sentinel;
 cp.execFileSync=(program,args,options)=>{
  if(program==='powershell.exe'&&options?.env?.STYX_NEW_PAYLOAD_FILES&&!foreignFile){
   const first=JSON.parse(options.env.STYX_NEW_PAYLOAD_FILES)[0],moved=first.parent+'.own-moved';
   fs.renameSync(first.parent,moved);fs.mkdirSync(first.parent);
   foreignFile=path.join(first.parent,path.basename(first.file));fs.linkSync(path.join(moved,path.basename(first.file)),foreignFile);
   sentinel=path.join(first.parent,'foreign-sentinel');fs.writeFileSync(sentinel,'FOREIGN PARENT SENTINEL');
   throw Error('controlled_empty_batch_failure');
  }
  return original(program,args,options);
 };syncBuiltinESMExports();
 try{assert.throws(()=>stage(f),/private_payload_creation_failed/);}finally{cp.execFileSync=original;syncBuiltinESMExports();}
 assert(foreignFile);assert(fs.existsSync(foreignFile));assert.equal(fs.statSync(foreignFile).size,0);assert.equal(fs.readFileSync(sentinel,'utf8'),'FOREIGN PARENT SENTINEL');assert(!published(f));
});

test('native actual installer process death cannot publish a partially copied generation',{skip:!windows,timeout:120000},async t=>{
 const f=fixture(t,64),worker=path.join(f.root,'worker.mjs'),input=path.join(f.root,'input.json');fs.writeFileSync(input,JSON.stringify({sourceDir:f.source,installRoot:f.installRoot,publicKeyPem:f.publicKeyPem}));
 fs.writeFileSync(worker,`import fs from 'node:fs';import path from 'node:path';import {stageSignedRelease} from ${JSON.stringify(new URL('../installer.mjs',import.meta.url).href)};const input=JSON.parse(fs.readFileSync(process.argv[2])),original=fs.fsyncSync;let ready=false;fs.fsyncSync=(fd)=>{const r=original(fd);const releases=path.join(input.installRoot,'releases');if(!ready&&fs.existsSync(releases)){const name=fs.readdirSync(releases).find(x=>x.startsWith('.stage-'));const file=name&&path.join(releases,name,'data/file-0.txt');if(file&&fs.existsSync(file)&&fs.statSync(file).size){ready=true;process.stdout.write('OWN_STAGE_INTERRUPT_READY\\n');Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,120000);}}return r;};stageSignedRelease(input);`);
 const child=cp.spawn(process.execPath,[worker,input],{stdio:['ignore','pipe','pipe']});let output='';
 await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('owned_stage_interrupt_ready_timeout')),60000);child.once('error',reject);child.stdout.on('data',chunk=>{output+=chunk;if(output.includes('OWN_STAGE_INTERRUPT_READY')){clearTimeout(timer);resolve();}});child.once('exit',()=>{if(!output.includes('OWN_STAGE_INTERRUPT_READY')){clearTimeout(timer);reject(Error('owned_stage_exited_before_interruption'));}});});
 const exit=new Promise(resolve=>child.once('exit',(code,signal)=>resolve({code,signal})));child.kill('SIGKILL');const ended=await exit;assert(!published(f));assert.equal(child.exitCode!==null||child.signalCode!==null,true);evidence('stage-interruption',{status:'PASS',actualChildKilled:true,...ended,published:false});
});
