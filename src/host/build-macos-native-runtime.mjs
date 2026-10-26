// Native App packaging bootstrap only. Complete schema/closure admission remains
// the original signed Rust C08 reader; this module does not issue release proofs.
import fs from 'node:fs';
import path from 'node:path';
import {createHash,createPublicKey,verify} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {requirePrivateDirectory,requirePrivateFile} from './private-storage.mjs';
const assert=(x,reason)=>{if(!x)throw Error(reason)};
const hex=s=>typeof s==='string'&&/^[a-f0-9]{64}$/.test(s);
const absolute=s=>typeof s==='string'&&path.isAbsolute(s)&&path.normalize(s)===s&&!/[\x00-\x1f\x7f]/.test(s);
function file(name,max){
 const st=requirePrivateFile(name);requireNoMacAcl(name);assert(st.nlink===1&&st.size>0&&st.size<=max,'native_bootstrap_regular_file_required');
 const fd=fs.openSync(name,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
 try{
  const opened=fs.fstatSync(fd,{bigint:true});assert(opened.dev===BigInt(st.dev)&&opened.ino===BigInt(st.ino),'native_bootstrap_changed');
  requirePrivateFile(name);requireNoMacAcl(name);return {fd,stat:opened};
 }catch(error){fs.closeSync(fd);throw error;}
}
function digest(fd,max){
 const before=fs.fstatSync(fd,{bigint:true});assert(before.isFile()&&before.nlink===1n&&before.size<=BigInt(max),'native_bootstrap_file_bound');
 const h=createHash('sha256'),buf=Buffer.alloc(1024*1024);let offset=0,n;
 while((n=fs.readSync(fd,buf,0,buf.length,offset))>0){offset+=n;assert(offset<=max,'native_bootstrap_file_bound');h.update(buf.subarray(0,n));}
 const after=fs.fstatSync(fd,{bigint:true});assert(['dev','ino','size','mtimeNs','ctimeNs'].every(k=>before[k]===after[k])&&BigInt(offset)===after.size,'native_bootstrap_changed');return h.digest('hex');
}
// Existing private-storage owns currentUID/mode/no-symlink admission. Its
// Darwin implementation does not inspect ACLs, so reject every ACL (not just
// broad grants) using the platform's fixed bounded listing before path exec.
// We do not interpret ACL principals, create ACLs or repair existing objects.
function requireNoMacAcl(name){
 if(process.platform!=='darwin')return;
 const output=execFileSync('/bin/ls',['-lde',name],{encoding:'utf8',timeout:10000,maxBuffer:32768,stdio:['ignore','pipe','pipe'],env:{LC_ALL:'C',PATH:'/usr/bin:/bin'}});
 const lines=output.replace(/\n$/,'').split('\n');
 assert(lines.length===1&&/^[d-][rwxStTs-]{9}[@ ]?\s/.test(lines[0]),'native_bootstrap_acl_not_empty');
}
function directory(name){const st=requirePrivateDirectory(name);requireNoMacAcl(name);assert(fs.realpathSync(name)===name,'native_bootstrap_canonical_directory_required');return st;}

// Authenticate only what is needed to execute the original native verifier.
// No unverified payload process runs before external Ed25519 pin/raw signature,
// fixed CLI location, whole CLI SHA and native Mach-O target have been checked.
const nativeStateSchema=Object.freeze({native_runtime_migrated_v1:2,native_runtime_migrated_v2:2,native_runtime_migrated_v3:2,native_runtime_selected_v1:3,native_app_runtime_selected_v1:4});
export function withAuthenticatedMacReader(input,arch,operation){
 assert(input&&Object.keys(input).sort().join(',')==='expectedPublisher,payloadDir,publisherFile','complete_native_runtime_inputs_required');
 assert(['x64','arm64'].includes(arch)&&absolute(input.payloadDir)&&absolute(input.publisherFile)&&hex(input.expectedPublisher),'native_macos_inputs_required');
 directory(input.payloadDir);directory(path.dirname(input.publisherFile));directory(path.join(input.payloadDir,'bin'));
 const held=[];const hold=(name,max)=>{const f=file(name,max);held.push(f);return f};
 try{
  const pub=hold(input.publisherFile,4096),mf=hold(path.join(input.payloadDir,'manifest.json'),1048576),sf=hold(path.join(input.payloadDir,'manifest.sig'),64);
  const pubRaw=fs.readFileSync(pub.fd),raw=fs.readFileSync(mf.fd),sig=fs.readFileSync(sf.fd);
  assert(sig.length===64,'native_raw_signature_required');const key=createPublicKey(pubRaw);
  assert(key.asymmetricKeyType==='ed25519'&&createHash('sha256').update(key.export({format:'der',type:'spki'})).digest('hex')===input.expectedPublisher,'native_publisher_pin_mismatch');
  assert(verify(null,raw,key,sig),'native_release_signature_invalid');
  const manifest=JSON.parse(raw),target=arch==='x64'?'x86_64-apple-darwin':'aarch64-apple-darwin';
  assert(manifest.schema===2&&manifest.runtime_format==='native_rust_v1'&&manifest.scope==='runtime_candidate'&&manifest.component==='styx'&&Object.hasOwn(nativeStateSchema,manifest.minimum_reader)&&manifest.contracts?.control===1&&manifest.contracts?.management_state===nativeStateSchema[manifest.minimum_reader]&&manifest.target===target&&manifest.entrypoint==='bin/styx'&&Array.isArray(manifest.files),'native_macos_c08_required');
  const entries=manifest.files.filter(m=>m.path==='bin/styx');assert(entries.length===1,'native_fixed_cli_required');const member=entries[0];
  assert(hex(member.sha256)&&member.executable===true&&Number.isSafeInteger(member.size)&&member.size>0&&member.size<=1073741824,'native_fixed_cli_required');
  const cli=path.join(input.payloadDir,'bin/styx'),image=hold(cli,1073741824);assert(image.stat.size===BigInt(member.size)&&digest(image.fd,1073741824)===member.sha256,'native_cli_hash_mismatch');
  const head=Buffer.alloc(16);assert(fs.readSync(image.fd,head,0,16,0)===16&&head.readUInt32LE(0)===0xfeedfacf&&head.readUInt32LE(4)===(arch==='x64'?0x01000007:0x0100000c)&&head.readUInt32LE(12)===2,'native_cli_macho_required');
  const before={manifestSha256:createHash('sha256').update(raw).digest('hex'),signatureSha256:createHash('sha256').update(sig).digest('hex'),publisherSha256:createHash('sha256').update(pubRaw).digest('hex'),cliSha256:member.sha256,target};
  // Recheck live owner/mode/ACL immediately before executing the verified
  // pathname. Held descriptors/hash alone do not prevent another principal
  // writing a mode/ACL-accessible original file or changing directory entries.
  directory(input.payloadDir);directory(path.join(input.payloadDir,'bin'));directory(path.dirname(input.publisherFile));
  for(const name of [input.publisherFile,path.join(input.payloadDir,'manifest.json'),path.join(input.payloadDir,'manifest.sig'),cli]){requirePrivateFile(name);requireNoMacAcl(name);}
  const result=operation({cli,manifest,...before});
  for(const [f,name,expected,max]of [[mf,path.join(input.payloadDir,'manifest.json'),before.manifestSha256,1048576],[sf,path.join(input.payloadDir,'manifest.sig'),before.signatureSha256,64],[pub,input.publisherFile,before.publisherSha256,4096],[image,cli,before.cliSha256,1073741824]]){
   const current=fs.lstatSync(name,{bigint:true});assert(!current.isSymbolicLink()&&current.dev===f.stat.dev&&current.ino===f.stat.ino&&digest(f.fd,max)===expected,'native_bootstrap_changed');
  }
  return result;
 }finally{for(const f of held)fs.closeSync(f.fd);}
}
// Cross-architecture signing may authenticate the publisher/manifest/fixed CLI
// envelope, but cannot run a foreign reader or claim full closure validation.
// Only actual native reader execution may supply that closure observation.
export function authenticateNativeMacRuntimeEnvelope(input,arch){
 return withAuthenticatedMacReader(input,arch,reader=>({...reader,bootstrapOnly:true,readerActualWait:false,readerExitCode:null}));
}
export function verifyNativeMacRuntime(input,arch=process.arch){
 return withAuthenticatedMacReader(input,arch,reader=>{
  assert(process.platform==='darwin'&&process.arch===arch,'native_macos_reader_execution_required');
  const stdout=execFileSync(reader.cli,['release','verify','--payload-dir',input.payloadDir,'--publisher-file',input.publisherFile,'--expected-publisher',input.expectedPublisher,'--json'],{encoding:'utf8',timeout:150000,maxBuffer:65536,stdio:['ignore','pipe','pipe'],env:{HOME:process.env.HOME,PATH:'/usr/bin:/bin:/usr/sbin:/sbin',TMPDIR:process.env.TMPDIR??'/tmp'}});
  const report=JSON.parse(stdout);assert(report.schema===1&&report.scope==='runtime_candidate'&&report.runtime_format==='native_rust_v1'&&report.minimum_reader===reader.manifest.minimum_reader&&report.target===reader.target&&report.entrypoint==='bin/styx'&&report.source_revision===reader.manifest.source?.revision&&report.source_inputs_sha256===reader.manifest.source?.inputs_sha256&&report.manifest_sha256===reader.manifestSha256&&report.publisher_spki_sha256===input.expectedPublisher&&report.installed===false&&report.runtime_launched===false,'native_original_reader_report_mismatch');
  return {...reader,report,readerActualWait:true,readerExitCode:0};
 });
}
export function copyNativeMacRuntime(input,resources,arch=process.arch){
 const original=verifyNativeMacRuntime(input,arch),payload=path.join(resources,'native'),publisher=path.join(resources,'native-publisher.pem');
 assert(!fs.existsSync(payload)&&!fs.existsSync(publisher),'native_output_exists');
 // PrivateRoot opens both Resources (publisher parent) and payload. Historical
 // publicModes(0755/0644) is incompatible; never normalize this branch publicly.
 fs.chmodSync(resources,0o700);fs.mkdirSync(payload,{mode:0o700});
 for(const name of [...original.manifest.files.map(m=>m.path),'manifest.json','manifest.sig']){
  // Full manifest paths were admitted by the original Rust reader above.
  const from=path.join(input.payloadDir,...name.split('/')),to=path.join(payload,...name.split('/'));
  fs.mkdirSync(path.dirname(to),{recursive:true,mode:0o700});fs.copyFileSync(from,to,fs.constants.COPYFILE_EXCL);
  fs.chmodSync(to,original.manifest.files.find(m=>m.path===name)?.executable?0o700:0o600);
 }
 fs.copyFileSync(input.publisherFile,publisher,fs.constants.COPYFILE_EXCL);fs.chmodSync(publisher,0o600);
 const copied=verifyNativeMacRuntime({payloadDir:payload,publisherFile:publisher,expectedPublisher:input.expectedPublisher},arch);
 assert(copied.manifestSha256===original.manifestSha256&&copied.signatureSha256===original.signatureSha256&&copied.cliSha256===original.cliSha256,'native_copy_changed');
 return {schema:1,cli:'native/bin/styx',cliSha256:copied.cliSha256,payload:'native',manifestSha256:copied.manifestSha256,publisher:'native-publisher.pem',publisherSpkiSha256:input.expectedPublisher};
}
