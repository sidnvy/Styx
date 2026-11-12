// Explicit local production-UI loop. No installer, DMG, test double or profile
// writer. Existing publisher-sealed Runtime and original local identity only.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync,spawnSync} from 'node:child_process';
import {buildMacApp,MAC_LOCAL_DEVELOPMENT,normalizeMacLocalSigning,verifyMacLocalSigning,macLocalSigningPlan} from './build-macos-app.mjs';
import {verifyNativeMacRuntime,copyNativeMacRuntime} from './build-macos-native-runtime.mjs';
import {preparedPreviewInventory,machOFiles} from './build-macos-preview.mjs';
const need=(ok,code)=>{if(!ok)throw Error(code)};
const PROJECT='/Users/it-bootstrap/Developer/Styx';
const PUBLISHER='bbb49c2626c3d4ef3cf9e1679db5305b100cee4a8c41c29c958ede82fb868bed';
const CERT='90792ed11f23a00f0107450dbc184f992016569ca188454cfa286fe0022c2c1e';
const LEAF='cb50cee601419f28b43756f4fc8aefdbf60abae2';
const SIGNING='/Users/it-bootstrap/Developer/Artifacts/Styx/20261108-gui-boundaries-c24/local-signing.json';
export function macLocalDevelopmentConfig(config){
 need(config&&Object.getPrototypeOf(config)===Object.prototype&&Object.keys(config).every(k=>['nativeRuntime','cuaBinary','sdkPath'].includes(k)),'local_development_config_required');
 const input=config.nativeRuntime;
 need(input&&Object.getPrototypeOf(input)===Object.prototype&&Object.keys(input).sort().join(',')==='expectedPublisher,payloadDir,publisherFile'&&input.expectedPublisher===PUBLISHER,'original_development_runtime_required');
 for(const p of [input.payloadDir,input.publisherFile,config.cuaBinary,...(config.sdkPath?[config.sdkPath]:[])])need(typeof p==='string'&&path.isAbsolute(p)&&path.normalize(p)===p&&!/[\x00-\x1f\x7f]/.test(p),'canonical_development_input_required');
 need(input.payloadDir.startsWith(PROJECT+'/')&&input.publisherFile.startsWith(PROJECT+'/'),'project_development_runtime_required');
 return {nativeRuntime:{...input},cuaBinary:config.cuaBinary,...(config.sdkPath?{sdkPath:config.sdkPath}:{})};
}
function physical(p,directory=false){
 need(fs.realpathSync(p)===p,'development_alias_refused');
 const st=fs.lstatSync(p);need(!st.isSymbolicLink()&&(directory?st.isDirectory():st.isFile())&&st.uid===process.getuid()&&!(st.mode&0o022),'owned_development_input_required');
 for(let parent=path.dirname(p);;parent=path.dirname(parent)){
  const s=fs.lstatSync(parent);need(s.isDirectory()&&!s.isSymbolicLink()&&(s.uid===0||s.uid===process.getuid())&&!(s.mode&0o022),'development_parent_refused');if(parent==='/')break;
 }
}
function privateDirectory(p){
 if(!fs.existsSync(p))fs.mkdirSync(p,{mode:0o700});physical(p,true);need(!(fs.statSync(p).mode&0o077),'private_development_directory_required');
}
let failedCommandCount=0;
const run=(file,args)=>{
 try{return execFileSync(file,args,{stdio:['ignore','pipe','pipe'],timeout:180000,maxBuffer:1024*1024});}
 catch(error){
  // Error bodies stay on-device; never turn a diagnostic failure into retry.
  const log=path.join(MAC_LOCAL_DEVELOPMENT.root,`command-error-${Date.now()}-${process.pid}-${failedCommandCount++}.private.log`);
  if(error.stderr!=null)fs.writeFileSync(log,error.stderr,{flag:'wx',mode:0o600});
  throw error;
 }
};
function noOpenFiles(p){
 const result=spawnSync('/usr/sbin/lsof',['-nP','+D',p],{encoding:'utf8',timeout:15000,maxBuffer:1024*1024});
 need(result.status===1&&!result.error&&!result.stdout&&!result.stderr,'development_app_still_in_use_or_unobservable');
}
function originalCode(p){run('/usr/bin/codesign',['--verify','--strict','-R',`=certificate leaf = H"${LEAF}"`,p]);}
export function macLocalDevelopmentInstalledApp(){
 // /Applications is a system-admin writable execution parent, not a private
 // profile/input directory. Use the original fixed path + code signature
 // boundary rather than applying the private-input ancestor mode policy.
 const app=MAC_LOCAL_DEVELOPMENT.runApp,parent=path.dirname(app);
 need(fs.realpathSync(parent)===parent&&fs.realpathSync(app)===app,'installed_development_alias_refused');
 const ps=fs.lstatSync(parent),st=fs.lstatSync(app);
 need(ps.isDirectory()&&!ps.isSymbolicLink()&&ps.uid===0&&!(ps.mode&0o002)&&st.isDirectory()&&!st.isSymbolicLink()&&(st.uid===0||st.uid===process.getuid())&&!(st.mode&0o022),'installed_development_path_refused');
 return app;
}
export function macLocalDevelopmentRunTarget(receipt,installedInventory){
 need(receipt?.schema===1&&receipt.kind==='local_production_ui_development'&&receipt.status==='PASS'&&receipt.app===MAC_LOCAL_DEVELOPMENT.app&&receipt.runApp===MAC_LOCAL_DEVELOPMENT.runApp&&receipt.build?.localDevelopment===true,'verified_development_build_receipt_required');
 need(Array.isArray(receipt.files)&&receipt.files.length>0&&JSON.stringify(receipt.files)===JSON.stringify(installedInventory),'installed_development_copy_mismatch');
 return MAC_LOCAL_DEVELOPMENT.runApp;
}
export function buildLocalMacDevelopment(config){
 need(process.platform==='darwin','native_macos_development_required');
 const input=macLocalDevelopmentConfig(config),{root,app,cache}=MAC_LOCAL_DEVELOPMENT;
 // The project/output parent is fixed and real; never make a new project or
 // repair existing ownership/permissions. The runner never touches /Applications.
 physical(PROJECT,true);physical(root,true);
 for(const p of [input.nativeRuntime.payloadDir,input.nativeRuntime.publisherFile,input.cuaBinary])physical(p,fs.statSync(p).isDirectory());
 const local=normalizeMacLocalSigning(JSON.parse(fs.readFileSync(SIGNING,'utf8')));
 need(local.identitySha1===LEAF&&local.certificateSha256===CERT,'original_development_identity_required');verifyMacLocalSigning(local);originalCode(input.cuaBinary);
 const verified=verifyNativeMacRuntime(input.nativeRuntime);
 need(verified.readerActualWait===true&&verified.readerExitCode===0,'development_runtime_verification_required');
 // No new Runtime is signed here, and no sealed nested byte is re-signed.
 for(const file of machOFiles(input.nativeRuntime.payloadDir))originalCode(file);
 const receiptFile=path.join(root,'development-app.json'),previous=path.join(root,'previous');
 need(!fs.existsSync(previous),'previous_development_attempt_requires_inspection');
 let old;
 if(fs.existsSync(app)){
  physical(receiptFile);need(!(fs.statSync(receiptFile).mode&0o077),'private_development_receipt_required');old=JSON.parse(fs.readFileSync(receiptFile,'utf8'));
  need(old.schema===1&&old.kind==='local_production_ui_development'&&old.status==='PASS'&&old.app===app&&JSON.stringify(old.files)===JSON.stringify(preparedPreviewInventory(app)),'existing_development_output_changed');
  originalCode(app);noOpenFiles(app);fs.mkdirSync(previous,{mode:0o700});fs.renameSync(app,path.join(previous,'Styx.app'));fs.renameSync(receiptFile,path.join(previous,'development-app.json'));
 }else need(!fs.existsSync(receiptFile),'orphan_development_receipt_requires_inspection');
 // Failed output and the prior signed bundle are deliberately retained; no
 // automatic retry/recovery or implicit Quit is performed by this runner.
 const built=buildMacApp({app,cuaBinary:input.cuaBinary,version:'0.4.0',nativeRuntime:true,localDevelopment:true,moduleCachePath:cache,...(input.sdkPath?{sdkPath:input.sdkPath}:{})});
 const resources=path.join(app,'Contents/Resources');
 const runtime=copyNativeMacRuntime(input.nativeRuntime,resources,process.arch);
 fs.writeFileSync(path.join(resources,'macos-runtime.json'),JSON.stringify({schema:1,nativeRuntime:runtime})+'\n',{flag:'wx',mode:0o600});
 privateDirectory(path.join(root,'state'));
 const native=path.join(resources,'native');
 for(const file of machOFiles(native))originalCode(file);
 const files=machOFiles(app).filter(file=>!file.startsWith(native+path.sep));
 for(const [command,args]of macLocalSigningPlan({app,localSigning:local,files,sealApp:true}))run(command,args);
 const after=verifyNativeMacRuntime({payloadDir:native,publisherFile:path.join(resources,'native-publisher.pem'),expectedPublisher:PUBLISHER});
 need(after.manifestSha256===verified.manifestSha256&&after.cliSha256===verified.cliSha256&&after.signatureSha256===verified.signatureSha256,'development_sealed_runtime_changed');
 const receipt={schema:1,kind:'local_production_ui_development',status:'PASS',app,runApp:MAC_LOCAL_DEVELOPMENT.runApp,profile:path.join(root,'state/NativeRustHost-v1/profile'),build:built,
  runtime,sourceRevision:run('/usr/bin/git',['-C',path.join(PROJECT,'source'),'rev-parse','HEAD']).toString().trim(),runtimeSourceRevision:after.report.source_revision,
  sourceDirty:run('/usr/bin/git',['-C',path.join(PROJECT,'source'),'status','--porcelain=v1']).length>0,
  files:preparedPreviewInventory(app),notarization:'NOT RUN',dmg:'NOT RUN',installation:'NOT RUN',guiLaunch:'NOT RUN',computerSource:'ORIGINAL_INSTALLED_PATH_AFTER_VERIFIED_DEPLOYMENT'};
 fs.writeFileSync(receiptFile,JSON.stringify(receipt,null,2)+'\n',{flag:'wx',mode:0o600});
 if(old){
  const prior=path.join(previous,'Styx.app');need(JSON.stringify(old.files)===JSON.stringify(preparedPreviewInventory(prior)),'previous_development_output_changed');noOpenFiles(prior);
  fs.rmSync(prior,{recursive:true});fs.unlinkSync(path.join(previous,'development-app.json'));fs.rmdirSync(previous);
 }
 return receipt;
}
// Deployment is deliberately separate: the GUI owner must normal-Quit and
// observe all original exits, then copy/verify the exact built App. No DMG and
// no automatic process control, installer, role change or profile migration.
export function launchInstalledMacDevelopment(){
 need(process.platform==='darwin','native_macos_development_required');
 const {root,app,runApp}=MAC_LOCAL_DEVELOPMENT,receiptFile=path.join(root,'development-app.json');
 physical(root,true);physical(receiptFile);need(!(fs.statSync(receiptFile).mode&0o077),'private_development_receipt_required');
 const receipt=JSON.parse(fs.readFileSync(receiptFile,'utf8'));
 physical(app,true);need(macLocalDevelopmentInstalledApp()===runApp,'fixed_installed_development_app_required');
 macLocalDevelopmentRunTarget(receipt,preparedPreviewInventory(runApp));
 need(JSON.stringify(receipt.files)===JSON.stringify(preparedPreviewInventory(app)),'development_build_changed');
 noOpenFiles(runApp);
 run('/usr/bin/codesign',['--verify','--deep','--strict','-R',`=identifier "app.styx.host" and certificate leaf = H"${LEAF}"`,runApp]);
 const resources=path.join(runApp,'Contents/Resources');
 const verified=verifyNativeMacRuntime({payloadDir:path.join(resources,'native'),publisherFile:path.join(resources,'native-publisher.pem'),expectedPublisher:PUBLISHER});
 need(verified.manifestSha256===receipt.runtime.manifestSha256&&verified.cliSha256===receipt.runtime.cliSha256,'installed_development_runtime_changed');
 const stderr=path.join(root,`app-stderr-${Date.now()}-${process.pid}.private.log`);
 const fd=fs.openSync(stderr,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL,0o600);fs.closeSync(fd);
 run('/usr/bin/open',['-a',runApp,'--stderr',stderr,'--args','--native-diagnostics']);
 return {status:'LAUNCH_DISPATCHED_NOT_READY_PROOF',app:runApp,profile:receipt.profile,stderr};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{
  need(process.argv.length===3,'usage_dev_macos_absolute_build_config_or_launch_installed');
  if(process.argv[2]==='--launch-installed')console.log(JSON.stringify(launchInstalledMacDevelopment()));
  else{
   const file=process.argv[2];need(path.isAbsolute(file)&&path.normalize(file)===file,'absolute_development_config_required');physical(file);
   const receipt=buildLocalMacDevelopment(JSON.parse(fs.readFileSync(file,'utf8')));
   console.log(JSON.stringify({status:receipt.status,buildApp:receipt.app,runApp:receipt.runApp,profile:receipt.profile,runtimeManifest:receipt.runtime.manifestSha256,guiLaunch:receipt.guiLaunch}));
  }
 }catch(error){console.error(/^[a-z0-9_]+$/.test(error.message)?error.message:'local_macos_development_failed_preserve_output');process.exitCode=2;}
}
