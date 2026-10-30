// Native self-contained precompiled developer preview. No Apple Developer account,
// notarization, existing application installation or private-key distribution.
import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {MAC_BUNDLE_ID,buildMacApp,macNativeSwiftSources,macLocalSigningPlan,normalizeMacLocalSigning,publicMacLocalSigning,verifyMacLocalSigning} from './build-macos-app.mjs';
import {isSparkleFrameworkLink} from './macos/platform-update/sparkle-build.mjs';
import {requirePrivateFile} from './private-storage.mjs';
import {verifyNativeMacRuntime,copyNativeMacRuntime,authenticateNativeMacRuntimeEnvelope} from './build-macos-native-runtime.mjs';
const ROOT=fileURLToPath(new URL('../',import.meta.url));
const assert=(x,code)=>{if(!x)throw Error(code)};
const sha=p=>createHash('sha256').update(fs.readFileSync(p)).digest('hex');
const ABS=p=>typeof p==='string'&&path.isAbsolute(p)&&path.normalize(p)===p;
function tree(source,destination,{skip=()=>false}={}){
 const st=fs.lstatSync(source);assert(!st.isSymbolicLink(),'distribution_symlink_forbidden');
 if(st.isDirectory()){fs.mkdirSync(destination,{recursive:true});for(const name of fs.readdirSync(source).sort())if(!skip(name))tree(path.join(source,name),path.join(destination,name),{skip});}
 else{assert(st.isFile(),'distribution_regular_files_required');fs.mkdirSync(path.dirname(destination),{recursive:true});if(fs.existsSync(destination))assert(sha(source)===sha(destination),'distribution_copy_collision');else fs.copyFileSync(source,destination,fs.constants.COPYFILE_EXCL);}
}
function scanPrivateMaterial(root,{allowSparkle=false}={}){
 function walk(dir){for(const e of fs.readdirSync(dir,{withFileTypes:true})){const file=path.join(dir,e.name);if(e.isSymbolicLink()&&allowSparkle&&isSparkleFrameworkLink(root,file))continue;assert(!e.isSymbolicLink(),'distribution_symlink_forbidden');if(e.isDirectory())walk(file);else{assert(!['admin.token','model.token','device.token','identity.pem','publisher-private.pem'].includes(e.name),'private_material_filename_in_distribution');const bytes=fs.readFileSync(file);assert(!/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\r\n]/.test(bytes.toString('utf8')),'private_key_in_distribution');}}}walk(root);
}
export function machOFiles(root,{preserveSparkle=false}={}){
 const files=[];
 function walk(dir){for(const e of fs.readdirSync(dir,{withFileTypes:true})){const file=path.join(dir,e.name);if(preserveSparkle&&file===path.join(root,'Contents/Frameworks/Sparkle.framework'))continue;assert(!e.isSymbolicLink(),'distribution_symlink_forbidden');if(e.isDirectory())walk(file);else{assert(e.isFile(),'distribution_regular_files_required');const fd=fs.openSync(file,'r'),head=Buffer.alloc(8);let n;try{n=fs.readSync(fd,head,0,8,0)}finally{fs.closeSync(fd)}if(n>=4&&['feedface','cefaedfe','feedfacf','cffaedfe','cafebabe','bebafeca','cafebabf','bfbafeca'].includes(head.subarray(0,4).toString('hex')))files.push(file);}}}
 walk(root);return files.sort();
}
export function previewSigningReceipt(localSigning){
 return {signing:localSigning===undefined?'adhoc_preview':'local_certificate_preview',notarization:'NOT RUN',external_publisher_identity:'NOT ESTABLISHED',private_key_in_artifact:false,
  ...(localSigning===undefined?{}:{local_signing:publicMacLocalSigning(localSigning)})};
}
export function buildMacPreview(config){
 assert(config?.nativeRuntime!==undefined,'native_runtime_required_for_product_app');
 return prepareNativeMacPreview(config);
}
export function executeMacPreviewSigningPlan(steps,{run=execFileSync}={}){
 assert(Array.isArray(steps)&&steps.every(step=>Array.isArray(step)&&step.length===2&&step[0]==='/usr/bin/codesign'&&Array.isArray(step[1])&&step[1].every(arg=>typeof arg==='string')),'invalid_preview_signing_plan');
 for(const [command,args]of steps)run(command,args,{stdio:'pipe',timeout:30000});
}

export function preparedPreviewInventory(app){
 assert(ABS(app)&&fs.realpathSync(app)===app&&fs.lstatSync(app).isDirectory(),'canonical_prepared_app_required');
 const files=[];
 function walk(dir,relative=''){for(const name of fs.readdirSync(dir).sort()){
  const file=path.join(dir,name),rel=relative?relative+'/'+name:name,st=fs.lstatSync(file);
  assert(!st.isSymbolicLink(),'distribution_symlink_forbidden');
  if(st.isDirectory()){files.push({path:rel,kind:'directory'});walk(file,rel)}
  else{assert(st.isFile(),'distribution_regular_files_required');files.push({path:rel,kind:'file',size:st.size,executable:!!(st.mode&0o111),sha256:sha(file)})}
 }}walk(app);return files;
}
// Native payload branch: no Node management, old worker manifest, publisher
// private key, legacy updater data or installer is adopted. Prepared output is
// unsigned, and cannot satisfy ProductOwnedCore's installed-App requirement.
export function prepareNativeMacPreview(config){
 assert(config&&Object.keys(config).every(k=>['destination','version','buildNumber','sourceRevision','cuaBinary','sdkPath','moduleCachePath','nativeRuntime','prepareOnly'].includes(k)),'invalid_native_app_configuration');
 const {destination,version,buildNumber,sourceRevision,cuaBinary,sdkPath,moduleCachePath,nativeRuntime,prepareOnly}=config;
 assert(prepareOnly===true&&process.platform==='darwin','native_app_prepare_only_required');
 assert(ABS(destination)&&!fs.existsSync(destination)&&/^[a-f0-9]{40}$/.test(sourceRevision??''),'fresh_native_app_destination_required');
 assert(nativeRuntime.expectedPublisher==='cb06529011b4c35ffc79f76440beeb88c6e3615e60d993d1485b5be45b307819','original_native_app_publisher_required');
 const observedSources=macNativeSwiftSources(),sourceFiles=Object.fromEntries([observedSources.source,...observedSources.additionalSources,path.join(ROOT,'host/macos/StyxUpdater.swift'),path.join(ROOT,'host/macos/render-brand-icons.swift')].map(file=>[path.relative(ROOT,file).split(path.sep).join('/'),sha(file)]));
 const verified=verifyNativeMacRuntime(nativeRuntime,process.arch);
 assert(sourceRevision===verified.report.source_revision,'native_app_source_revision_mismatch');
 fs.mkdirSync(destination,{mode:0o700});const app=path.join(destination,'image-root/Styx.app');
 const appBuild=buildMacApp({app,nativeRuntime:true,cuaBinary,version,buildNumber,sdkPath,moduleCachePath:moduleCachePath??path.join(destination,'swift-module-cache')});
 const resources=path.join(app,'Contents/Resources');
 const metadata={schema:1,nativeRuntime:copyNativeMacRuntime(nativeRuntime,resources,process.arch)};
 fs.writeFileSync(path.join(resources,'macos-runtime.json'),JSON.stringify(metadata,null,2)+'\n',{flag:'wx',mode:0o600});
 scanPrivateMaterial(app);
 const receipt={schema:1,kind:'prepared_native_rust_app',delivery:'NOT FINALIZED',sourceRevision,version,buildNumber,arch:process.arch,appBuild,
  sourceFiles,nativeRuntime:metadata.nativeRuntime,nativeSignatureSha256:verified.signatureSha256,runtimeSourceRevision:verified.report.source_revision,
  nativeUpdater:'native_handoff_blocked_no_legacy_core',readerActualWait:true,readerExitCode:0,files:preparedPreviewInventory(app),signing:'NOT RUN',native_gui_acceptance:'NOT RUN',tcc_attribution:'NOT RUN'};
 assert(Object.entries(sourceFiles).every(([name,digest])=>sha(path.join(ROOT,...name.split('/')))===digest),'native_app_source_changed');
 fs.writeFileSync(path.join(destination,'prepared-native-app.json'),JSON.stringify(receipt,null,2)+'\n',{flag:'wx',mode:0o600});return receipt;
}
// Artifact creation is after the App and C08 seals. No code is signed or
// changed here; mounting is verification, never an installation or App launch.
export function assertNativeMacAppInventory(app,expected){
 assert(JSON.stringify(preparedPreviewInventory(app))===JSON.stringify(expected),'native_archive_app_inventory_changed');
}
// A nonzero/timeout attach can still have mounted the image. Consult the
// platform's structured inventory before cleaning only our exact fresh mount.
export function withNativeMacDmgMount({image,mount,verification,run},inspect){
 const initial=fs.lstatSync(image,{bigint:true});
 assert(initial.isFile()&&!initial.isSymbolicLink(),'native_dmg_regular_image_required');
 const imageSha=sha(image);
 const parent=fs.lstatSync(mount,{bigint:true});
 assert(parent.isDirectory()&&!parent.isSymbolicLink()&&fs.readdirSync(mount).length===0,'native_dmg_fresh_mountpoint_required');
 verification.mountpoint=mount;verification.detachAttempted=false;verification.detached=false;
 let attached=false;
 try{
  run('/usr/bin/hdiutil',['attach','-readonly','-nobrowse','-mountpoint',mount,image],90000);attached=true;
  inspect();
 }finally{
  if(!attached){
   verification.failedAttachObservation='unknown';
   try{
    const plist=run('/usr/bin/hdiutil',['info','-plist'],30000);
    const info=JSON.parse(run('/usr/bin/plutil',['-convert','json','-o','-','-'],30000,plist));
    assert(info&&Array.isArray(info.images)&&info.images.length<=1024,'native_dmg_info_invalid');
    const matches=[];
    for(const entry of info.images){
     assert(entry&&typeof entry==='object'&&Array.isArray(entry['system-entities']),'native_dmg_info_invalid');
     for(const entity of entry['system-entities']){
      assert(entity&&typeof entity==='object','native_dmg_info_invalid');
      if(entity['mount-point']===mount)matches.push(entry);
     }
    }
    const current=fs.lstatSync(image,{bigint:true});
    assert(['dev','ino','size','mtimeNs','ctimeNs'].every(k=>current[k]===initial[k])&&sha(image)===imageSha,'native_dmg_image_changed');
    if(matches.length===1&&matches[0]['image-path']===image){
     verification.failedAttachObservation='exact_owned_image_mounted';attached=true;
    }else if(matches.length===0){
     const currentMount=fs.lstatSync(mount,{bigint:true});
     assert(currentMount.dev===parent.dev&&currentMount.ino===parent.ino&&fs.readdirSync(mount).length===0,'native_dmg_mountpoint_changed');
     verification.failedAttachObservation='not_mounted';
    }
   }catch{
    // Unknown is retained, not permission to detach some other image or force.
    verification.failedAttachObservation='unknown';
   }
  }
  if(attached){
   verification.detachAttempted=true;
   run('/usr/bin/hdiutil',['detach',mount],90000);
   verification.detached=true;
   fs.rmdirSync(mount);
  }
 }
}
function nativeMacArtifacts({destination,app,metadata,expectedPublisherSha256,createDmg=true}){
 assert(typeof createDmg==='boolean','invalid_native_create_dmg');
 const files=preparedPreviewInventory(app),observations=[];
 const verification={schema:1,status:'FAIL',readonlyMount:true,appLaunched:false,observations};
 const run=(command,args,timeout=30000,input)=>{
  const fact={command:[command,...args],actualWait:false,exitCode:null};observations.push(fact);
  try{const output=execFileSync(command,args,{stdio:'pipe',timeout,input,maxBuffer:1048576});fact.actualWait=true;fact.exitCode=0;return output;}
  catch(error){fact.actualWait=Number.isInteger(error.status);fact.exitCode=error.status??null;fact.signal=error.signal??null;throw error;}
 };
 const inputFor=target=>({payloadDir:path.join(target,'Contents/Resources/native'),publisherFile:path.join(target,'Contents/Resources/native-publisher.pem'),expectedPublisher:expectedPublisherSha256});
 const original=authenticateNativeMacRuntimeEnvelope(inputFor(app),metadata.arch);
 const check=target=>{
  assertNativeMacAppInventory(target,files);
  run('/usr/bin/codesign',['--verify','--deep','--strict',target]);
  run('/usr/bin/codesign',['--verify','--strict','-R',`=identifier "${MAC_BUNDLE_ID}" and certificate leaf = H"cb50cee601419f28b43756f4fc8aefdbf60abae2"`,target]);
  const copied=authenticateNativeMacRuntimeEnvelope(inputFor(target),metadata.arch);
  assert(copied.manifestSha256===original.manifestSha256&&copied.signatureSha256===original.signatureSha256&&copied.cliSha256===original.cliSha256&&copied.publisherSha256===original.publisherSha256,'native_archive_c08_changed');
  assertNativeMacAppInventory(target,files);
 };
 try{
  check(app);
  const zip='Styx-'+metadata.version+'-native-macos-'+metadata.arch+'.zip';
  run('/usr/bin/ditto',['-c','-k','--keepParent',app,path.join(destination,zip)],180000);
  run('/usr/bin/unzip',['-tq',path.join(destination,zip)],180000);
  const names=[zip];let primaryArtifact=zip;
  if(createDmg){
   const image=path.dirname(app);
   fs.symlinkSync('/Applications',path.join(image,'Applications'));
   fs.writeFileSync(path.join(image,'READ-ME.txt'),'Drag Styx.app to Applications, then open it from Applications.\nThis development build uses the original local signing identity and is not notarized.\nPKG is only for explicit advanced persistent-service installation or repair.\n',{flag:'wx',mode:0o644});
   const dmg='Styx-'+metadata.version+'-native-macos-'+metadata.arch+'.dmg';
   run('/usr/bin/hdiutil',['create','-volname','Styx','-srcfolder',image,'-format','UDZO',path.join(destination,dmg)],300000);
   run('/usr/bin/hdiutil',['verify',path.join(destination,dmg)],180000);
   const mount=fs.mkdtempSync(path.join(destination,'verify-native-image-'));
   withNativeMacDmgMount({image:path.join(destination,dmg),mount,verification,run},()=>{
    const link=path.join(mount,'Applications');assert(fs.lstatSync(link).isSymbolicLink()&&fs.readlinkSync(link)==='/Applications','native_dmg_applications_link_changed');
    assert(fs.readFileSync(path.join(mount,'READ-ME.txt'),'utf8')===fs.readFileSync(path.join(image,'READ-ME.txt'),'utf8'),'native_dmg_instructions_changed');
    check(path.join(mount,'Styx.app'));
   });
   names.push(dmg);primaryArtifact=dmg;
  }
  assertNativeMacAppInventory(app,files);
  verification.status='PASS';
  return {primaryArtifact,installMethod:createDmg?'drag_to_applications':'internal_transport_only',artifacts:names.map(name=>({name,sha256:sha(path.join(destination,name)),bytes:fs.statSync(path.join(destination,name)).size})),archiveVerification:verification};
 }finally{
  fs.writeFileSync(path.join(destination,'native-archive-verification.json'),JSON.stringify(verification,null,2)+'\n',{flag:'wx',mode:0o600});
 }
}
export function finalizeNativeMacPreview(config){
 assert(process.platform==='darwin','native_macos_signing_required');
 assert(config&&Object.keys(config).every(k=>['nativePreparedSource','preparedReceiptSha256','destination','localSigning','expectedPublisherSha256','crossArchSignOnly','createDmg'].includes(k)),'invalid_native_app_finalization');
 const {nativePreparedSource,preparedReceiptSha256,destination,localSigning,expectedPublisherSha256,crossArchSignOnly=false,createDmg=true}=config;
 assert(typeof crossArchSignOnly==='boolean'&&typeof createDmg==='boolean','invalid_cross_arch_sign_only');
 assert(ABS(nativePreparedSource)&&ABS(destination)&&!fs.existsSync(destination)&&/^[a-f0-9]{64}$/.test(preparedReceiptSha256??'')&&/^[a-f0-9]{64}$/.test(expectedPublisherSha256??''),'native_app_finalization_inputs_required');
 const relative=path.relative(nativePreparedSource,destination),reverse=path.relative(destination,nativePreparedSource),outside=p=>p==='..'||p.startsWith('..'+path.sep)||path.isAbsolute(p);
 assert(outside(relative)&&outside(reverse),'native_app_destination_overlap');
 const local=normalizeMacLocalSigning(localSigning);
 // This bridge preserves the exact retained rc12 identity; no replacement
 // signing certificate or new publisher is inferred from candidate bytes.
 assert(local.identitySha1==='cb50cee601419f28b43756f4fc8aefdbf60abae2'&&local.certificateSha256==='90792ed11f23a00f0107450dbc184f992016569ca188454cfa286fe0022c2c1e'&&expectedPublisherSha256==='cb06529011b4c35ffc79f76440beeb88c6e3615e60d993d1485b5be45b307819','original_native_app_identity_required');
 const receiptPath=path.join(nativePreparedSource,'prepared-native-app.json');assert(sha(receiptPath)===preparedReceiptSha256,'prepared_native_app_receipt_changed');
 const metadata=JSON.parse(fs.readFileSync(receiptPath,'utf8')),originalApp=path.join(nativePreparedSource,'image-root/Styx.app');
 assert(metadata.schema===1&&metadata.kind==='prepared_native_rust_app'&&metadata.delivery==='NOT FINALIZED'&&(crossArchSignOnly?metadata.arch==='x64'&&process.arch==='arm64':metadata.arch===process.arch)&&metadata.readerActualWait===true&&metadata.readerExitCode===0&&metadata.nativeRuntime.publisherSpkiSha256===expectedPublisherSha256&&JSON.stringify(preparedPreviewInventory(originalApp))===JSON.stringify(metadata.files),'prepared_native_app_changed');
 const inputFor=app=>({payloadDir:path.join(app,'Contents/Resources/native'),publisherFile:path.join(app,'Contents/Resources/native-publisher.pem'),expectedPublisher:expectedPublisherSha256});
 const inspect=crossArchSignOnly?authenticateNativeMacRuntimeEnvelope:verifyNativeMacRuntime;
 const protectedNative=app=>preparedPreviewInventory(app).filter(row=>row.path==='Contents/Resources/native'||row.path.startsWith('Contents/Resources/native/')||row.path==='Contents/Resources/native-publisher.pem'||row.path==='Contents/Resources/macos-runtime.json');
 const nativeInventory=protectedNative(originalApp);
 const original=inspect(inputFor(originalApp),metadata.arch);
 assert(original.manifestSha256===metadata.nativeRuntime.manifestSha256&&original.signatureSha256===metadata.nativeSignatureSha256,'prepared_native_manifest_changed');
 fs.mkdirSync(destination,{mode:0o700});const app=path.join(destination,'image-root/Styx.app');tree(originalApp,app);
 // Historical tree() does not retain file modes; restore exact prepared mode
 // metadata explicitly below (snapshot contains execute bits, no public chmod).
 fs.chmodSync(path.join(app,'Contents/Resources'),0o700);
 for(const row of metadata.files){const file=path.join(app,...row.path.split('/'));if(row.kind==='directory')fs.chmodSync(file,row.path.startsWith('Contents/Resources')?0o700:0o755);else fs.chmodSync(file,row.executable?0o700:0o600);}
 assert(JSON.stringify(preparedPreviewInventory(app))===JSON.stringify(metadata.files),'prepared_native_copy_changed');
 const resources=path.join(app,'Contents/Resources'),nativeRoot=path.join(resources,'native');
 verifyMacLocalSigning(localSigning);
 fs.writeFileSync(path.join(resources,'local-signing.json'),JSON.stringify(publicMacLocalSigning(localSigning),null,2)+'\n',{flag:'wx',mode:0o600});
 const native=machOFiles(app),sealed=native.filter(file=>file.startsWith(nativeRoot+path.sep)),unsigned=native.filter(file=>!file.startsWith(nativeRoot+path.sep));
 // A publisher-sealed runtime is immutable. All nested Mach-O must already have
 // the original platform signature; reject instead of codesigning sealed bytes.
 for(const file of sealed)execFileSync('/usr/bin/codesign',['--verify','--strict','-R',`=certificate leaf = H"${local.identitySha1}"`,file],{stdio:'pipe',timeout:30000});
 executeMacPreviewSigningPlan(macLocalSigningPlan({app,localSigning,files:unsigned,sealApp:false}));
 const copied=inspect(inputFor(app),metadata.arch);
 assert(copied.manifestSha256===original.manifestSha256&&copied.signatureSha256===original.signatureSha256&&copied.cliSha256===original.cliSha256,'sealed_native_payload_changed');
 scanPrivateMaterial(app);executeMacPreviewSigningPlan(macLocalSigningPlan({app,localSigning,files:[],sealApp:true}));
 const after=inspect(inputFor(app),metadata.arch);
 assert(after.manifestSha256===original.manifestSha256&&after.signatureSha256===original.signatureSha256,'sealed_native_payload_changed');
 assert(JSON.stringify(protectedNative(app))===JSON.stringify(nativeInventory),'sealed_native_inventory_changed');
 if(crossArchSignOnly){
  // No foreign CLI executes on this machine. This receipt is deliberately
  // pending and cannot be consumed as a final native App delivery.
  const pending={schema:1,kind:'signed_native_rust_app_pending_native_verification',status:'SIGNED_PENDING_NATIVE_VERIFICATION',delivery:'NOT FINALIZED',
   sourceRevision:metadata.sourceRevision,runtimeSourceRevision:metadata.runtimeSourceRevision,sourceFiles:metadata.sourceFiles,
   arch:metadata.arch,version:metadata.version,buildNumber:metadata.buildNumber,compiler:metadata.appBuild.compiler,
   nativeRuntime:metadata.nativeRuntime,nativeSignatureSha256:after.signatureSha256,preparedReceiptSha256,
   ...previewSigningReceipt(localSigning),files:preparedPreviewInventory(app),
   sealedRuntimeCodesign:'verified_only_never_resigned',coreManagementRuntime:'owned_rust_stdio_no_node_core',
   nativeReaderActualWait:false,nativeReaderExitCode:null,native_ui_acceptance:'NOT RUN',tcc_attribution:'NOT RUN',installation:'NOT RUN'};
  fs.writeFileSync(path.join(destination,'signed-pending-app.json'),JSON.stringify(pending,null,2)+'\n',{flag:'wx',mode:0o600});return pending;
 }
 const archives=nativeMacArtifacts({destination,app,metadata,expectedPublisherSha256,createDmg});
 const receipt={schema:1,kind:'native_rust_local_certificate_preview',app,sourceRevision:metadata.sourceRevision,runtimeSourceRevision:metadata.runtimeSourceRevision,
  sourceFiles:metadata.sourceFiles,nativeRuntime:metadata.nativeRuntime,nativeSignatureSha256:after.signatureSha256,...previewSigningReceipt(localSigning),compiler:metadata.appBuild.compiler,
  sealedRuntimeCodesign:'verified_only_never_resigned',coreManagementRuntime:'owned_rust_stdio_no_node_core',nativeReaderActualWait:true,nativeReaderExitCode:0,
  ...archives,native_ui_acceptance:'NOT RUN',tcc_attribution:'NOT RUN',installation:'NOT RUN'};
 fs.writeFileSync(path.join(destination,'native-app-receipt.json'),JSON.stringify(receipt,null,2)+'\n',{flag:'wx',mode:0o600});return receipt;
}
// Native completion is read/verify/copy/package only. It never signs or opens
// a private key, and never treats a cross-machine pending receipt as readiness.
export function completeNativeMacPreview(config){
 assert(process.platform==='darwin','native_macos_completion_required');
 assert(config&&Object.keys(config).every(k=>['signedPendingSource','pendingReceiptSha256','destination','expectedPublisherSha256','createDmg'].includes(k)),'invalid_native_app_completion');
 const {signedPendingSource,pendingReceiptSha256,destination,expectedPublisherSha256,createDmg=true}=config;
 assert(typeof createDmg==='boolean','invalid_native_create_dmg');
 assert(ABS(signedPendingSource)&&ABS(destination)&&!fs.existsSync(destination)&&/^[a-f0-9]{64}$/.test(pendingReceiptSha256??'')&&expectedPublisherSha256==='cb06529011b4c35ffc79f76440beeb88c6e3615e60d993d1485b5be45b307819','native_app_completion_inputs_required');
 const relative=path.relative(signedPendingSource,destination),reverse=path.relative(destination,signedPendingSource),outside=p=>p==='..'||p.startsWith('..'+path.sep)||path.isAbsolute(p);
 assert(outside(relative)&&outside(reverse),'native_app_destination_overlap');
 const receiptPath=path.join(signedPendingSource,'signed-pending-app.json');requirePrivateFile(receiptPath);assert(sha(receiptPath)===pendingReceiptSha256,'signed_pending_receipt_changed');
 const metadata=JSON.parse(fs.readFileSync(receiptPath,'utf8')),originalApp=path.join(signedPendingSource,'image-root/Styx.app');
 assert(metadata.schema===1&&metadata.kind==='signed_native_rust_app_pending_native_verification'&&metadata.status==='SIGNED_PENDING_NATIVE_VERIFICATION'&&metadata.delivery==='NOT FINALIZED'&&metadata.arch===process.arch&&metadata.nativeReaderActualWait===false&&metadata.nativeReaderExitCode===null&&metadata.nativeRuntime.publisherSpkiSha256===expectedPublisherSha256&&JSON.stringify(preparedPreviewInventory(originalApp))===JSON.stringify(metadata.files),'signed_pending_app_changed');
 const local=metadata.local_signing;
 assert(local?.schema===1&&local.certificateSha1==='cb50cee601419f28b43756f4fc8aefdbf60abae2'&&local.certificateSha256==='90792ed11f23a00f0107450dbc184f992016569ca188454cfa286fe0022c2c1e','original_native_app_identity_required');
 const inputFor=app=>({payloadDir:path.join(app,'Contents/Resources/native'),publisherFile:path.join(app,'Contents/Resources/native-publisher.pem'),expectedPublisher:expectedPublisherSha256});
 const requirement=`=identifier "${MAC_BUNDLE_ID}" and certificate leaf = H"${local.certificateSha1}"`;
 const observations=[];
 const run=(command,args,timeout=30000)=>{execFileSync(command,args,{stdio:'pipe',timeout});observations.push({command:[command,...args],actualWait:true,exitCode:0});};
 // Verify the original App before executing even its authenticated reader.
 run('/usr/bin/codesign',['--verify','--deep','--strict',originalApp]);
 run('/usr/bin/codesign',['--verify','--strict','-R',requirement,originalApp]);
 for(const file of machOFiles(originalApp))run('/usr/bin/codesign',['--verify','--strict','-R',`=certificate leaf = H"${local.certificateSha1}"`,file]);
 fs.mkdirSync(destination,{mode:0o700});
 const prefix=path.join(destination,'app-signing-certificate-');run('/usr/bin/codesign',['-d','--extract-certificates='+prefix,originalApp]);
 const certificate=prefix+'0',st=fs.lstatSync(certificate);
 assert(st.isFile()&&!st.isSymbolicLink()&&st.nlink===1&&st.size<=65536&&st.uid===process.getuid()&&!(st.mode&0o022)&&sha(certificate)===local.certificateSha256,'original_native_app_certificate_mismatch');
 const original=verifyNativeMacRuntime(inputFor(originalApp),metadata.arch);
 assert(original.manifestSha256===metadata.nativeRuntime.manifestSha256&&original.signatureSha256===metadata.nativeSignatureSha256&&original.cliSha256===metadata.nativeRuntime.cliSha256&&original.report.source_revision===metadata.runtimeSourceRevision&&original.report.source_revision===metadata.sourceRevision,'signed_pending_native_binding_changed');
 const app=path.join(destination,'image-root/Styx.app');tree(originalApp,app);fs.chmodSync(path.join(app,'Contents/Resources'),0o700);
 for(const row of metadata.files){const file=path.join(app,...row.path.split('/'));if(row.kind==='directory')fs.chmodSync(file,row.path.startsWith('Contents/Resources')?0o700:0o755);else fs.chmodSync(file,row.executable?0o700:0o600);}
 assert(JSON.stringify(preparedPreviewInventory(app))===JSON.stringify(metadata.files),'signed_native_copy_changed');
 run('/usr/bin/codesign',['--verify','--deep','--strict',app]);
 run('/usr/bin/codesign',['--verify','--strict','-R',requirement,app]);
 const copied=verifyNativeMacRuntime(inputFor(app),metadata.arch);
 assert(copied.manifestSha256===original.manifestSha256&&copied.signatureSha256===original.signatureSha256&&copied.cliSha256===original.cliSha256,'sealed_native_payload_changed');
 scanPrivateMaterial(app);
 const archives=nativeMacArtifacts({destination,app,metadata,expectedPublisherSha256,createDmg});
 assert(sha(receiptPath)===pendingReceiptSha256&&JSON.stringify(preparedPreviewInventory(originalApp))===JSON.stringify(metadata.files)&&JSON.stringify(preparedPreviewInventory(app))===JSON.stringify(metadata.files),'signed_native_inputs_changed');
 const receipt={schema:1,kind:'native_rust_local_certificate_preview',app,sourceRevision:metadata.sourceRevision,runtimeSourceRevision:metadata.runtimeSourceRevision,
  sourceFiles:metadata.sourceFiles,nativeRuntime:metadata.nativeRuntime,nativeSignatureSha256:copied.signatureSha256,
  signing:'local_certificate_preview',notarization:'NOT RUN',local_signing:local,private_key_in_artifact:false,compiler:metadata.compiler,
  completion:'native_architecture_verification_after_original_cross_signing',signedPendingReceiptSha256:pendingReceiptSha256,
  sealedRuntimeCodesign:'verified_only_never_resigned',coreManagementRuntime:'owned_rust_stdio_no_node_core',nativeReaderActualWait:true,nativeReaderExitCode:0,
  nativeVerification:observations,...archives,native_ui_acceptance:'NOT RUN',tcc_attribution:'NOT RUN',installation:'NOT RUN'};
 fs.writeFileSync(path.join(destination,'native-app-receipt.json'),JSON.stringify(receipt,null,2)+'\n',{flag:'wx',mode:0o600});return receipt;
}
if(process.argv[1]&&fs.realpathSync(process.argv[1])===fs.realpathSync(fileURLToPath(import.meta.url))){
 try{assert(process.argv.length===3&&ABS(process.argv[2]),'usage_absolute_preview_config');const config=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));console.log(JSON.stringify(config.signedPendingSource?completeNativeMacPreview(config):config.nativePreparedSource?finalizeNativeMacPreview(config):buildMacPreview(config)));}
 catch{console.error('Styx developer preview build failed; preserve incomplete output for inspection.');process.exitCode=2;}
}
