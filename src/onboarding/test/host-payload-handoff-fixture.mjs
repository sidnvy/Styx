import fs from 'node:fs';import os from 'node:os';import path from 'node:path';import {createHash,generateKeyPairSync,sign} from 'node:crypto';import {stageSignedRelease,activateRelease,refreshVerifiedBootstrap} from '../../host/installer.mjs';
const sha=x=>createHash('sha256').update(x).digest('hex');
const key=()=>generateKeyPairSync('ed25519');
const pem=k=>k.publicKey.export({type:'spki',format:'pem'});
const pin=k=>sha(k.publicKey.export({type:'spki',format:'der'}));
const put=(p,data,mode=0o600)=>{fs.mkdirSync(path.dirname(p),{recursive:true,mode:0o700});fs.writeFileSync(p,typeof data==='object'&&!Buffer.isBuffer(data)?JSON.stringify(data,null,2)+'\n':data,{mode});};
const json=p=>JSON.parse(fs.readFileSync(p));
const opts={platform:'darwin',arch:process.arch};
export function migrationFixture(t,{cross=false,platform='darwin'}={}){
 const opts={platform,arch:process.arch},suffix=platform==='win32'?'.exe':'';
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'styx-payload-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const stateDir=path.join(dir,'deployment'),base=path.join(dir,'host'),root=path.join(base,'install'),app=path.join(dir,'Styx.app'),oldKey=key(),nextKey=cross?key():oldKey;
 function bundle(directory,version,k){
  const names=['private-storage','installer','launch','connect','enroll','setup-native','doctor','macos-launchagent','macos-native-launcher','linux-service'].map(n=>'host/'+n+'.mjs').concat(['host/windows-task.ps1',...['node','codex','cua-driver'].map(n=>'bin/'+n+suffix)]);
  const files=names.map(name=>{const content=Buffer.from(version+' '+name+'\n');put(path.join(directory,name),content,name.startsWith('bin/')?0o700:0o600);return {path:name,sha256:sha(content),size:content.length,executable:name.startsWith('bin/')};});
  const raw=Buffer.from(JSON.stringify({schema:1,version,platform,arch:process.arch,files})+'\n');put(path.join(directory,'manifest.json'),raw);put(path.join(directory,'manifest.sig'),sign(null,raw,k.privateKey).toString('base64url')+'\n');return directory;
 }
 const old=bundle(path.join(dir,'old'),'0.1.0-old',oldKey),candidate=bundle(cross?path.join(app,'Contents/Resources/host-bundle'):path.join(dir,'candidate'),'0.2.0-next',nextKey);
 fs.mkdirSync(base,{mode:0o700});stageSignedRelease({sourceDir:old,installRoot:root,publicKeyPem:pem(oldKey),...opts});activateRelease(root,'0.1.0-old',pem(oldKey),opts);refreshVerifiedBootstrap(root,pem(oldKey),'0.1.0-old',opts);
 const registration={path:app,cdhash:'a'.repeat(40),certificateSha1:'b'.repeat(40),certificateSha256:'c'.repeat(64)};
 put(path.join(app,'Contents/Resources/artifact-defaults.json'),{bundle:'host-bundle',publisherKeyFile:'publisher.pem',publisherSha256:pin(nextKey)});put(path.join(app,'Contents/Resources/publisher.pem'),pem(nextKey));
 const config={schema:1,mode:'join-existing',gateway:{url:'https://gateway.example'},host:{bundle:old,publisherKeyFile:path.join(base,'publisher.pem'),publisherSha256:pin(oldKey),baseDir:base,label:'Test Mac',computer:false,macPreviewApp:registration}};
 const service={installRoot:root,hostConfigFile:path.join(base,'device/host.json'),trustPublicKeyFile:path.join(base,'publisher.pem'),nodeBinary:path.join(root,'releases/0.1.0-old/bin/node'+suffix),label:'app.styx.connector',unitName:'styx-host.service',logDir:path.join(base,'logs')};
 const serviceRaw=platform==='win32'?{task_name:'Styx-Host',install_root:root,host_config_file:service.hostConfigFile,publisher_key_file:service.trustPublicKeyFile,node_binary:service.nodeBinary}:service;
 const receipt={schema:1,status:'prepared_not_paired',version:'0.1.0-old',publisher_sha256:pin(oldKey),node:service.nodeBinary,release_root:path.join(root,'releases/0.1.0-old'),enrollment_config:path.join(base,'enrollment.json'),service_config:path.join(base,'service.json'),pairing:'NOT RUN',service_install:'NOT RUN',native_permissions:'NOT RUN'};
 put(path.join(stateDir,'deployment.json'),config);put(path.join(base,'service.json'),serviceRaw);put(path.join(base,'setup-receipt.json'),receipt);put(path.join(base,'publisher.pem'),pem(oldKey));
 const identity=key();put(path.join(base,'device/identity.pem'),identity.privateKey.export({type:'pkcs8',format:'pem'}));put(path.join(base,'device/identity.json'),{version:1,device_id:'styx-test',fingerprint:pin(identity)});put(path.join(base,'device/host.token'),'PRIVATE_TEST_TOKEN');put(path.join(base,'device/host.json'),{host_id:'styx-test',gateway_ws_url:'wss://gateway.example/',token_file:path.join(base,'device/host.token'),exec:{binary:path.join(root,'releases/0.1.0-old/bin/codex'),cwd:base}});
 put(path.join(base,'enrollment.json'),{gateway_url:config.gateway.url,storage_dir:path.join(base,'device')});put(path.join(base,'setup-state.json'),{schema:1,status:'preparing',version:'0.1.0-old'});
 const configSha256=sha(fs.readFileSync(path.join(stateDir,'deployment.json'))),evidenceFile=p=>({path:p,sha256:sha(fs.readFileSync(p))});
 put(path.join(stateDir,'state.json'),{schema:1,mode:config.mode,configSha256,steps:[{id:'host.prepare',status:'succeeded',evidence:{...receipt,receipt:evidenceFile(path.join(base,'setup-receipt.json')),serviceConfiguration:evidenceFile(path.join(base,'service.json'))}},{id:'host.claim',status:'succeeded',evidence:{hostConfiguration:evidenceFile(service.hostConfigFile)}},{id:'host.doctor',status:'succeeded',evidence:{healthy:true}},{id:'host.service.install',status:'pending'}],onboardingDecisions:{background:{configSha256}}});
 put(path.join(stateDir,'background.json'),{schema:1,configSha256,status:'disabled'});put(path.join(stateDir,'capabilities.json'),{schema:1,configSha256,status:'applied'});
 const adapters={platform,observeAbsence:async()=>({status:'absent'}),verifyApp:value=>({...value,cdhash:'d'.repeat(40),trust:'local_certificate_preview_not_notarized'})};
 return {dir,stateDir,base,root,app,config,candidate,oldKey,nextKey,adapters,bundle,opts};
}
