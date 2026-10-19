// Local first-contact preparation. Never enrolls, grants permissions or starts services.
import fs from 'node:fs';
import path from 'node:path';
import {createHash,createPublicKey} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {requirePrivateDirectory,requirePrivateFile,ensurePrivateDirectory} from './private-storage.mjs';
import {verifyMacPreviewApp} from './macos-preview-trust.mjs';
import {verifySignedRelease,stageSignedRelease,activateRelease,refreshVerifiedBootstrap} from './installer.mjs';
const assert=(ok,code)=>{if(!ok)throw Error(code)};
const absolute=p=>typeof p==='string'&&path.isAbsolute(p)&&path.normalize(p)===p;
const write=(p,value)=>fs.writeFileSync(p,typeof value==='string'?value:JSON.stringify(value,null,2)+'\n',{flag:'wx',mode:0o600});
export function prepareNativeSetup(config){
  const {bundle,publisherKeyFile,publisherSha256,baseDir,gatewayUrl,label,computer=false,gatewayCaFile}=config;
  for(const p of [bundle,publisherKeyFile,baseDir])assert(absolute(p),'absolute_setup_paths_required');
  assert(typeof computer==='boolean','invalid_computer_selection');
  assert(typeof label==='string'&&label.length>0&&label.length<=72,'invalid_host_label');
  const gateway=new URL(gatewayUrl);
  assert(gateway.protocol==='https:'&&!gateway.username&&!gateway.password&&!gateway.search&&!gateway.hash&&gateway.pathname==='/','gateway_https_origin_required');
  assert(/^[a-f0-9]{64}$/.test(publisherSha256??''),'trusted_publisher_fingerprint_required');
  const pubStat=fs.lstatSync(publisherKeyFile);assert(pubStat.isFile()&&!pubStat.isSymbolicLink(),'regular_publisher_key_required');
  const pub=fs.readFileSync(publisherKeyFile,'utf8');
  const digest=createHash('sha256').update(createPublicKey(pub).export({type:'spki',format:'der'})).digest('hex');
  assert(digest===publisherSha256,'publisher_fingerprint_mismatch');
  const verified=verifySignedRelease(bundle,pub);
  const exe=process.platform==='win32'?'.exe':'';
  const serviceHelper=process.platform==='win32'?'windows-task.ps1':process.platform==='darwin'?'macos-launchagent.mjs':'linux-service.mjs';
  const required=['host/private-storage.mjs','host/installer.mjs','host/launch.mjs','host/enroll.mjs','host/setup-native.mjs','host/doctor.mjs','host/'+serviceHelper,`bin/node${exe}`,`bin/codex${exe}`,`bin/cua-driver${exe}`];
  const files=new Map(verified.manifest.files.map(f=>[f.path,f]));
  for(const name of required)assert(files.has(name)&&(!name.startsWith('bin/')||files.get(name).executable),'complete_native_release_required');
  const shell=config.shell??(process.platform==='win32'?path.join(process.env.SystemRoot??'C:\\Windows','System32','WindowsPowerShell','v1.0','powershell.exe'):'/bin/sh');
  assert(absolute(shell)&&fs.statSync(shell).isFile(),'native_shell_required');
  let ca;
  if(gatewayCaFile!==undefined){assert(absolute(gatewayCaFile),'absolute_gateway_ca_required');const st=fs.lstatSync(gatewayCaFile);assert(st.isFile()&&!st.isSymbolicLink(),'regular_gateway_ca_required');ca=fs.readFileSync(gatewayCaFile);}
  let previewApp;
  if(config.macPreviewApp!==undefined){assert(process.platform==='darwin','mac_preview_only');previewApp=verifyMacPreviewApp(config.macPreviewApp);}
  if(computer&&process.platform==='darwin'&&!previewApp){
    assert(/^[A-Z0-9]{10}$/.test(config.macTeamID??''),'mac_team_required');
    execFileSync('/usr/bin/codesign',['--verify','--deep','--strict','/Applications/Styx.app'],{stdio:'ignore',timeout:10000});
    execFileSync('/usr/bin/codesign',['--verify','--strict','-R',`=anchor apple generic and identifier "app.styx.host" and certificate leaf[subject.OU] = "${config.macTeamID}"`,'/Applications/Styx.app'],{stdio:'ignore',timeout:10000});
  }
  // Reject existing state before any mutation; interrupted preparation is never replayed.
  requirePrivateDirectory(path.dirname(baseDir));
  assert(!fs.existsSync(baseDir),'setup_directory_already_exists');
  fs.mkdirSync(baseDir,{mode:0o700});requirePrivateDirectory(baseDir);
  write(path.join(baseDir,'setup-state.json'),{schema:1,status:'preparing',version:verified.version});
  const installRoot=path.join(baseDir,'install'),device=path.join(baseDir,'device');
  for(const p of [device,path.join(baseDir,'work'),path.join(baseDir,'codex-home'),path.join(baseDir,'logs')])ensurePrivateDirectory(p);
  const trust=path.join(baseDir,'publisher.pem');write(trust,pub);
  const caFile=ca?path.join(baseDir,'gateway-ca.pem'):undefined;if(ca)write(caFile,ca.toString());
  stageSignedRelease({sourceDir:bundle,installRoot,publicKeyPem:pub});
  activateRelease(installRoot,verified.version,pub);refreshVerifiedBootstrap(installRoot,pub,verified.version);
  const release=path.join(installRoot,'releases',verified.version);
  const enrollment={gateway_url:gateway.origin,...(caFile?{gateway_ca_file:caFile}:{}),storage_dir:device,label,
    cwd:path.join(baseDir,'work'),shell,codex_home:path.join(baseDir,'codex-home'),exec_binary:path.join(release,'bin','codex'+exe),computer_requested:computer,
    ...(computer?{computer_binary:process.platform==='darwin'?path.join(previewApp?.path??'/Applications/Styx.app','Contents/MacOS/cua-driver'):path.join(release,'bin','cua-driver'+exe),
      ...(process.platform==='darwin'?{computer_socket:`/tmp/styx-cua-${process.getuid()}/cua.sock`}:{}),
      ...(process.platform==='linux'&&config.wayland===true?{computer_env:{CUA_DRIVER_RS_ENABLE_WAYLAND:'1'}}:{})}:{})};
  write(path.join(baseDir,'enrollment.json'),enrollment);
  const node=process.platform==='win32'?path.join(installRoot,'node.exe'):path.join(release,'bin','node');
  const common={installRoot,hostConfigFile:path.join(device,'host.json'),trustPublicKeyFile:trust,nodeBinary:node};
  const service=process.platform==='win32'?{task_name:'Styx-Host',install_root:installRoot,host_config_file:common.hostConfigFile,publisher_key_file:trust,node_binary:node}
    :process.platform==='darwin'?{...common,label:'app.styx.connector',logDir:path.join(baseDir,'logs')}:{...common,unitName:'styx-host.service'};
  write(path.join(baseDir,'service.json'),service);
  const receipt={schema:1,status:'prepared_not_paired',version:verified.version,publisher_sha256:digest,
    node,release_root:release,enrollment_config:path.join(baseDir,'enrollment.json'),service_config:path.join(baseDir,'service.json'),
    pairing:'NOT RUN',service_install:'NOT RUN',native_permissions:'NOT RUN'};
  write(path.join(baseDir,'setup-receipt.json'),receipt);return receipt;
}
if(process.argv[1]&&fs.realpathSync(process.argv[1])===fs.realpathSync(fileURLToPath(import.meta.url))){
  try{assert(process.argv[2]==='prepare'&&absolute(process.argv[3]),'usage_prepare_absolute_config');requirePrivateFile(process.argv[3]);console.log(JSON.stringify(prepareNativeSetup(JSON.parse(fs.readFileSync(process.argv[3],'utf8')))));}
  catch{console.error('Styx native setup failed; preserve partial state for inspection. No enrollment or service start was attempted.');process.exitCode=2;}
}
