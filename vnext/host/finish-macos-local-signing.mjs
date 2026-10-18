// Run locally in the Mac user's interactive Terminal only after reviewing the
// prepared marked scratch app. Never unlocks or exports a key or changes ACLs.
import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {macDevelopmentSigningPlan,MAC_BUNDLE_ID} from './build-macos-app.mjs';
const assert=(ok,why)=>{if(!ok)throw Error(why)};
function privateFile(file){
  const st=fs.lstatSync(file);
  assert(st.isFile()&&!st.isSymbolicLink()&&st.uid===process.getuid()&&!(st.mode&0o077),'local_signing_file_not_private');
}
export function finishMacDevelopmentSigning(configFile){
  assert(process.platform==='darwin','native_macos_signing_required');
  assert(typeof configFile==='string'&&path.isAbsolute(configFile),'absolute_local_signing_config_required');
  privateFile(configFile);
  const config=JSON.parse(fs.readFileSync(configFile,'utf8'));
  assert(config.signingMode==='local-development'&&!config.notaryProfile,'explicit_local_development_only');
  const plan=macDevelopmentSigningPlan(config),root=path.dirname(config.app);
  const info=fs.lstatSync(root);
  assert(info.isDirectory()&&!info.isSymbolicLink()&&info.uid===process.getuid()&&!(info.mode&0o077),'marked_private_scratch_required');
  const marker=path.join(root,'.styx-local-owner.json');privateFile(marker);
  assert(JSON.parse(fs.readFileSync(marker,'utf8')).kind==='styx-local-development-app-pilot','owned_local_pilot_marker_required');
  for(const dir of [config.app,path.join(config.app,'Contents'),path.join(config.app,'Contents/MacOS')]){
    const st=fs.lstatSync(dir);
    assert(st.isDirectory()&&!st.isSymbolicLink()&&st.uid===process.getuid(),'prepared_app_directory_not_owned_regular');
    assert(fs.realpathSync(dir).startsWith(fs.realpathSync(root)+path.sep),'prepared_app_path_redirect_refused');
  }
  for(const member of ['Contents/Info.plist','Contents/MacOS/Styx','Contents/MacOS/cua-driver']){
    const st=fs.lstatSync(path.join(config.app,member));
    assert(st.isFile()&&!st.isSymbolicLink()&&st.uid===process.getuid(),'prepared_app_member_not_owned_regular');
  }
  const bundle=execFileSync('/usr/libexec/PlistBuddy',['-c','Print :CFBundleIdentifier',path.join(config.app,'Contents/Info.plist')],{encoding:'utf8',timeout:5000}).trim();
  assert(bundle===MAC_BUNDLE_ID,'prepared_app_bundle_identity_mismatch');
  const receiptFile=config.app+'.local-signing.json';assert(!fs.existsSync(receiptFile),'local_signing_receipt_already_exists');
  for(const [command,args] of plan)
    execFileSync(command,args,{stdio:'inherit',timeout:120000});
  const receipt={schema:1,status:'PASS',bundle_id:MAC_BUNDLE_ID,signing:'PASS',
    signing_detail:'Apple Development signature and explicit certificate OU verified for this local prepared app',
    notarization:'NOT RUN',external_distribution:'NOT RUN',native_gui_acceptance:'NOT RUN',
    key_export:'NOT RUN',keychain_acl_change:'NOT RUN'};
  fs.writeFileSync(receiptFile,JSON.stringify(receipt,null,2)+'\n',{flag:'wx',mode:0o600});
  return receipt;
}
if(process.argv[1]&&fs.realpathSync(process.argv[1])===fs.realpathSync(fileURLToPath(import.meta.url))){
  try{console.log(JSON.stringify(finishMacDevelopmentSigning(process.argv[2])))}
  catch{console.error('Styx local signing remains BLOCKED; inspect the OS codesign result above. No keychain setting was changed.');process.exitCode=2}
}
