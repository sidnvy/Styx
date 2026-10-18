// Native AppKit owner packaging. Signing/notarization are explicit publisher actions.
import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';

export const MAC_BUNDLE_ID='app.styx.host';
const SOURCE=fileURLToPath(new URL('./macos/Styx.swift',import.meta.url));
const assert=(condition,message)=>{if(!condition)throw Error(message)};
const xml=value=>value.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;');
export function appInfoPlist(version){
  assert(/^\d+\.\d+\.\d+$/.test(version??''),'invalid_app_version');
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>${MAC_BUNDLE_ID}</string>
<key>CFBundleName</key><string>Styx</string>
<key>CFBundleDisplayName</key><string>Styx</string>
<key>CFBundleExecutable</key><string>Styx</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>${xml(version)}</string>
<key>CFBundleVersion</key><string>${xml(version)}</string>
<key>LSMinimumSystemVersion</key><string>13.0</string>
<key>LSUIElement</key><true/>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>\n`;
}
export function macSigningPlan({app,identity,teamID,notaryProfile}={}){
  assert(typeof app==='string'&&path.isAbsolute(app)&&path.basename(app)==='Styx.app','invalid_styx_app_path');
  assert(typeof identity==='string'&&/^Developer ID Application: [^\n]+ \([A-Z0-9]{10}\)$/.test(identity),'developer_id_application_required');
  assert(/^[A-Z0-9]{10}$/.test(teamID??'')&&identity.endsWith(`(${teamID})`),'signing_team_mismatch');
  if(notaryProfile!==undefined)assert(/^[A-Za-z0-9._-]{1,80}$/.test(notaryProfile),'invalid_notary_profile');
  // Sign nested code first. Never use --deep to paper over unidentified code.
  const steps=[
    ['/usr/bin/codesign',['--force','--options','runtime','--timestamp','--sign',identity,path.join(app,'Contents/MacOS/cua-driver')]],
    ['/usr/bin/codesign',['--force','--options','runtime','--timestamp','--sign',identity,app]],
    ['/usr/bin/codesign',['--verify','--deep','--strict','--verbose=2',app]],
    ['/usr/bin/codesign',['--verify','--strict','-R',`anchor apple generic and identifier "${MAC_BUNDLE_ID}" and certificate leaf[subject.OU] = "${teamID}"`,app]]
  ];
  if(notaryProfile){
    const archive=app+'.notarization.zip';
    steps.push(['/usr/bin/ditto',['-c','-k','--keepParent',app,archive]],
      ['/usr/bin/xcrun',['notarytool','submit',archive,'--keychain-profile',notaryProfile,'--wait','--output-format','json']],
      ['/usr/bin/xcrun',['stapler','staple',app]],
      ['/usr/bin/xcrun',['stapler','validate',app]],
      ['/usr/sbin/spctl',['--assess','--type','execute','--verbose=2',app]]);
  }
  return steps;
}
export function buildMacApp({app,cuaBinary,version,identity,teamID,notaryProfile}={}){
  assert(process.platform==='darwin','native_macos_build_required');
  const plist=appInfoPlist(version);
  assert(typeof app==='string'&&path.isAbsolute(app)&&path.basename(app)==='Styx.app','invalid_styx_app_path');
  assert(typeof cuaBinary==='string'&&path.isAbsolute(cuaBinary),'absolute_cua_binary_required');
  assert(!fs.existsSync(app)&&!fs.existsSync(app+'.notarization.zip'),'app_destination_exists');
  const stat=fs.lstatSync(cuaBinary);
  assert(stat.isFile()&&!stat.isSymbolicLink(),'regular_cua_binary_required');
  const observed=execFileSync(cuaBinary,['--version'],{encoding:'utf8',timeout:10000}).trim();
  assert(/^cua-driver 0\.36\.0(?:\s|$)/.test(observed),'pinned_cua_036_required');
  assert(!notaryProfile||identity,'notarization_requires_signing');
  assert(!teamID||identity,'team_requires_signing');
  const steps=identity?macSigningPlan({app,identity,teamID,notaryProfile}):[];
  fs.mkdirSync(path.dirname(app),{recursive:true});
  fs.mkdirSync(app);
  try{
    const macos=path.join(app,'Contents/MacOS');
    fs.mkdirSync(macos,{recursive:true});
    fs.writeFileSync(path.join(app,'Contents/Info.plist'),plist,{flag:'wx'});
    const driver=path.join(macos,'cua-driver');
    fs.copyFileSync(cuaBinary,driver,fs.constants.COPYFILE_EXCL);fs.chmodSync(driver,0o755);
    const inputHash=createHash('sha256').update(fs.readFileSync(cuaBinary)).digest('hex');
    execFileSync('/usr/bin/xcrun',['swiftc','-O','-target',`${process.arch==='arm64'?'arm64':'x86_64'}-apple-macosx13.0`,SOURCE,'-o',path.join(macos,'Styx'),'-framework','AppKit','-framework','ApplicationServices','-framework','CoreGraphics'],{stdio:'inherit',timeout:180000});
    execFileSync('/usr/bin/plutil',['-lint',path.join(app,'Contents/Info.plist')],{stdio:'inherit'});
    for(const [command,args] of steps){
      const output=execFileSync(command,args,{encoding:'utf8',timeout:1800000});
      if(args[0]==='notarytool')assert(JSON.parse(output).status==='Accepted','notarization_not_accepted');
    }
    return {schema:1,bundle_id:MAC_BUNDLE_ID,version,arch:process.arch,
      cua_version:observed,cua_input_sha256:inputHash,app,
      signing:identity?'PASS':'NOT RUN',
      signing_detail:identity?'developer_id_verified':'unsigned_development_bundle',
      notarization:notaryProfile?'PASS':'NOT RUN',
      notarization_detail:notaryProfile?'accepted_stapled_assessed':'not_submitted',
      native_gui_acceptance:'NOT RUN',tcc_attribution:'NOT RUN'};
  }catch(error){
    // Preserve failed output for diagnostics; never identify it as a release.
    throw Error('macos_app_build_failed: '+error.message,{cause:error});
  }
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const [configFile]=process.argv.slice(2);
  try{
    assert(configFile&&path.isAbsolute(configFile),'absolute_build_config_required');
    const receipt=buildMacApp(JSON.parse(fs.readFileSync(configFile,'utf8')));
    // Receipt remains outside the signed bundle; writing inside invalidates its seal.
    fs.writeFileSync(receipt.app+'.build.json',JSON.stringify(receipt,null,2)+'\n',{flag:'wx',mode:0o600});
    console.log(JSON.stringify(receipt));
  }catch(error){console.error('Styx macOS app: '+error.message);process.exitCode=2}
}
