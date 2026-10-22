// Native AppKit owner packaging. Signing/notarization are explicit publisher actions.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {execFileSync} from 'node:child_process';
import {createHash,X509Certificate} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {crc32,normalizePresentation} from '../plugin/package.mjs';
import {normalizeMacPlatformUpdate,stageMacSparkle,sparkleDistributionSigningPlan} from './macos/platform-update/sparkle-build.mjs';

export const MAC_BUNDLE_ID='app.styx.host';
const SOURCE=fileURLToPath(new URL('./macos/Styx.swift',import.meta.url));
const UPDATER=fileURLToPath(new URL('./macos/StyxUpdater.swift',import.meta.url));
const GLYPH=fileURLToPath(new URL('./macos/BrandGlyph.swift',import.meta.url));
const ICON_RENDERER=fileURLToPath(new URL('./macos/render-brand-icons.swift',import.meta.url));
const PRODUCT_UI=fileURLToPath(new URL('./macos/product-ui/',import.meta.url));
const BRAND=fileURLToPath(new URL('../assets/brand/',import.meta.url));
const LICENSES=fileURLToPath(new URL('../licenses/',import.meta.url));
const assert=(condition,message)=>{if(!condition)throw Error(message)};
const xml=value=>value.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;');
// sips preserves source ICC/EXIF metadata. The exported plugin image uses the
// same bounded, metadata-free PNG contract as the Core profile API.
export function prepareMacPluginIcon(bytes){
  assert(Buffer.isBuffer(bytes)&&bytes.length>=8&&bytes.length<=256*1024&&bytes.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])),'invalid_packaged_plugin_png');
  const parts=[bytes.subarray(0,8)],metadata=new Set(['iCCP','eXIf','tEXt','zTXt','iTXt']);
  for(let offset=8;offset<bytes.length;){
    assert(offset+12<=bytes.length,'invalid_packaged_plugin_png');
    const size=bytes.readUInt32BE(offset),end=offset+12+size;
    assert(end<=bytes.length&&bytes.readUInt32BE(end-4)===crc32(bytes.subarray(offset+4,end-4)),'invalid_packaged_plugin_png');
    if(!metadata.has(bytes.toString('latin1',offset+4,offset+8)))parts.push(bytes.subarray(offset,end));
    offset=end;
  }
  const result=Buffer.concat(parts);
  normalizePresentation({icon:{mimeType:'image/png',dataBase64:result.toString('base64')}});
  return result;
}
// Keep release ordering separate from the marketing version. This canonical
// subset fits Apple's documented 4/2/2 digit components and avoids aliases.
export function macAppBuildMetadata({version,buildNumber,updateRelease=false}={}){
  assert(/^\d+\.\d+\.\d+$/.test(version??''),'invalid_app_version');
  assert(typeof updateRelease==='boolean','invalid_macos_update_release');
  assert(buildNumber===undefined||typeof buildNumber==='string'&&/^[1-9]\d{0,3}(?:\.(?:0|[1-9]\d?)){0,2}$/.test(buildNumber),'invalid_macos_build_number');
  assert(!updateRelease||buildNumber!==undefined,'macos_update_release_build_number_required');
  return {marketingVersion:version,buildNumber:buildNumber??'0',updateRelease,
    buildNumberSource:buildNumber===undefined?'development_sentinel_not_for_updates':'explicit_release_sequence'};
}
export function appInfoPlist(version,{buildNumber,updateRelease=false,platformUpdate,app}={}){
  const metadata=macAppBuildMetadata({version,buildNumber,updateRelease});
  const updater=normalizeMacPlatformUpdate(platformUpdate,{app,updateRelease});
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>${MAC_BUNDLE_ID}</string>
<key>CFBundleName</key><string>Styx</string>
<key>CFBundleDisplayName</key><string>Styx</string>
<key>CFBundleExecutable</key><string>Styx</string>
<key>CFBundleIconFile</key><string>Styx.icns</string>
<key>CFBundleLocalizations</key><array><string>en</string><string>zh-Hans</string></array>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>${xml(version)}</string>
<key>CFBundleVersion</key><string>${xml(metadata.buildNumber)}</string>
<key>StyxUpdateRelease</key><${metadata.updateRelease?'true':'false'}/>
${updater?`<key>SUFeedURL</key><string>${xml(updater.feedUrl)}</string>
<key>SUPublicEDKey</key><string>${xml(updater.publicEdKey)}</string>
<key>SUEnableAutomaticChecks</key><false/>
<key>SUAutomaticallyUpdate</key><false/>
<key>SUSendProfileInfo</key><false/>
<key>SUVerifyUpdateBeforeExtraction</key><true/>
<key>StyxIsolatedPlatformUpdateProbe</key><${updater.isolatedProbe?'true':'false'}/>
${updater.isolatedProbe?'<key>NSAppTransportSecurity</key><dict><key>NSAllowsLocalNetworking</key><true/></dict>':''}`:''}
<key>LSMinimumSystemVersion</key><string>13.0</string>
<key>LSUIElement</key><true/>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>\n`;
}
export function macSigningPlan({app,identity,teamID,notaryProfile}={}){
  assert(typeof app==='string'&&path.posix.isAbsolute(app)&&path.posix.basename(app)==='Styx.app','invalid_styx_app_path');
  assert(typeof identity==='string'&&/^Developer ID Application: [^\n]+ \([A-Z0-9]{10}\)$/.test(identity),'developer_id_application_required');
  assert(/^[A-Z0-9]{10}$/.test(teamID??'')&&identity.endsWith(`(${teamID})`),'signing_team_mismatch');
  if(notaryProfile!==undefined)assert(/^[A-Za-z0-9._-]{1,80}$/.test(notaryProfile),'invalid_notary_profile');
  // Sign nested code first. Never use --deep to paper over unidentified code.
  const steps=[
    ['/usr/bin/codesign',['--force','--options','runtime','--timestamp','--sign',identity,path.posix.join(app,'Contents/MacOS/cua-driver')]],
    ['/usr/bin/codesign',['--force','--options','runtime','--timestamp','--sign',identity,path.posix.join(app,'Contents/MacOS/StyxUpdater')]],
    ['/usr/bin/codesign',['--force','--options','runtime','--timestamp','--sign',identity,app]],
    ['/usr/bin/codesign',['--verify','--deep','--strict','--verbose=2',app]],
    ['/usr/bin/codesign',['--verify','--strict','-R',`=anchor apple generic and identifier "${MAC_BUNDLE_ID}" and certificate leaf[subject.OU] = "${teamID}"`,app]]
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
// Explicit local Mac acceptance only. Apple Development CN suffix is a user
// identifier and need not equal the certificate OU/TeamIdentifier. Verify the
// supplied team against the signed code requirement instead of guessing it.
export function macDevelopmentSigningPlan({app,identity,teamID}={}){
  assert(typeof app==='string'&&path.posix.isAbsolute(app)&&path.posix.basename(app)==='Styx.app','invalid_styx_app_path');
  assert(typeof identity==='string'&&/^Apple Development: [^\n]+ \([A-Z0-9]{10}\)$/.test(identity),'apple_development_identity_required');
  assert(/^[A-Z0-9]{10}$/.test(teamID??''),'development_signing_team_required');
  return [
    ['/usr/bin/codesign',['--force','--options','runtime','--timestamp=none','--sign',identity,path.posix.join(app,'Contents/MacOS/cua-driver')]],
    ['/usr/bin/codesign',['--force','--options','runtime','--timestamp=none','--sign',identity,path.posix.join(app,'Contents/MacOS/StyxUpdater')]],
    ['/usr/bin/codesign',['--force','--options','runtime','--timestamp=none','--sign',identity,app]],
    ['/usr/bin/codesign',['--verify','--deep','--strict','--verbose=2',app]],
    ['/usr/bin/codesign',['--verify','--strict','-R',`=anchor apple generic and identifier "${MAC_BUNDLE_ID}" and certificate leaf[subject.OU] = "${teamID}"`,app]]
  ];
}
export function macAdhocSigningPlan({app,files=[],sealApp=true}={}){
  assert(typeof app==='string'&&path.posix.isAbsolute(app)&&path.posix.normalize(app)===app&&path.posix.basename(app)==='Styx.app','invalid_styx_app_path');
  assert(Array.isArray(files)&&new Set(files).size===files.length&&files.every(f=>typeof f==='string'&&path.posix.isAbsolute(f)&&path.posix.normalize(f)===f&&f.startsWith(app+'/')),'adhoc_nested_code_paths_required');
  const ordered=[...files].sort((a,b)=>b.split('/').length-a.split('/').length||a.localeCompare(b));
  const steps=ordered.map(file=>['/usr/bin/codesign',['--force','--timestamp=none','--sign','-',file]]);
  if(sealApp)steps.push(['/usr/bin/codesign',['--force','--timestamp=none','--sign','-',app]],['/usr/bin/codesign',['--verify','--deep','--strict','--verbose=2',app]]);
  return steps;
}
// A persistent local certificate is an explicit preview identity, never an
// Apple publisher identity. The keychain is build input, not public metadata.
export function normalizeMacLocalSigning(value){
  assert(value&&Object.getPrototypeOf(value)===Object.prototype&&Object.keys(value).length===3&&
    Object.keys(value).every(k=>['identitySha1','certificateSha256','keychain'].includes(k)), 'invalid_local_signing_configuration');
  assert(typeof value.identitySha1==='string'&&/^[a-f0-9]{40}$/.test(value.identitySha1),'invalid_local_signing_identity_sha1');
  assert(typeof value.certificateSha256==='string'&&/^[a-f0-9]{64}$/.test(value.certificateSha256),'invalid_local_signing_certificate_sha256');
  assert(typeof value.keychain==='string'&&path.posix.isAbsolute(value.keychain)&&path.posix.normalize(value.keychain)===value.keychain&&
    !/[\x00-\x1f\x7f]/.test(value.keychain),'absolute_local_signing_keychain_required');
  return {identitySha1:value.identitySha1,certificateSha256:value.certificateSha256,keychain:value.keychain};
}
export function publicMacLocalSigning(value){
  const local=normalizeMacLocalSigning(value);
  return {schema:1,certificateSha1:local.identitySha1,certificateSha256:local.certificateSha256};
}
export function verifyMacLocalSigning(value,{run=execFileSync}={}){
  const local=normalizeMacLocalSigning(value),stat=fs.lstatSync(local.keychain);
  assert(stat.isFile()&&!stat.isSymbolicLink(),'regular_local_signing_keychain_required');
  const pem=run('/usr/bin/security',['find-certificate','-a','-p',local.keychain],{encoding:'utf8',timeout:15000,maxBuffer:1024*1024});
  const matching=String(pem).match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g)?.map(p=>new X509Certificate(p)).find(cert=>
    createHash('sha1').update(cert.raw).digest('hex')===local.identitySha1);
  assert(matching&&createHash('sha256').update(matching.raw).digest('hex')===local.certificateSha256,'local_signing_certificate_fingerprint_mismatch');
  return publicMacLocalSigning(local);
}
export function macLocalSigningPlan({app,localSigning,files=[],sealApp=true}={}){
  const local=normalizeMacLocalSigning(localSigning);
  assert(typeof app==='string'&&path.posix.isAbsolute(app)&&path.posix.normalize(app)===app&&path.posix.basename(app)==='Styx.app'&&!/[\x00-\x1f\x7f]/.test(app),'invalid_styx_app_path');
  assert(typeof sealApp==='boolean'&&Array.isArray(files)&&new Set(files).size===files.length&&files.every(f=>typeof f==='string'&&
    path.posix.isAbsolute(f)&&path.posix.normalize(f)===f&&f.startsWith(app+'/')&&!/[\x00-\x1f\x7f]/.test(f)),'local_nested_code_paths_required');
  const ordered=[...files].sort((a,b)=>b.split('/').length-a.split('/').length||a.localeCompare(b));
  const steps=[];
  const add=file=>{
    const relative=path.posix.relative(app,file);
    const identifier=file===app||relative==='Contents/MacOS/Styx'?MAC_BUNDLE_ID:
      MAC_BUNDLE_ID+'.code.'+createHash('sha256').update(relative).digest('hex').slice(0,32);
    const requirement=`identifier "${identifier}" and certificate leaf = H"${local.identitySha1}"`;
    steps.push(['/usr/bin/codesign',['--force','--timestamp=none','--keychain',local.keychain,'--sign',local.identitySha1,
      '--identifier',identifier,'--requirements','=designated => '+requirement,file]],
      ['/usr/bin/codesign',['--verify','--strict','-R','='+requirement,file]]);
  };
  for(const file of ordered)add(file);
  if(sealApp){add(app);steps.push(['/usr/bin/codesign',['--verify','--deep','--strict','--verbose=2',app]]);}
  return steps;
}
export function macNativeSwiftSources(){
  const additionalSources=[GLYPH,...fs.readdirSync(PRODUCT_UI).filter(name=>name.endsWith('.swift')).sort().map(name=>path.join(PRODUCT_UI,name))];
  assert(additionalSources.length>0,'native_product_sources_required');
  return {source:SOURCE,additionalSources};
}
export function macSwiftBuildArguments({source,output,arch=process.arch,sdkPath,moduleCachePath,additionalSources=[],frameworkSearchPath}={}){
  const absolute=p=>typeof p==='string'&&path.posix.isAbsolute(p)&&path.posix.normalize(p)===p&&!/[\x00-\x1f\x7f]/.test(p);
  assert(absolute(source)&&absolute(output),'absolute_swift_build_paths_required');
  assert(Array.isArray(additionalSources)&&additionalSources.every(absolute),'absolute_additional_swift_sources_required');
  assert(['arm64','x64'].includes(arch),'unsupported_swift_build_arch');
  assert(sdkPath===undefined||absolute(sdkPath),'absolute_macos_sdk_required');
  assert(frameworkSearchPath===undefined||absolute(frameworkSearchPath),'absolute_framework_search_path_required');
  assert(moduleCachePath===undefined||absolute(moduleCachePath),'absolute_swift_module_cache_required');
  assert(sdkPath===undefined||moduleCachePath!==undefined,'explicit_sdk_requires_isolated_module_cache');
  return ['swiftc','-O','-warnings-as-errors','-target',`${arch==='arm64'?'arm64':'x86_64'}-apple-macosx13.0`,
    ...(sdkPath===undefined?[]:['-sdk',sdkPath]),...(moduleCachePath===undefined?[]:['-module-cache-path',moduleCachePath]),
    ...(frameworkSearchPath?['-F',frameworkSearchPath,'-framework','Sparkle','-Xlinker','-rpath','-Xlinker','@executable_path/../Frameworks']:[]),
    ...(additionalSources.length?['-D','STYX_PRODUCT_UI']:[]),source,...additionalSources,'-o',output,'-framework','AppKit','-framework','ApplicationServices','-framework','CoreGraphics','-framework','SwiftUI','-framework','WebKit'];
}
export function buildMacApp({app,cuaBinary,version,buildNumber,updateRelease=false,platformUpdate,identity,teamID,notaryProfile,signingMode='distribution',localSigning,sdkPath,moduleCachePath}={}){
  assert(process.platform==='darwin','native_macos_build_required');
  const build=macAppBuildMetadata({version,buildNumber,updateRelease});
  // Developer ID output needs a distinct build even before a feed is enabled;
  // signing is not a claim that this artifact has been publicly published.
  if(identity&&signingMode==='distribution'||notaryProfile)assert(buildNumber!==undefined,'macos_distribution_build_number_required');
  const updater=normalizeMacPlatformUpdate(platformUpdate,{app,updateRelease});
  const plist=appInfoPlist(version,{buildNumber,updateRelease,platformUpdate,app});
  assert(['distribution','local-development'].includes(signingMode),'invalid_macos_signing_mode');
  if(localSigning!==undefined){normalizeMacLocalSigning(localSigning);assert(identity===undefined&&teamID===undefined&&notaryProfile===undefined&&signingMode==='distribution','local_signing_modes_mutually_exclusive');}
  assert(signingMode!=='local-development'||identity,'local_development_identity_required');
  assert(signingMode!=='local-development'||!notaryProfile,'local_development_notarization_not_supported');
  assert(typeof app==='string'&&path.isAbsolute(app)&&path.basename(app)==='Styx.app','invalid_styx_app_path');
  assert(typeof cuaBinary==='string'&&path.isAbsolute(cuaBinary),'absolute_cua_binary_required');
  assert(!fs.existsSync(app)&&!fs.existsSync(app+'.notarization.zip'),'app_destination_exists');
  const nativeSources=macNativeSwiftSources(),productSources=nativeSources.additionalSources;
  const buildRoot=fs.mkdtempSync(path.join(os.tmpdir(),'styx-native-build-'));
  const entry=path.join(buildRoot,'main.swift');fs.copyFileSync(nativeSources.source,entry);
  const swiftArgs=macSwiftBuildArguments({source:entry,additionalSources:productSources,output:path.join(app,'Contents/MacOS/Styx'),sdkPath,moduleCachePath,...(updater?{frameworkSearchPath:path.join(app,'Contents/Frameworks')}: {})});
  if(sdkPath!==undefined)assert(fs.statSync(sdkPath).isDirectory()&&fs.statSync(path.join(sdkPath,'SDKSettings.json')).isFile(),'macos_sdk_directory_required');
  if(moduleCachePath!==undefined)assert(!fs.existsSync(moduleCachePath),'fresh_swift_module_cache_required');
  const stat=fs.lstatSync(cuaBinary);
  assert(stat.isFile()&&!stat.isSymbolicLink(),'regular_cua_binary_required');
  const observed=execFileSync(cuaBinary,['--version'],{encoding:'utf8',timeout:10000}).trim();
  assert(/^cua-driver 0\.36\.0(?:\s|$)/.test(observed),'pinned_cua_036_required');
  assert(!notaryProfile||identity,'notarization_requires_signing');
  assert(!teamID||identity,'team_requires_signing');
  const steps=localSigning!==undefined?macLocalSigningPlan({app,localSigning,files:[path.posix.join(app,'Contents/MacOS/cua-driver'),path.posix.join(app,'Contents/MacOS/Styx'),path.posix.join(app,'Contents/MacOS/StyxUpdater')]}):identity?(signingMode==='local-development'
    ?macDevelopmentSigningPlan({app,identity,teamID})
    :macSigningPlan({app,identity,teamID,notaryProfile})):[];
  fs.mkdirSync(path.dirname(app),{recursive:true});
  fs.mkdirSync(app);
  try{
    if(moduleCachePath!==undefined)fs.mkdirSync(moduleCachePath,{mode:0o700});
    const notices=path.join(app,'Contents/Resources/licenses');
    fs.mkdirSync(notices,{recursive:true});
    if(localSigning!==undefined){
      const descriptor=verifyMacLocalSigning(localSigning);
      fs.writeFileSync(path.join(app,'Contents/Resources/local-signing.json'),JSON.stringify(descriptor,null,2)+'\n',{flag:'wx'});
    }
    const sparkle=updater?stageMacSparkle(updater,{app,buildRoot}):null;
    for(const name of ['cua-LICENSE','styx-LICENSE','provenance.json'])
      fs.copyFileSync(path.join(LICENSES,name),path.join(notices,name),fs.constants.COPYFILE_EXCL);
    const brand=path.join(app,'Contents/Resources/brand');fs.mkdirSync(brand);
    for(const name of ['styx-icon-dark-source.jpg','styx-icon-light-source.jpg'])fs.copyFileSync(path.join(BRAND,name),path.join(brand,name));
    const iconset=path.join(buildRoot,'Styx.iconset');fs.mkdirSync(iconset);
    const iconSource=path.join(buildRoot,'icon-renderer');fs.mkdirSync(iconSource);
    const iconEntry=path.join(iconSource,'main.swift'),iconBinary=path.join(iconSource,'render-icons');
    fs.copyFileSync(ICON_RENDERER,iconEntry);
    execFileSync('/usr/bin/xcrun',macSwiftBuildArguments({source:iconEntry,additionalSources:[GLYPH],output:iconBinary,sdkPath,
      ...(sdkPath?{moduleCachePath:path.join(buildRoot,'icon-module-cache')}:{})}),{stdio:'inherit',timeout:180000});
    execFileSync(iconBinary,[path.join(BRAND,'styx-icon-light-source.jpg'),brand,iconset],{stdio:'pipe',timeout:30000});
    const pluginIcon=path.join(brand,'styx-plugin-icon.png');
    fs.writeFileSync(pluginIcon,prepareMacPluginIcon(fs.readFileSync(pluginIcon)));
    execFileSync('/usr/bin/iconutil',['-c','icns',iconset,'-o',path.join(app,'Contents/Resources/Styx.icns')],{stdio:'pipe'});
    const macos=path.join(app,'Contents/MacOS');
    fs.mkdirSync(macos,{recursive:true});
    fs.writeFileSync(path.join(app,'Contents/Info.plist'),plist,{flag:'wx'});
    const driver=path.join(macos,'cua-driver');
    fs.copyFileSync(cuaBinary,driver,fs.constants.COPYFILE_EXCL);fs.chmodSync(driver,0o755);
    const inputHash=createHash('sha256').update(fs.readFileSync(cuaBinary)).digest('hex');
    execFileSync('/usr/bin/xcrun',swiftArgs,{stdio:'inherit',timeout:180000});
    execFileSync('/usr/bin/xcrun',macSwiftBuildArguments({source:UPDATER,output:path.join(macos,'StyxUpdater'),sdkPath,moduleCachePath}),{stdio:'inherit',timeout:180000});
    execFileSync('/usr/bin/plutil',['-lint',path.join(app,'Contents/Info.plist')],{stdio:'inherit'});
    for(const [command,args] of [...(updater?sparkleDistributionSigningPlan({app,identity,signingMode}):[]),...steps]){
      // A local keychain approval must not turn into an unattended long wait.
      const output=execFileSync(command,args,{encoding:'utf8',timeout:localSigning!==undefined||signingMode==='local-development'?15000:1800000});
      if(args[0]==='notarytool')assert(JSON.parse(output).status==='Accepted','notarization_not_accepted');
    }
    return {schema:1,bundle_id:MAC_BUNDLE_ID,version,buildNumber:build.buildNumber,buildNumberSource:build.buildNumberSource,updateRelease:build.updateRelease,arch:process.arch,
      cua_version:observed,cua_input_sha256:inputHash,app,
      platformUpdate:sparkle?{frameworkVersion:sparkle.version,archiveSha256:sparkle.archiveSha256,feedUrl:updater.feedUrl,isolatedProbe:updater.isolatedProbe}:null,
      signing:localSigning!==undefined||identity?'PASS':'NOT RUN',
      signing_detail:localSigning!==undefined?'local_certificate_preview':identity?(signingMode==='local-development'?'apple_development_local_only':'developer_id_verified'):'unsigned_development_bundle',
      signing_mode:localSigning!==undefined?'local_certificate_preview':signingMode,...(localSigning!==undefined?{local_signing:publicMacLocalSigning(localSigning)}:{}),external_distribution:'NOT RUN',
      compiler:{sdk_path:sdkPath??'xcrun_default',module_cache_path:moduleCachePath??'compiler_default',warnings_as_errors:true,target:swiftArgs[swiftArgs.indexOf('-target')+1]},
      notarization:notaryProfile?'PASS':'NOT RUN',
      notarization_detail:notaryProfile?'accepted_stapled_assessed':'not_submitted',
      native_gui_acceptance:'NOT RUN',tcc_attribution:'NOT RUN'};
  }catch(error){
    // Preserve failed output for diagnostics; never identify it as a release.
    throw Error('macos_app_build_failed: '+error.message,{cause:error});
  }finally{fs.rmSync(buildRoot,{recursive:true,force:true})}
}
if(process.argv[1]&&fs.realpathSync(process.argv[1])===fs.realpathSync(fileURLToPath(import.meta.url))){
  const [configFile]=process.argv.slice(2);
  try{
    assert(configFile&&path.isAbsolute(configFile),'absolute_build_config_required');
    const receipt=buildMacApp(JSON.parse(fs.readFileSync(configFile,'utf8')));
    // Receipt remains outside the signed bundle; writing inside invalidates its seal.
    fs.writeFileSync(receipt.app+'.build.json',JSON.stringify(receipt,null,2)+'\n',{flag:'wx',mode:0o600});
    console.log(JSON.stringify(receipt));
  }catch(error){console.error('Styx macOS app: '+error.message);process.exitCode=2}
}
