import fs from 'node:fs';
import path from 'node:path';

// Retain the designated identity previously assigned to Resources/runtime/node.
// Moving code into a standard helper bundle must not rotate its firewall identity.
export const MAC_CORE_IDENTIFIER='app.styx.host.code.13381750b855ab349e3d8ec3bc21f874';
export const MAC_CORE_NAME='Styx Core';
export const MAC_CORE_RELATIVE='Contents/Helpers/Styx Core.app';
export const MAC_CORE_EXECUTABLE=MAC_CORE_RELATIVE+'/Contents/MacOS/Styx Core';
const check=(ok,message)=>{if(!ok)throw Error(message)};
export function coreRuntimeExecutable(app){
 check(typeof app==='string'&&path.isAbsolute(app)&&path.normalize(app)===app&&path.basename(app)==='Styx.app','invalid_core_helper_app');
 const bundle=path.join(app,MAC_CORE_RELATIVE);
 // Legacy packages remain usable during upgrades. A malformed new helper must
 // fail closed instead of selecting another runtime with a different identity.
 const file=fs.lstatSync(bundle,{throwIfNoEntry:false})?path.join(app,MAC_CORE_EXECUTABLE):path.join(app,'Contents/Resources/runtime/node');
 const root=fs.realpathSync(app);
 let cursor=file;
 while(cursor!==app){check(!fs.lstatSync(cursor).isSymbolicLink(),'core_helper_redirect_forbidden');cursor=path.dirname(cursor)}
 check(fs.lstatSync(file).isFile()&&fs.realpathSync(file).startsWith(root+path.sep),'core_helper_regular_runtime_required');
 return file;
}
export function coreHelperInfoPlist({version,buildNumber}){
 check(typeof version==='string'&&/^\d+\.\d+\.\d+$/.test(version),'invalid_core_helper_version');
 check(typeof buildNumber==='string'&&/^\d+(?:\.\d+){0,2}$/.test(buildNumber),'invalid_core_helper_build');
 return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>${MAC_CORE_IDENTIFIER}</string>
<key>CFBundleName</key><string>${MAC_CORE_NAME}</string>
<key>CFBundleDisplayName</key><string>${MAC_CORE_NAME}</string>
<key>CFBundleExecutable</key><string>${MAC_CORE_NAME}</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>${version}</string>
<key>CFBundleVersion</key><string>${buildNumber}</string>
<key>LSUIElement</key><true/>
</dict></plist>\n`;
}

// This is the existing Node executable, not a proxy or a privileged service.
// The outer App still owns its Process and private startup pipe.
export function prepareCoreHelper({app,nodeBinary,version,buildNumber}){
 check(typeof app==='string'&&path.isAbsolute(app)&&path.normalize(app)===app&&path.basename(app)==='Styx.app','invalid_core_helper_app');
 check(typeof nodeBinary==='string'&&path.isAbsolute(nodeBinary),'invalid_core_helper_input');
 const input=fs.lstatSync(nodeBinary);
 check(input.isFile()&&!input.isSymbolicLink(),'core_helper_regular_input_required');
 const info=coreHelperInfoPlist({version,buildNumber});
 const bundle=path.join(app,MAC_CORE_RELATIVE),executable=path.join(app,MAC_CORE_EXECUTABLE);
 check(!fs.existsSync(bundle),'core_helper_destination_exists');
 fs.mkdirSync(path.dirname(executable),{recursive:true});
 fs.copyFileSync(nodeBinary,executable,fs.constants.COPYFILE_EXCL);fs.chmodSync(executable,0o755);
 fs.writeFileSync(path.join(bundle,'Contents/Info.plist'),info,{flag:'wx',mode:0o644});
 return{bundle,executable,identifier:MAC_CORE_IDENTIFIER};
}
