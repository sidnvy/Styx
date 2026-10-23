import test from 'node:test';
import assert from 'node:assert/strict';
import {macNativeAppRequirement,verifiedMacNativeLauncher,macNativeHostArguments,macHostExecutionIdentity} from '../macos-native-launcher.mjs';
const nativeApp={path:'/Applications/Styx.app',teamID:'ABCDEFGHIJ'};
const executable='/Applications/Styx.app/Contents/MacOS/Styx';
const options={executable,teamID:nativeApp.teamID,nodeBinary:'/private/Styx Host/node',installRoot:'/private/Styx Host',hostConfigFile:'/private/Host 用户 &.json',trustPublicKeyFile:'/private/publisher.pem'};
const filesystem={
 lstatSync:file=>({isSymbolicLink:()=>false,isDirectory:()=>file!==executable,isFile:()=>file===executable}),
 realpathSync:file=>file,
 accessSync:()=>{}
};
test('native supervisor only accepts an explicit stable fixed App and team; no ad-hoc identity',()=>{
 assert.match(macNativeAppRequirement(nativeApp),/anchor apple generic and identifier "app\.styx\.host"/);
 for(const value of [undefined,{},[],{...nativeApp,path:'/tmp/Styx.app'},{...nativeApp,teamID:'adhoc'},{...nativeApp,teamID:'ABCDEFGHIJ" or true'},{...nativeApp,cdhash:'abc'}])assert.throws(()=>macNativeAppRequirement(value));
});
test('signature adapter verifies a fixed team-bound requirement and propagates no private data',()=>{
 const calls=[];
 assert.equal(verifiedMacNativeLauncher(nativeApp,{filesystem,run:(command,args)=>{calls.push([command,args]);return ''}}),executable);
 assert.deepEqual(calls,[['/usr/bin/codesign',['--verify','--deep','--strict','-R',macNativeAppRequirement(nativeApp),nativeApp.path]]]);
 assert.throws(()=>verifiedMacNativeLauncher(nativeApp,{filesystem,run:()=>{throw Error('signature team mismatch')}}),/native_app_signature_invalid/);
 let ran=false;
 assert.throws(()=>verifiedMacNativeLauncher(nativeApp,{filesystem:{...filesystem,realpathSync:()=>'/tmp/redirected'},run:()=>{ran=true}}),/native_app_redirect_refused/);
 assert.equal(ran,false);
 assert.throws(()=>verifiedMacNativeLauncher(nativeApp,{filesystem:{...filesystem,lstatSync:()=>({isSymbolicLink:()=>true})},run:()=>{ran=true}}),/native_app_regular_bundle_required/);
 assert.equal(ran,false);
});
test('native Host argv preserves literal paths and rejects unsigned external runtimes',()=>{
 assert.deepEqual(macNativeHostArguments(options),[executable,'--host-service','ABCDEFGHIJ',options.nodeBinary,options.installRoot,options.hostConfigFile,options.trustPublicKeyFile]);
 for(const bad of [{nodeBinary:'/usr/local/bin/node'},{nodeBinary:'/private/Styx Host/../node'},{hostConfigFile:'relative.json'},{trustPublicKeyFile:'/private/pub\nkey'},{executable:'/tmp/Styx.app/Contents/MacOS/Styx'}])assert.throws(()=>macNativeHostArguments({...options,...bad}));
});
test('native configuration never projects measured TCC attribution or desktop readiness',()=>{
 assert.deepEqual(macHostExecutionIdentity(),{launcher:'legacy_node',nativeResponsibility:'not_established',tccAttribution:'NOT RUN'});
 assert.deepEqual(macHostExecutionIdentity({nativeApp}),{launcher:'signed_native_supervisor',bundleID:'app.styx.host',teamID:nativeApp.teamID,nativeResponsibility:'configured_unverified',tccAttribution:'NOT RUN'});
});

test('every native argument path rejects controls and noncanonical spelling without executing a child',()=>{
 for(const key of ['nodeBinary','installRoot','hostConfigFile','trustPublicKeyFile']){
  for(const invalid of ['','relative/path','/private/../outside','/private/./file','/private//file','/private/file\0','/private/file\r','/private/file\n','/private/file\t','/private/file\u007f','/private/file\u0085','/private/file\ufffe','/private/file\uffff'])assert.throws(()=>macNativeHostArguments({...options,[key]:invalid}),key+': '+JSON.stringify(invalid));
 }
 for(const teamID of ['ABCDEFGHIJ\n','ABCDEFGHIJ\r','ABCDEFGHIJ\0','ＡＢＣＤＥＦＧＨＩＪ'])assert.throws(()=>macNativeHostArguments({...options,teamID}));
 assert.throws(()=>macNativeHostArguments({...options,nodeBinary:options.installRoot+'-other/node'}),/native_launcher_signed_node_required/);
});
