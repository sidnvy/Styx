import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {prepareCoreHelper,coreRuntimeExecutable,MAC_CORE_IDENTIFIER,MAC_CORE_RELATIVE,MAC_CORE_EXECUTABLE} from '../core-helper.mjs';
import {macLocalSigningPlan,macAdhocSigningPlan} from '../../build-macos-app.mjs';
function fixture(t){const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'styx-core-helper-')));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));const app=path.join(root,'Styx.app'),nodeBinary=path.join(root,'input-node');fs.mkdirSync(app);fs.writeFileSync(nodeBinary,'signed-runtime-fixture');return{app,nodeBinary,version:'0.3.0',buildNumber:'1015'}}
test('standard helper bundles the actual runtime and preserves the old designated identifier',t=>{
 const f=fixture(t),result=prepareCoreHelper(f);
 assert.equal(result.executable,path.join(f.app,MAC_CORE_EXECUTABLE));
 assert.equal(coreRuntimeExecutable(f.app),result.executable);
 assert.deepEqual(fs.readFileSync(result.executable),fs.readFileSync(f.nodeBinary));
 assert.equal(MAC_CORE_IDENTIFIER,'app.styx.host.code.'+createHash('sha256').update('Contents/Resources/runtime/node').digest('hex').slice(0,32));
 const plist=fs.readFileSync(path.join(result.bundle,'Contents/Info.plist'),'utf8');
 assert.match(plist,/<key>CFBundleName<\/key><string>Styx Core<\/string>/);
 assert.match(plist,/<key>CFBundleExecutable<\/key><string>Styx Core<\/string>/);
 assert.throws(()=>prepareCoreHelper(f),/destination_exists/);
});
test('legacy updater selection works but malformed new helper cannot fall back or redirect',t=>{
 const f=fixture(t),legacy=path.join(f.app,'Contents/Resources/runtime/node');fs.mkdirSync(path.dirname(legacy),{recursive:true});fs.copyFileSync(f.nodeBinary,legacy);
 assert.equal(coreRuntimeExecutable(f.app),legacy);
 const helper=prepareCoreHelper(f);fs.unlinkSync(helper.executable);fs.symlinkSync(f.nodeBinary,helper.executable);
 assert.throws(()=>coreRuntimeExecutable(f.app),/redirect_forbidden/);
 fs.unlinkSync(helper.executable);assert.throws(()=>coreRuntimeExecutable(f.app),/ENOENT/);
});
test('nested helper is sealed before outer app and uses the same certificate requirement as old Node',()=>{
 const app='/build/Styx.app',exe=path.join(app,MAC_CORE_EXECUTABLE),bundle=path.join(app,MAC_CORE_RELATIVE),main=app+'/Contents/MacOS/Styx';
 const localSigning={identitySha1:'a'.repeat(40),certificateSha256:'b'.repeat(64),keychain:'/private/signing.keychain-db'};
 const old=macLocalSigningPlan({app,files:[app+'/Contents/Resources/runtime/node'],localSigning});
 const plan=macLocalSigningPlan({app,files:[main,exe],localSigning});
 const signing=plan.filter(([,args])=>args.includes('--sign')).map(([,args])=>args);
 assert.deepEqual(signing.map(a=>a.at(-1)),[exe,bundle,main,app]);
 const requirement=args=>args[args.indexOf('--requirements')+1];
 assert.equal(requirement(signing[0]),requirement(old.find(([,a])=>a.includes('--sign'))[1]));
 assert.equal(requirement(signing[0]),requirement(signing[1]));
 const adhoc=macAdhocSigningPlan({app,files:[main,exe]}).filter(([,a])=>a.includes('--sign')).map(([,a])=>a.at(-1));
 assert.deepEqual(adhoc,[exe,bundle,main,app]);
});
