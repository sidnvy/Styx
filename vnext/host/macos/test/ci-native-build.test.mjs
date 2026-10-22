import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {fileURLToPath} from 'node:url';
import {macNativeSwiftSources,macSwiftBuildArguments} from '../../build-macos-app.mjs';
import {compileMacTestingApp} from '../ci-native-build.mjs';
const native=path.resolve(fileURLToPath(new URL('../',import.meta.url)));
test('product packaging and CI consume the complete shared native Swift source closure',()=>{
 const inputs=macNativeSwiftSources(),ui=path.join(native,'product-ui');
 assert.equal(inputs.source,path.join(native,'Styx.swift'));
 assert.deepEqual(inputs.additionalSources,[path.join(native,'BrandGlyph.swift'),...fs.readdirSync(ui).filter(name=>name.endsWith('.swift')).sort().map(name=>path.join(ui,name))]);
 assert.ok(inputs.additionalSources.some(file=>file.endsWith('/ProductModel.swift')));assert.ok(inputs.additionalSources.some(file=>file.endsWith('/ProductViews.swift')));
});
// Inject only subprocess execution and platform for this portable argv/source
// contract. A stub compiler is never recorded as native macOS acceptance.
test('CI copies main.swift, uses production Swift argv and provides real artwork without signing',t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-mac-ci-contract-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const output=path.join(root,'build with spaces'),sdkPath=path.join(root,'SDK'),calls=[];fs.mkdirSync(sdkPath);
 const run=(command,args,options)=>{calls.push({command,args:[...args],options});if(args[0]==='--sdk')return sdkPath+'\n';fs.writeFileSync(args[args.indexOf('-o')+1],'contract compiler fixture');};
 const result=compileMacTestingApp(output,{platform:'darwin',arch:'arm64',run}),inputs=macNativeSwiftSources();
 assert.deepEqual(fs.readFileSync(path.join(output,'main.swift')),fs.readFileSync(inputs.source));
 const expected=macSwiftBuildArguments({source:path.join(output,'main.swift'),additionalSources:inputs.additionalSources,output:result.binary,arch:'arm64',sdkPath,moduleCachePath:path.join(output,'module-cache')});expected.splice(1,0,'-D','STYX_TESTING');
 assert.deepEqual(calls.map(call=>call.command),['/usr/bin/xcrun','/usr/bin/xcrun']);assert.deepEqual(calls[1].args,expected);assert.equal(result.signing,'NOT RUN');assert.equal(result.tcc,'NOT RUN');
 assert.ok(fs.statSync(path.join(result.app,'Contents/Resources/brand/styx-icon-light-source.jpg')).size>1000);assert.ok(fs.readFileSync(path.join(result.app,'Contents/Info.plist'),'utf8').includes('app.styx.host'));
 assert.throws(()=>compileMacTestingApp(output,{platform:'darwin',run:()=>assert.fail('existing output must not compile')}),/fresh_absolute_native_ci_output_required/);
 const other=path.join(root,'other');assert.throws(()=>compileMacTestingApp(other,{platform:'linux',run:()=>assert.fail('non-native platform must not compile')}),/native_macos_compile_required/);assert.equal(fs.existsSync(other),false);
});
test('develop pushes compile before binary-dependent fixtures and retain the native owner lifetime gate',()=>{
 const workflow=fs.readFileSync(new URL('../../../../.github/workflows/styx-macos-app.yml',import.meta.url),'utf8');
 assert.match(workflow,/push:\s*\n\s*branches: \[develop\]/);assert.match(workflow,/paths: \['vnext\/\*\*'/);
 const compile=workflow.indexOf('node vnext/host/macos/ci-native-build.mjs'),fixtures=workflow.indexOf('node --test --test-concurrency=1 vnext/host/macos/test/*.test.mjs');assert.ok(compile>0&&fixtures>compile);
 assert.ok(workflow.slice(compile,fixtures).includes('STYX_NATIVE_TEST_BINARY='));assert.ok(workflow.includes('"$STYX_NATIVE_TEST_BINARY" --self-test'));assert.ok(workflow.includes('liveness-acceptance.py "$STYX_NATIVE_TEST_BINARY"'));
 assert.equal(workflow.includes('swiftc -D STYX_TESTING'),false);
});
