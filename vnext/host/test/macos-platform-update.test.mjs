import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {appInfoPlist,macSwiftBuildArguments} from '../build-macos-app.mjs';
import {normalizeMacPlatformUpdate,stageMacSparkle,isSparkleFrameworkLink,sparkleDistributionSigningPlan} from '../macos/platform-update/sparkle-build.mjs';
const config={feedUrl:'https://updates.example.org/styx/appcast.xml',publicEdKey:Buffer.alloc(32,1).toString('base64'),sparkleArchive:'/private/build/Sparkle.tar.xz'};
test('unconfigured builds have no feed, while configured builds require a release number and HTTPS',()=>{
 assert.equal(normalizeMacPlatformUpdate(undefined),null);
 assert.equal(appInfoPlist('0.3.0').includes('SUFeedURL'),false);
 const options={app:'/build/Styx.app',updateRelease:true};
 assert.equal(normalizeMacPlatformUpdate(config,options).isolatedProbe,false);
 const plist=appInfoPlist('0.3.0',{...options,buildNumber:'1008',platformUpdate:config});
 assert.match(plist,/<key>SUFeedURL<\/key><string>https:\/\/updates.example.org\/styx\/appcast.xml<\/string>/);
 assert.match(plist,/<key>SUVerifyUpdateBeforeExtraction<\/key><true\/>/);
 assert.throws(()=>normalizeMacPlatformUpdate(config,{...options,updateRelease:false}),/numbered_release/);
 for(const change of [{feedUrl:'http://updates.example.org/feed'},{feedUrl:'https://user:pass@updates.example.org/feed'},{feedUrl:'https://updates.example.org/feed?token=secret'},{publicEdKey:'bad'},{sparkleArchive:'relative'},{isolatedProbe:'true'},{extra:true}])assert.throws(()=>normalizeMacPlatformUpdate({...config,...change},options));
});
test('loopback is allowed only for explicitly isolated temporary App builds',()=>{
 const probe={...config,feedUrl:'http://127.0.0.1:49256/appcast.xml',isolatedProbe:true};
 assert.equal(normalizeMacPlatformUpdate(probe,{app:'/private/tmp/styx-platform-update-test/Styx.app',updateRelease:true}).isolatedProbe,true);
 for(const app of ['/Applications/Styx.app','/private/tmp/other/Styx.app','/private/tmp/styx-platform-update-test/../../Styx.app'])assert.throws(()=>normalizeMacPlatformUpdate(probe,{app,updateRelease:true}),/isolated_platform_update_app_required/);
 assert.throws(()=>normalizeMacPlatformUpdate({...probe,feedUrl:'http://192.168.1.2:49256/appcast.xml'},{app:'/private/tmp/styx-platform-update-test/Styx.app',updateRelease:true}),/https_required/);
});
test('unverified framework bytes are rejected before extraction or any executable runs',t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-sparkle-input-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));const archive=path.join(root,'archive');fs.writeFileSync(archive,'wrong bytes');
 assert.throws(()=>stageMacSparkle({...config,sparkleArchive:archive},{app:path.join(root,'Styx.app'),buildRoot:root,run:()=>assert.fail('unverified bytes must not execute')}),/sparkle_archive_checksum_mismatch/);
});
test('only canonical Sparkle links stay within the copied framework',t=>{
 const app=fs.mkdtempSync(path.join(os.tmpdir(),'styx-sparkle-links-'));t.after(()=>fs.rmSync(app,{recursive:true,force:true}));const framework=path.join(app,'Contents/Frameworks/Sparkle.framework');fs.mkdirSync(path.join(framework,'Versions/B'),{recursive:true});fs.writeFileSync(path.join(framework,'Versions/B/Sparkle'),'fixture');fs.symlinkSync('B',path.join(framework,'Versions/Current'));fs.symlinkSync('Versions/Current/Sparkle',path.join(framework,'Sparkle'));
 assert.equal(isSparkleFrameworkLink(app,path.join(framework,'Sparkle')),true);fs.unlinkSync(path.join(framework,'Sparkle'));fs.symlinkSync('/tmp',path.join(framework,'Sparkle'));assert.throws(()=>isSparkleFrameworkLink(app,path.join(framework,'Sparkle')),/link_changed/);
 assert.equal(isSparkleFrameworkLink(app,path.join(app,'unrecognized')),false);
});
test('Sparkle linking and nested signing preserve platform protections and XPC entitlements',()=>{
 const args=macSwiftBuildArguments({source:'/src/main.swift',output:'/build/Styx.app/Contents/MacOS/Styx',frameworkSearchPath:'/build/Styx.app/Contents/Frameworks'});assert.ok(args.includes('Sparkle'));assert.ok(args.includes('@executable_path/../Frameworks'));
 const plan=sparkleDistributionSigningPlan({app:'/build/Styx.app',identity:'Developer ID Application: Example (A123456789)'});
 assert.ok(plan[0][1].at(-1).endsWith('Downloader.xpc'));assert.ok(plan.at(-1)[1].at(-1).endsWith('Sparkle.framework'));
 for(const [,args] of plan){assert.ok(args.includes('--preserve-metadata=entitlements'));assert.ok(args.includes('runtime'));assert.equal(args.includes('--deep'),false)}
});
