import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';

test('AppKit update quit leaves the Swift Task before terminateLater waits', {skip:process.platform!=='darwin',timeout:30000}, t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-quit-handoff-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const main=path.join(root,'main.swift'),binary=path.join(root,'QuitHandoffProbe');
 fs.copyFileSync(fileURLToPath(new URL('./QuitHandoffProbe.swift',import.meta.url)),main);
 const compile=spawnSync('swiftc',['-target',`${process.arch==='arm64'?'arm64':'x86_64'}-apple-macosx13.0`,'-warnings-as-errors',fileURLToPath(new URL('../product-ui/ProductTermination.swift',import.meta.url)),main,'-o',binary],{encoding:'utf8',timeout:20000});
 assert.equal(compile.status,0,compile.stderr);
 const previous=spawnSync(binary,[],{encoding:'utf8',timeout:7000});
 assert.equal(previous.status,73,previous.stderr);assert.match(previous.stderr,/quit-task-timeout/);
 const fixed=spawnSync(binary,['--deferred'],{encoding:'utf8',timeout:7000});
 assert.equal(fixed.status,0,fixed.stderr);assert.match(fixed.stdout,/quit-admitted/);
});
