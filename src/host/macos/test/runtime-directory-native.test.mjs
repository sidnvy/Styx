import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';

test('Mac runtime recovers a dead embedded daemon socket without replacing a live owner', {skip:process.platform!=='darwin',timeout:60000}, t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-runtime-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const source=fs.readFileSync(new URL('../Styx.swift',import.meta.url),'utf8');
 const start=source.indexOf('enum HostError:'),end=source.indexOf('// Pinned official Cua');
 assert.ok(start>=0&&end>start);
 const runtime=path.join(root,'RuntimeDirectory.swift'),binary=path.join(root,'RuntimeDirectoryProbe');
 fs.writeFileSync(runtime,'import Foundation\nimport Darwin\n'+source.slice(start,end));
 const args=['-target',`${process.arch==='arm64'?'arm64':'x86_64'}-apple-macosx13.0`,'-warnings-as-errors'];
 if(process.env.STYX_SWIFT_MODULE_CACHE)args.push('-module-cache-path',process.env.STYX_SWIFT_MODULE_CACHE);
 args.push(runtime,fileURLToPath(new URL('./RuntimeDirectoryProbe.swift',import.meta.url)),'-o',binary);
 const compile=spawnSync('swiftc',args,{encoding:'utf8',timeout:45000});
 assert.equal(compile.status,0,compile.stderr);
 const result=spawnSync(binary,[path.join(root,'runtime')],{encoding:'utf8',timeout:5000});
 assert.equal(result.status,0,result.stderr);
 assert.match(result.stdout,/PASS stale socket recovery; live listener, live child and exclusive owner preserved/);
});
