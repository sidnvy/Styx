import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash,generateKeyPairSync} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {execFileSync} from 'node:child_process';
import {buildLinuxCli,cliProductSource} from '../build-linux-cli.mjs';
test('CLI source closure excludes mutable user state, native apps and test fixtures',()=>{
 for(const n of ['onboarding/core.mjs','gateway/conversation-owners.mjs','onboarding/tunnel-context.mjs','host/linux-service.mjs','packages/styx-browser-provider/login-state.mjs',...['styx-native-onboarding','styx-cli','styx-browser','styx-computer-use'].map(name=>'plugin/skills/'+name+'/SKILL.md'),'assets/brand/styx-logo.png'])assert.equal(cliProductSource(n),true,n);
 for(const n of ['deployment.json','host.json','publisher-key.pem','host/test/fixture.mjs','packages/styx-exec-adapter/.runtime/codex','host/windows/Styx.cs','onboarding/test/keys.json','.git/config'])assert.equal(cliProductSource(n),false,n);
});
test('CLI builder rejects implicit paths without side effects',()=>{
 assert.throws(()=>buildLinuxCli({destination:'relative'}),process.platform==='linux'&&process.arch==='x64'?/absolute_cli_paths_required/:/linux_x64_native_build_required/);
});
test('portable CLI boots same Core and an independent signed Gateway without Host artifacts',{
 skip:process.platform!=='linux'||process.arch!=='x64'||!process.env.STYX_TEST_LINUX_NODE,timeout:60000
},async t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-cli-build-'));fs.chmodSync(root,0o700);t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const {privateKey}=generateKeyPairSync('ed25519');const key=path.join(root,'key.pem');fs.writeFileSync(key,privateKey.export({type:'pkcs8',format:'pem'}),{mode:0o600});
 const output=path.join(root,'preview');const result=buildLinuxCli({destination:output,version:'0.3.0-test',privateKeyFile:key,nodeBinary:process.env.STYX_TEST_LINUX_NODE});
 assert.equal(result.hostBundleIncluded,false);assert.equal(result.identityCreated,false);
 assert.match(fs.readFileSync(path.join(output,'README.md'),'utf8'),/Gateway-only/);
 assert.equal(fs.existsSync(path.join(output,'host-bundle')),false);assert.equal(fs.existsSync(path.join(output,'key.pem')),false);
 const cli=(...args)=>JSON.parse(execFileSync(path.join(output,'styx'),args,{encoding:'utf8',timeout:20000}));
 assert.ok(cli('help').commands.includes('plan STATE'));
 const api=await import(pathToFileURL(path.join(output,'app/plugin/package.mjs'))),connection={tunnelId:'tunnel_'+'a'.repeat(32)},receipt={version:1,connection,independentStyx:true,freshConnection:true,verifiedAt:new Date().toISOString(),serverName:'styx-vnext',tools:['list_execution_environments','get_execution_environment_status','exec_command','write_stdin'],method:'authenticated-mcp-discovery'};
 const generated=api.buildPackageFiles({connection},receipt);assert.deepEqual(generated.files.filter(file=>file.path.startsWith('skills/')).map(file=>file.path).sort(),['styx-native-onboarding','styx-cli','styx-browser','styx-computer-use'].map(name=>'skills/'+name+'/SKILL.md').sort());
 const manifest=JSON.parse(fs.readFileSync(path.join(output,'gateway-bundle/manifest.json')));
 for(const name of ['gateway/conversation-owners.mjs','onboarding/tunnel-context.mjs']){assert.ok(manifest.files.some(entry=>entry.path==='app/'+name),name);assert.deepEqual(fs.readFileSync(path.join(output,'app',name)),fs.readFileSync(path.join(output,'gateway-bundle/app',name)));}
 for(const entry of manifest.files){const bytes=fs.readFileSync(path.join(output,'gateway-bundle',entry.path));assert.equal(bytes.length,entry.size,entry.path);assert.equal(createHash('sha256').update(bytes).digest('hex'),entry.sha256,entry.path);}

 const input=path.join(root,'input.json'),state=path.join(root,'state');
 const config={schema:1,mode:'create-local',gateway:{url:'https://127.0.0.1:18292',openssl:'/usr/bin/openssl',runtime:{bundle:path.join(output,'gateway-bundle'),publisherKeyFile:path.join(output,'publisher.pem'),publisherSha256:result.publisherSha256,baseDir:path.join(root,'gateway-runtime')}}};
 fs.writeFileSync(input,JSON.stringify(config),{mode:0o600});
 const created=cli('create',input,state),plan=cli('plan',state),status=cli('status',state);
 assert.equal(created.roles.host,'disabled');assert.equal(created.roles.exec,'disabled');assert.equal(created.roles.computer,'disabled');assert.deepEqual(plan.roles,status.roles);
 assert.deepEqual(created.steps.map(x=>x.id),['gateway.runtime.prepare','gateway.prepare','gateway.start','gateway.verify']);
 assert.throws(()=>buildLinuxCli({destination:output,version:'0.3.0-test',privateKeyFile:key,nodeBinary:process.env.STYX_TEST_LINUX_NODE}),/fresh_cli_output_required/);
 // Package is portable, including when its directory contains spaces.
 const renamed=path.join(root,'portable preview');fs.renameSync(output,renamed);
 assert.ok(JSON.parse(execFileSync(path.join(renamed,'styx'),['help'],{encoding:'utf8'})).commands.length>10);
});
