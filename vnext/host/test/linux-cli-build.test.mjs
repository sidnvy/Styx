import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {generateKeyPairSync} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {buildLinuxCli,cliProductSource} from '../build-linux-cli.mjs';
test('CLI source closure excludes mutable user state, native apps and test fixtures',()=>{
 for(const n of ['onboarding/core.mjs','host/linux-service.mjs','packages/styx-browser-provider/login-state.mjs','plugin/skills/styx-native-onboarding/SKILL.md','assets/brand/styx-logo.png'])assert.equal(cliProductSource(n),true,n);
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
 assert.equal(fs.existsSync(path.join(output,'host-bundle')),false);assert.equal(fs.existsSync(path.join(output,'key.pem')),false);
 const cli=(...args)=>JSON.parse(execFileSync(path.join(output,'styx'),args,{encoding:'utf8',timeout:20000}));
 assert.ok(cli('help').commands.includes('plan STATE'));
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
