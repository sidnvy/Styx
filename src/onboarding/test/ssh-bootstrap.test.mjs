import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {generateKeyPairSync} from 'node:crypto';
import {sshBootstrapPlan,createSshPairingTransport} from '../ssh-bootstrap.mjs';
const posixTest=(name,fn)=>test(name,{skip:process.platform==='win32'?'POSIX executable fixture; native Windows SSH not asserted':false},fn);
function fixture(t){
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'styx-ssh-owner-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const known=path.join(dir,'known_hosts');fs.writeFileSync(known,'existing trusted fixture key\n',{mode:0o600});
 const binary=path.join(dir,'ssh-fixture');
 fs.writeFileSync(binary,'#!/usr/bin/env node\nprocess.stderr.write("INVITATION_SECRET_DO_NOT_LOG");process.exit(255);\n',{mode:0o700});
 const target={platform:'linux',host:'known.example',user:'sid',port:22,knownHostsFile:known,sshBinary:binary,nodeBinary:'/opt/styx/node',installRoot:'/opt/styx',publisherPublicKey:generateKeyPairSync('ed25519').publicKey.export({format:'pem',type:'spki'})};
 const config={gateway_url:'https://gateway.example',label:'owner',cwd:'/home/sid',shell:'/bin/sh',computer_requested:false};
 return {dir,target,config};
}
posixTest('SSH pins existing known_hosts, disables config hooks/password prompts/forwarding and never puts invitation in argv',t=>{
 const f=fixture(t),plan=sshBootstrapPlan(f.target);
 assert.equal(plan.command,f.target.sshBinary);
 for(const item of ['StrictHostKeyChecking=yes','BatchMode=yes','ForwardAgent=no','PermitLocalCommand=no','ClearAllForwardings=yes','ControlMaster=no','ControlPath=none','NumberOfPasswordPrompts=0'])assert.ok(plan.args.includes(item));
 assert.ok(plan.args.includes('UserKnownHostsFile='+f.target.knownHostsFile));assert.deepEqual(plan.args.slice(0,3),['-F','/dev/null','-T']);
 assert.ok(!plan.args.join(' ').includes('accept-new'));assert.ok(!plan.args.join(' ').includes('StrictHostKeyChecking=no'));
});
posixTest('host/user/port injection and uncontrolled known_hosts are refused before spawn',t=>{
 const f=fixture(t);
 for(const patch of [{host:'-oProxyCommand=evil'},{host:'host;touch /tmp/evil'},{user:'sid;evil'},{port:'22 -o bad'},{nodeBinary:'relative/node'},{installRoot:'/opt/../foreign'},{platform:'win32'}])assert.throws(()=>sshBootstrapPlan({...f.target,...patch}));
 fs.chmodSync(f.target.knownHostsFile,0o666);assert.throws(()=>sshBootstrapPlan(f.target),/owner_controlled/);
});
posixTest('remote path shell metacharacters are quoted as one literal rather than executable syntax',t=>{
 const f=fixture(t);const payload="/opt/space node'; touch HACK; echo '";
 const plan=sshBootstrapPlan({...f.target,nodeBinary:payload});
 const command=plan.args.at(-1);assert.ok(command.startsWith("exec '/opt/space node'\\''; touch HACK; echo '\\''' --input-type=module -e '"));
});
posixTest('SSH remote refusal is fixed and never echoes raw stderr/invitation',async t=>{
 const f=fixture(t),transport=createSshPairingTransport(f.target,f.config);
 await assert.rejects(transport.request('INVITATION_SECRET_DO_NOT_LOG'),error=>error.message==='ssh_pairing_remote_failed');
});
posixTest('public reply is bounded and schema filtered, arbitrary credential fields never escape',async t=>{
 const f=fixture(t);const id='styx-'+'a'.repeat(24),fp='b'.repeat(64),request='c'.repeat(32);
 const argsFile=path.join(f.dir,'argv.json');
 const reply={device_id:id,fingerprint:fp,request_id:request,status:'pending',platform:'linux',private_key:'SECRET_KEY',token:'SECRET_TOKEN'};
 fs.writeFileSync(f.target.sshBinary,'#!/usr/bin/env node\nconst fs=require("node:fs");fs.writeFileSync('+JSON.stringify(argsFile)+',JSON.stringify(process.argv.slice(2)));let input="";process.stdin.on("data",d=>input+=d);process.stdin.on("end",()=>process.stdout.write('+JSON.stringify(JSON.stringify(reply))+'));\n',{mode:0o700});
 const transport=createSshPairingTransport(f.target,f.config);const result=await transport.request('SECRET_INVITATION_IN_STDIN');
 assert.equal(result.fingerprint,fp);assert.ok(!JSON.stringify(result).includes('SECRET'));assert.ok(!fs.readFileSync(argsFile,'utf8').includes('SECRET_INVITATION_IN_STDIN'));
 fs.writeFileSync(f.target.sshBinary,'#!/usr/bin/env node\nprocess.stdout.write("x".repeat(17000));\n',{mode:0o700});
 await assert.rejects(transport.request('secret'),/ssh_pairing_reply_limit/);
});
posixTest('missing signed installation or runtime cannot silently become an arbitrary remote installer',async t=>{
 const f=fixture(t);assert.throws(()=>createSshPairingTransport({...f.target,publisherPublicKey:undefined},f.config));
 const privateKey=generateKeyPairSync('ed25519').privateKey.export({format:'pem',type:'pkcs8'});assert.throws(()=>createSshPairingTransport({...f.target,publisherPublicKey:privateKey},f.config),/trusted_publisher_public_key_required/);
 assert.throws(()=>createSshPairingTransport({...f.target,nodeBinary:undefined},f.config));
 const plan=sshBootstrapPlan(f.target);assert.ok(plan.args.at(-1).includes('activeRelease'));assert.ok(!plan.args.at(-1).includes('curl '));assert.ok(!plan.args.at(-1).includes('wget '));
});
