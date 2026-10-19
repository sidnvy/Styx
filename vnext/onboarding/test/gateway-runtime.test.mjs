import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {generateKeyPairSync,sign,createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {buildGatewayRuntimeRelease,prepareGatewayRuntime,readGatewayRuntime} from '../gateway-runtime.mjs';

const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const node=process.platform==='win32'?'node.exe':'node';
function fixture(t,{real=false}={}){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-gateway-runtime-'));fs.chmodSync(root,0o700);t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const keys=generateKeyPairSync('ed25519'),priv=path.join(root,'sign.pem'),pub=path.join(root,'public.pem');
 fs.writeFileSync(priv,keys.privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o600});fs.writeFileSync(pub,keys.publicKey.export({format:'pem',type:'spki'}),{mode:0o600});
 const binary=path.join(root,node),license=path.join(root,'LICENSE');
 if(real)fs.copyFileSync(process.execPath,binary);else fs.writeFileSync(binary,'signed-runtime-fixture\n');
 fs.writeFileSync(license,'Fixture license; not a redistributed runtime artifact.\n');
 const bundle=path.join(root,'bundle'),built=buildGatewayRuntimeRelease({destination:bundle,version:'1.0.0-runtime-test',privateKeyFile:priv,nodeBinary:binary,nodeLicenseFile:license});
 const config={bundle,publisherKeyFile:pub,publisherSha256:built.publisherSha256,baseDir:path.join(root,'gateway-runtime')};
 return {root,keys,bundle,config,built};
}
function resign(f,mutate){
 const file=path.join(f.bundle,'manifest.json'),manifest=JSON.parse(fs.readFileSync(file,'utf8'));mutate(manifest);
 const raw=JSON.stringify(manifest)+'\n';fs.writeFileSync(file,raw);fs.writeFileSync(path.join(f.bundle,'manifest.sig'),sign(null,Buffer.from(raw),f.keys.privateKey).toString('base64url'));
}
test('independent signed Gateway runtime creates no Host identity, Exec, Cua or service',t=>{
 const f=fixture(t),result=prepareGatewayRuntime(f.config);
 assert.equal(result.status,'gateway_runtime_prepared');assert.equal(result.version,f.built.version);assert.equal(result.manifestSha256,f.built.manifestSha256);
 const release=path.join(result.installRoot,'releases',result.version);
 assert.deepEqual(fs.readdirSync(path.join(release,'bin')),[node]);
 for(const filename of ['device','enrollment.json','service.json','host.json','codex-home','work'])assert.equal(fs.existsSync(path.join(f.config.baseDir,filename)),false);
 const receipt=JSON.parse(fs.readFileSync(path.join(f.config.baseDir,'runtime-receipt.json'),'utf8'));
 assert.equal(receipt.exec,'NOT INSTALLED');assert.equal(receipt.cua,'NOT INSTALLED');assert.equal(receipt.service,'NOT INSTALLED');
 assert.equal(JSON.parse(fs.readFileSync(path.join(f.config.baseDir,'runtime-state.json'),'utf8')).status,'prepared');
 assert.equal(readGatewayRuntime(f.config).nodeBinary,result.nodeBinary);
 assert.throws(()=>prepareGatewayRuntime(f.config),/gateway_runtime_directory_already_exists/);
});
test('publisher mismatch and tampered source fail before creating installation',t=>{
 const f=fixture(t);assert.throws(()=>prepareGatewayRuntime({...f.config,publisherSha256:'0'.repeat(64)}),/publisher_fingerprint_mismatch/);
 assert.equal(fs.existsSync(f.config.baseDir),false);
 fs.appendFileSync(path.join(f.bundle,'bin',node),'unsigned change');
 assert.throws(()=>prepareGatewayRuntime(f.config),/release_file_metadata_mismatch|release_file_hash_mismatch/);
 assert.equal(fs.existsSync(f.config.baseDir),false);
});
test('a correctly signed Host payload cannot be installed as a Gateway-only runtime',t=>{
 const f=fixture(t),filename='bin/'+(process.platform==='win32'?'codex.exe':'codex'),bytes=Buffer.from('host-exec-fixture');fs.writeFileSync(path.join(f.bundle,filename),bytes);
 resign(f,m=>m.files.push({path:filename,sha256:hash(bytes),size:bytes.length,executable:true}));
 assert.throws(()=>prepareGatewayRuntime(f.config),/gateway_runtime_contains_host_or_unknown_payload/);assert.equal(fs.existsSync(f.config.baseDir),false);
});
test('runtime must explicitly carry an executable signed Node, with no ambient Node fallback',t=>{
 const f=fixture(t);resign(f,m=>m.files.find(e=>e.path==='bin/'+node).executable=false);
 assert.throws(()=>prepareGatewayRuntime(f.config),/signed_gateway_node_required/);assert.equal(fs.existsSync(f.config.baseDir),false);
});
test('read-only inspection rejects changed active runtime and publisher identity',t=>{
 const f=fixture(t),result=prepareGatewayRuntime(f.config),bytes=fs.readFileSync(result.nodeBinary);
 fs.appendFileSync(result.nodeBinary,'unsigned');assert.throws(()=>readGatewayRuntime(f.config),/service_node_hash_mismatch/);
 fs.writeFileSync(result.nodeBinary,bytes);
 fs.writeFileSync(result.publisherKeyFile,generateKeyPairSync('ed25519').publicKey.export({format:'pem',type:'spki'}));
 assert.throws(()=>readGatewayRuntime(f.config),/publisher_fingerprint_mismatch/);
});
test('installed Node and trust survive installer process exit and unavailable source bundle',t=>{
 const f=fixture(t,{real:true}),result=prepareGatewayRuntime(f.config),configFile=path.join(f.root,'runtime-config.json');
 fs.writeFileSync(configFile,JSON.stringify(f.config),{mode:0o600});fs.rmSync(f.bundle,{recursive:true});fs.unlinkSync(f.config.publisherKeyFile);
 const entry=fileURLToPath(new URL('../gateway-runtime.mjs',import.meta.url));
 const observed=JSON.parse(execFileSync(result.nodeBinary,[entry,'status',configFile],{encoding:'utf8',timeout:10000}));
 assert.equal(observed.status,'gateway_runtime_verified');assert.equal(observed.manifestSha256,result.manifestSha256);
 assert.equal(execFileSync(result.nodeBinary,['--version'],{encoding:'utf8',timeout:10000}),process.version+'\n');
});
