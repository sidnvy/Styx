import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {preparedPreviewInventory,verifyPreparedPreview,executeMacPreviewSigningPlan} from '../build-macos-preview.mjs';
import {macLocalSigningPlan} from '../build-macos-app.mjs';
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
function fixture(t){
 const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'styx-prepared-')));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const app=path.join(root,'image-root/Styx.app'),resources=path.join(app,'Contents/Resources'),bundle=path.join(resources,'host-bundle');fs.mkdirSync(bundle,{recursive:true});
 const {privateKey,publicKey}=generateKeyPairSync('ed25519'),bytes=Buffer.from('native compilation fixture');
 fs.writeFileSync(path.join(bundle,'node'),bytes);const manifest=JSON.stringify({schema:1,version:'0.3.0-test',platform:'darwin',arch:'x64',files:[{path:'node',size:bytes.length,sha256:hash(bytes),executable:true}]});
 fs.writeFileSync(path.join(bundle,'manifest.json'),manifest);fs.writeFileSync(path.join(bundle,'manifest.sig'),sign(null,Buffer.from(manifest),privateKey).toString('base64url'));
 fs.writeFileSync(path.join(resources,'publisher.pem'),publicKey.export({format:'pem',type:'spki'}));fs.writeFileSync(path.join(resources,'source-files.json'),JSON.stringify({revision:'a'.repeat(40)}));
 const metadata={schema:1,kind:'prepared_native_preview',delivery:'NOT FINALIZED',arch:'x64',sourceRevision:'a'.repeat(40),releaseVersion:'0.3.0-test',files:preparedPreviewInventory(app)};
 const receipt=path.join(root,'prepared-preview.json');fs.writeFileSync(receipt,JSON.stringify(metadata));return {root,app,resources,bundle,receipt,pin:hash(fs.readFileSync(receipt))};
}
test('transported native inventory is pinned and verifies Host using target arch, not signer arch',t=>{
 const f=fixture(t);assert.equal(verifyPreparedPreview(f.root,f.pin).metadata.arch,'x64');
 assert.throws(()=>verifyPreparedPreview(f.root,'0'.repeat(64)),/receipt_changed/);
 fs.appendFileSync(path.join(f.bundle,'node'),'changed');assert.throws(()=>verifyPreparedPreview(f.root,f.pin),/contents_changed/);
});
test('unlisted files and redirected directories cannot enter a prepared candidate',t=>{
 const f=fixture(t),extra=path.join(f.resources,'foreign');fs.writeFileSync(extra,'x');assert.throws(()=>verifyPreparedPreview(f.root,f.pin),/contents_changed/);fs.unlinkSync(extra);
 fs.renameSync(f.bundle,f.bundle+'.before');fs.symlinkSync(f.bundle+'.before',f.bundle,'junction');assert.throws(()=>verifyPreparedPreview(f.root,f.pin),/symlink_forbidden/);
});
test('real signing plan uses tuple command argv and stops immediately on failure',()=>{
 const localSigning={identitySha1:'c'.repeat(40),certificateSha256:'d'.repeat(64),keychain:'/private/build/keychain'};
 const app='/private/build/Styx.app',plan=macLocalSigningPlan({app,localSigning,files:[app+'/Contents/MacOS/Styx']}),seen=[];
 executeMacPreviewSigningPlan(plan,{run:(command,args)=>seen.push([command,args])});assert.deepEqual(seen,plan);
 let count=0;assert.throws(()=>executeMacPreviewSigningPlan(plan,{run:()=>{count++;throw Error('signature_denied')}}),/signature_denied/);assert.equal(count,1);
 assert.throws(()=>executeMacPreviewSigningPlan(['/usr/bin/codesign',['--verify']],{run:()=>assert.fail('malformed plan executed')}),/invalid_preview_signing_plan/);
});
test('existing-only signing cannot provision; session holds lock and stops once after builder failure',()=>{
 const script=fileURLToPath(new URL('../macos/run-local-signing.py',import.meta.url));
 execFileSync('python3',['-c',String.raw`
import importlib.util,json,pathlib,tempfile,fcntl,os,types
p=pathlib.Path(__import__('sys').argv[1]); spec=importlib.util.spec_from_file_location('session',p); m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
with tempfile.TemporaryDirectory() as temp:
 root=pathlib.Path(temp)/'identity'
 try: m.identity.prepare(root,existing_only=True);raise AssertionError('provisioned')
 except RuntimeError: pass
 assert not root.exists()
 root.mkdir(mode=0o700)
 identity={'identitySha1':'a'*40,'certificateSha256':'b'*64,'keychain':str(root/'styx-development.keychain-db')}
 (root/'identity.json').write_text(json.dumps(identity));(root/'identity.json').chmod(0o600)
 (root/'host-publisher-private.pem').write_text('private fixture');(root/'host-publisher-private.pem').chmod(0o600)
 config=root/'build.json';config.write_text(json.dumps({'preparedSource':str(root/'historical-prepared'),'localSigning':identity,'hostPublisher':{'mode':'persistent','privateKeyFile':str(root/'host-publisher-private.pem')}}))
 calls=[]
 def prepare(r,existing_only=False):
  assert r==root and existing_only
  with open(root/'signing-session.lock','r') as lock:
   try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);raise AssertionError('lock not held')
   except BlockingIOError: pass
  calls.append('prepare');return identity
 def run(args,check):
  assert calls==['prepare'] and args[1].endswith('build-macos-preview.mjs') and args[2]==str(config)
  calls.append('build');return types.SimpleNamespace(returncode=7)
 m.identity.prepare=prepare;m.subprocess.run=run
 assert m.run_session(root,config,pathlib.Path('/trusted/node'))==7
 assert calls==['prepare','build']
 with open(root/'signing-session.lock','r') as lock: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
`,script],{stdio:'pipe'});
});
