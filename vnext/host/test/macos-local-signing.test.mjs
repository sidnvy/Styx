import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {createHash,X509Certificate} from 'node:crypto';
import {localCertificatePin,readLocalCertificatePin,verifyLocalCertificate} from '../macos-local-signing.mjs';
import {verifyMacPreviewApp} from '../macos-preview-trust.mjs';
import {previewSigningIdentity} from '../macos/setup-launcher.mjs';

test('local preview verifies stable certificate requirement plus both public certificate hashes', {skip:process.platform==='win32'},t=>{
 const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'styx-local-signing-test-')));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const app=path.join(root,'Styx.app'),resources=path.join(app,'Contents/Resources');fs.mkdirSync(resources,{recursive:true});
 execFileSync('/usr/bin/openssl',['req','-new','-newkey','rsa:2048','-nodes','-x509','-days','1','-subj','/CN=Isolated Local Signing Test','-keyout',path.join(root,'private.pem'),'-out',path.join(root,'certificate.pem')],{stdio:'pipe'});
 const raw=new X509Certificate(fs.readFileSync(path.join(root,'certificate.pem'))).raw;
 const pin={schema:1,certificateSha1:createHash('sha1').update(raw).digest('hex'),certificateSha256:createHash('sha256').update(raw).digest('hex')};
 fs.writeFileSync(path.join(resources,'local-signing.json'),JSON.stringify(pin));
 const cdhash='b'.repeat(40);let unstable=false,adhoc=false;
 const run=(_command,args)=>{
  const extraction=args.find(arg=>arg.startsWith('--extract-certificates='));if(extraction)fs.writeFileSync(extraction.slice('--extract-certificates='.length)+'0',raw);
  if(args.includes('-r-'))return{status:0,stderr:'# designated => '+(unstable?'cdhash H"'+cdhash+'"':`identifier "app.styx.host" and certificate leaf = H"${pin.certificateSha1}"`)};
  return{status:0,stderr:`Identifier=app.styx.host\n${adhoc?'Signature=adhoc':'Authority=Isolated Local Signing Test'}\nCDHash=${cdhash}\n`};
 };
 assert.deepEqual(readLocalCertificatePin(app),pin);
 assert.deepEqual(verifyLocalCertificate(app,pin,{run}),pin);
 const registration={path:app,cdhash,certificateSha1:pin.certificateSha1,certificateSha256:pin.certificateSha256};
 assert.equal(verifyMacPreviewApp(registration,{platform:'darwin',run}).trust,'local_certificate_preview_not_notarized');
 // A recorded CDHash is an observation, not the identity for certificate mode.
 assert.equal(verifyMacPreviewApp({...registration,cdhash:'c'.repeat(40)},{platform:'darwin',run}).cdhash,cdhash);
 assert.deepEqual(previewSigningIdentity({app},{run}),registration);
 assert.throws(()=>verifyLocalCertificate(app,{...pin,certificateSha256:'f'.repeat(64)},{run}),/pin_mismatch/);
 assert.throws(()=>verifyLocalCertificate(app,pin,{run:()=>({status:1})}),/requirement_failed/);
 unstable=true;assert.throws(()=>verifyLocalCertificate(app,pin,{run}),/unstable_designated_requirement/);unstable=false;
 adhoc=true;assert.throws(()=>verifyMacPreviewApp(registration,{platform:'darwin',run}),/certificate_required/);
 assert.throws(()=>previewSigningIdentity({app},{run}),/local_certificate_required/);
 for(const invalid of [{...pin,certificateSha1:undefined},{...pin,certificateSha256:undefined},{...pin,keychain:'/private/keychain'}, {...pin,schema:2}])assert.throws(()=>localCertificatePin(invalid),/invalid_local_signing_descriptor/);
 fs.unlinkSync(path.join(resources,'local-signing.json'));assert.equal(readLocalCertificatePin(app),null);
 fs.symlinkSync(path.join(root,'certificate.pem'),path.join(resources,'local-signing.json'));assert.throws(()=>readLocalCertificatePin(app),/regular_local_signing_descriptor_required/);
});
