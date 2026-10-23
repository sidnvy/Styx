// Local certificate continuity is distinct from Apple publisher/notarization
// trust. Only public certificate pins enter a preview bundle or deployment.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash,X509Certificate} from 'node:crypto';
import {spawnSync} from 'node:child_process';
const fail=code=>{throw Error(code)};
export function localCertificatePin(value){
 if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).some(k=>!['schema','certificateSha1','certificateSha256'].includes(k))||value.schema!==1||!/^[a-f0-9]{40}$/.test(value.certificateSha1??'')||!/^[a-f0-9]{64}$/.test(value.certificateSha256??''))fail('invalid_local_signing_descriptor');
 return {schema:1,certificateSha1:value.certificateSha1,certificateSha256:value.certificateSha256};
}
export function readLocalCertificatePin(app){
 const file=path.join(app,'Contents/Resources/local-signing.json');let st;
 try{st=fs.lstatSync(file)}catch(error){if(error.code==='ENOENT')return null;throw error}
 if(!st.isFile()||st.isSymbolicLink()||st.size>4096)fail('regular_local_signing_descriptor_required');
 return localCertificatePin(JSON.parse(fs.readFileSync(file,'utf8')));
}
export function verifyLocalCertificate(app,value,{run=spawnSync}={}){
 const pin=localCertificatePin(value),opts={encoding:'utf8',timeout:15000,maxBuffer:65536,stdio:['ignore','pipe','pipe']};
 const checked=run('/usr/bin/codesign',['--verify','--strict','-R',`=identifier "app.styx.host" and certificate leaf = H"${pin.certificateSha1}"`,app],opts);
 if(checked.error||checked.status!==0)fail('local_preview_certificate_requirement_failed');
 const requirements=run('/usr/bin/codesign',['-d','-r-',app],opts);
 const text=String(requirements.stdout??'')+'\n'+String(requirements.stderr??'');
 const expected=`identifier "app.styx.host" and certificate leaf = H"${pin.certificateSha1}"`;
 if(requirements.error||requirements.status!==0||!text.split('\n').some(line=>line.replace(/^# /,'').trim()==='designated => '+expected))fail('local_preview_unstable_designated_requirement');
 const scratch=fs.mkdtempSync(path.join(os.tmpdir(),'styx-public-certificate-'));
 try{
  const prefix=path.join(scratch,'certificate-'),result=run('/usr/bin/codesign',['-d','--extract-certificates='+prefix,app],opts);
  if(result.error||result.status!==0)fail('local_preview_certificate_unavailable');
  const file=prefix+'0',st=fs.lstatSync(file);if(!st.isFile()||st.isSymbolicLink()||st.size>65536)fail('local_preview_certificate_unavailable');
  const raw=new X509Certificate(fs.readFileSync(file)).raw;
  if(createHash('sha1').update(raw).digest('hex')!==pin.certificateSha1||createHash('sha256').update(raw).digest('hex')!==pin.certificateSha256)fail('local_preview_certificate_pin_mismatch');
  return pin;
 }finally{fs.rmSync(scratch,{recursive:true,force:true})}
}
