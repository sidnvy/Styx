// Test-only anonymous child. Private RSA keys never leave this process.
import {generateKeyPairSync,sign,privateDecrypt,createHash,createHmac,constants} from 'node:crypto';
import {createInterface} from 'node:readline';
import {pathToFileURL} from 'node:url';
const {joinPayload,capabilityPayload,pairingComparisonCode}=await import(pathToFileURL(process.env.STYX_TEST_SERVICE_PROTOCOL).href);
const keys={a:generateKeyPairSync('rsa',{modulusLength:3072}),b:generateKeyPairSync('rsa',{modulusLength:3072})};
const credentials=new Map();
const pem=k=>k.publicKey.export({type:'spki',format:'pem'});
const fingerprint=k=>createHash('sha256').update(k.publicKey.export({type:'spki',format:'der'})).digest('hex');
const reply=data=>process.stdout.write(JSON.stringify({ok:true,data})+'\n');
reply({node:process.version,public_a:pem(keys.a),public_b:pem(keys.b),fingerprint_a:fingerprint(keys.a),fingerprint_b:fingerprint(keys.b)});
const lines=createInterface({input:process.stdin,crlfDelay:Infinity});
for await (const line of lines) {
  try {
    if(line.length>65536)throw new Error('bounded command');
    const request=JSON.parse(line);
    if(request.op==='stop') { for(const value of credentials.values())value.fill(0);reply({stopped:true});lines.close();break; }
    if(request.op==='comparison') {
      reply({code:pairingComparisonCode({gatewayOrigin:request.origin,certificateSha256:request.certificate_sha256,requestId:request.request_id,deviceFingerprint:request.device_fingerprint})});continue;
    }
    const key=keys[request.key];if(!key)throw new Error('key selector');
    if(request.op==='sign_join'||request.op==='sign_capability') {
      const bytes=request.op==='sign_join'?joinPayload(request.payload):capabilityPayload(request.payload);
      reply({signature:sign('sha256',Buffer.from(bytes),{key:key.privateKey,padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32}).toString('base64url')});continue;
    }
    if(request.op==='unwrap') {
      const raw=privateDecrypt({key:key.privateKey,padding:constants.RSA_PKCS1_OAEP_PADDING,oaepHash:'sha256'},Buffer.from(request.ciphertext,'base64url'));
      if(!/^[A-Za-z0-9_-]{32,}$/.test(raw.toString('ascii'))) {raw.fill(0);throw new Error('credential shape');}
      credentials.get(request.key)?.fill(0);credentials.set(request.key,raw);
      reply({credential:raw.toString('ascii'),confirmation:createHmac('sha256',raw).update('styx-enrollment-confirm:'+request.request_id).digest('hex')});continue;
    }
    throw new Error('unknown command');
  } catch {
    // Never echo a request, decrypted credential, key or native error object.
    process.stdout.write(JSON.stringify({ok:false,data:null})+'\n');
  }
}
for(const value of credentials.values())value.fill(0);
