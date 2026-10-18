import fs from 'node:fs';
import {requirePrivateFile,ensurePrivateDirectory} from '../shared/private-file.mjs';
import path from 'node:path';
import {
  randomBytes,generateKeyPairSync,createPublicKey,createPrivateKey,createHash,
  sign,privateDecrypt,createHmac,constants
} from 'node:crypto';
import https from 'node:https';
import {fileURLToPath} from 'node:url';
import {joinPayload} from '../shared/enrollment-protocol.mjs';

const ID=/^styx-[a-f0-9]{24}$/;
const TOKEN=/^[A-Za-z0-9_-]{32,}$/;
const sha=b=>createHash('sha256').update(b).digest('hex');
const assert=(truth,msg)=>{if(!truth)throw Error(msg)};
function protectedDir(folder){
  ensurePrivateDirectory(folder);
}
function protectedRead(p) {
  requirePrivateFile(p);
  return fs.readFileSync(p,'utf8');
}
function privateWrite(p,content){
  fs.writeFileSync(p,content,{flag:'wx',mode:0o600});
}
function configOf(raw){
  const config=raw;
  assert(config&&typeof config==='object'&&!Array.isArray(config),'invalid_install_config');
  const url=new URL(config.gateway_url);
  assert(url.protocol==='https:'&&url.username===''&&url.password===''&&
    url.search===''&&url.hash===''&&['','/'].includes(url.pathname),
    'trusted_gateway_https_origin_required');
  assert(typeof config.storage_dir==='string'&&path.isAbsolute(config.storage_dir),
    'absolute_storage_dir_required');
  assert(typeof config.label==='string'&&config.label.length>0&&config.label.length<=72,
    'invalid_host_label');
  assert(typeof config.cwd==='string'&&path.isAbsolute(config.cwd),
    'host_cwd_required');
  assert(typeof config.shell==='string'&&path.isAbsolute(config.shell),
    'host_shell_required');
  assert(typeof config.exec_binary==='string'&&path.isAbsolute(config.exec_binary),
    'codex_binary_required');
  if(config.computer_requested) {
    assert(typeof config.computer_binary==='string'&&path.isAbsolute(config.computer_binary),
      'cua_binary_required');
  }
  if(config.gateway_ca_file!==undefined)
    assert(typeof config.gateway_ca_file==='string'&&path.isAbsolute(config.gateway_ca_file),
      'gateway_ca_path_invalid');
  return config;
}

export async function enrollmentHttpRequest({gateway_url,gateway_ca_file},
  route,data,{adminToken}={}){
  const url=new URL('/styx/enroll/'+route,gateway_url);
  if(url.protocol!=='https:' || url.username || url.password)
    throw Error('trusted_gateway_https_required');
  const reqBody=data===undefined?null:JSON.stringify(data);
  // CA certificates are public information, not credentials; they may be
  // distributed mode 0644, unlike private device keys and bearer tokens.
  const ca=gateway_ca_file?fs.readFileSync(gateway_ca_file):undefined;
  return await new Promise((resolve,reject)=>{
    const req=https.request(url,{
      method:reqBody===null?'GET':'POST',
      rejectUnauthorized:true,
      ...(ca?{ca}:{}),
      headers:{
        ...(reqBody!==null?{'Content-Type':'application/json',
          'Content-Length':Buffer.byteLength(reqBody)}:{}),
        ...(adminToken?{Authorization:'Bearer '+adminToken}:{})
      },
      timeout:10000
    },res=>{
      const chunks=[];let bytes=0;
      res.on('data',data=>{
        bytes+=data.length;
        if(bytes>16*1024){req.destroy(Error('response_too_large'));return}
        chunks.push(data);
      });
      res.on('end',()=>{
        let body;
        try{body=JSON.parse(Buffer.concat(chunks).toString('utf8'))}
        catch{reject(Error('invalid_gateway_json'));return}
        if(res.statusCode>=400){
          const e=new Error(body.error||'enrollment_denied');e.status=res.statusCode;
          reject(e);return;
        }
        resolve({status:res.statusCode,body});
      });
    });
    req.on('timeout',()=>req.destroy(Error('gateway_timeout')));
    req.on('error',reject);
    req.end(reqBody??undefined);
  });
}
export async function enrollmentRequest(config,route,data,options={}) {
  return enrollmentHttpRequest(configOf(config),route,data,options);
}

/** Local host identity is created on the device, not on the Gateway. */
export function initLocalIdentity(config) {
  const cfg=configOf(config);
  protectedDir(cfg.storage_dir);
  const privatePath=path.join(cfg.storage_dir,'identity.pem');
  const idFile=path.join(cfg.storage_dir,'identity.json');
  if(fs.existsSync(privatePath)||fs.existsSync(idFile)){
    assert(fs.existsSync(privatePath)&&fs.existsSync(idFile),'incomplete_device_identity');
    const record=JSON.parse(protectedRead(idFile));
    const priv=createPrivateKey(protectedRead(privatePath));
    const fingerprint=sha(createPublicKey(priv).export({type:'spki',format:'der'}));
    assert(fingerprint===record.fingerprint && ID.test(record.device_id),
      'device_identity_changed');
    return record;
  }
  const {privateKey}=generateKeyPairSync('rsa',{
    modulusLength:3072,publicExponent:0x10001,
    publicKeyEncoding:{format:'pem',type:'spki'},
    privateKeyEncoding:{format:'pem',type:'pkcs8'}
  });
  const pub=createPublicKey(privateKey).export({type:'spki',format:'pem'});
  const id='styx-'+randomBytes(12).toString('hex');
  const record={version:1,device_id:id,platform:process.platform,
    fingerprint:sha(createPublicKey(privateKey).export({type:'spki',format:'der'})),
    public_key_pem:pub,created_at:new Date().toISOString()};
  try{
    privateWrite(privatePath,privateKey);
    privateWrite(idFile,JSON.stringify(record,null,2)+'\n');
  }catch(e){
    // Never silently overwrite or regenerate an enrolled identity.
    throw e;
  }
  return record;
}

export async function requestEnrollment(config,invitation){
  const cfg=configOf(config);
  assert(typeof invitation==='string'&&TOKEN.test(invitation),'invalid_invitation');
  const identity=initLocalIdentity(cfg);
  const pendingFile=path.join(cfg.storage_dir,'pending.json');
  assert(!fs.existsSync(pendingFile),'pending_request_exists');
  const body={
    invitation,device_id:identity.device_id,label:cfg.label,
    platform:process.platform,cwd:cfg.cwd,shell:cfg.shell,
    computer_requested:cfg.computer_requested===true,
    public_key_pem:identity.public_key_pem
  };
  const privateKey=protectedRead(path.join(cfg.storage_dir,'identity.pem'));
  body.signature=sign('sha256',Buffer.from(joinPayload(body)),{
    key:privateKey,padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32
  }).toString('base64url');
  const response=await enrollmentRequest(cfg,'join',body);
  assert(response.status===202&&response.body.fingerprint===identity.fingerprint,
    'gateway_public_key_binding_failed');
  privateWrite(pendingFile,JSON.stringify(response.body,null,2)+'\n');
  return {device_id:identity.device_id,request_id:response.body.request_id,
    fingerprint:identity.fingerprint,status:'pending',expires_at:response.body.expires_at};
}
export async function claimEnrollment(config){
  const cfg=configOf(config);
  protectedDir(cfg.storage_dir);
  const record=JSON.parse(protectedRead(path.join(cfg.storage_dir,'identity.json')));
  const request=JSON.parse(protectedRead(path.join(cfg.storage_dir,'pending.json')));
  const body={request_id:request.request_id,claim_secret:request.claim_secret};
  const answer=await enrollmentRequest(cfg,'claim',body);
  if(answer.body.status==='pending')return {status:'pending'};
  assert(answer.body.status==='approved'&&
    answer.body.device_id===record.device_id&&
    answer.body.crypto==='RSA-OAEP-SHA256','invalid_claim_identity');
  const privateKey=protectedRead(path.join(cfg.storage_dir,'identity.pem'));
  const token=privateDecrypt({key:privateKey,padding:constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash:'sha256'},Buffer.from(answer.body.encrypted_credential,'base64url'))
    .toString('utf8');
  assert(TOKEN.test(token),'invalid_unwrapped_token');
  const tokenFile=path.join(cfg.storage_dir,'host.token');
  if(fs.existsSync(tokenFile)) {
    assert(protectedRead(tokenFile).trim()===token,'approved_token_changed');
  } else {
    privateWrite(tokenFile,token+'\n');
  }
  const signature=createHmac('sha256',token).update(
    'styx-enrollment-confirm:'+body.request_id).digest('hex');
  const confirmed=await enrollmentRequest(cfg,'confirm',{
    ...body,confirmation:signature
  });
  assert(confirmed.body.status==='ready_to_connect' &&
    confirmed.body.device_id===record.device_id,'claim_not_confirmed');
  const gatewayURL=new URL(cfg.gateway_url);
  gatewayURL.protocol='wss:';
  const hostConfig={
    host_id:record.device_id,
    gateway_ws_url:gatewayURL.href,
    token_file:tokenFile,
    ...(cfg.gateway_ca_file?{gateway_ca_file:cfg.gateway_ca_file}:{}),
    exec:{binary:cfg.exec_binary,cwd:cfg.cwd,
      ...(cfg.codex_home?{env:{CODEX_HOME:cfg.codex_home}}:{})},
    ...(answer.body.approved_capabilities.computer?{
      computer:{
        enabled:true,binary:cfg.computer_binary,
        connections:1,
        ...(cfg.computer_socket?{socket:cfg.computer_socket}:{}),
        ...(cfg.computer_env?{env:cfg.computer_env}:{})
      }
    }:{})
  };
  const hostFile=path.join(cfg.storage_dir,'host.json');
  if(fs.existsSync(hostFile)){
    const prior=JSON.parse(protectedRead(hostFile));
    assert(prior.host_id===hostConfig.host_id,'existing_host_config_mismatch');
  } else {
    privateWrite(hostFile,JSON.stringify(hostConfig,null,2)+'\n');
  }
  return {status:'ready_to_connect',device_id:record.device_id,
    capabilities:answer.body.approved_capabilities,
    local_host_config:hostFile};
}

export async function waitForApproval(config,{
  timeoutMs=600000,pollMs=1500,signal
}={}) {
  if(!Number.isSafeInteger(timeoutMs)||timeoutMs<1000||timeoutMs>900000||
    !Number.isSafeInteger(pollMs)||pollMs<100||pollMs>30000)
    throw Error('invalid_approval_wait');
  const expires=Date.now()+timeoutMs;
  while(Date.now()<expires){
    if(signal?.aborted)throw Error('approval_wait_cancelled');
    const result=await claimEnrollment(config);
    if(result.status==='ready_to_connect')return result;
    const remaining=expires-Date.now();
    if(remaining<=0)break;
    await new Promise(resolve=>{
      const interval=setTimeout(resolve,Math.min(pollMs,remaining));
    });
  }
  throw Error('approval_wait_expired');
}

// Optional CLI; no model-supplied arbitrary install commands or OS grants.
if (process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const [command,configFile,inviteFile]=process.argv.slice(2);
  if(!['init','join','claim','wait','onboard'].includes(command)||!configFile){
    process.stderr.write('Usage: node host/enroll.mjs init|join|claim /private/config.json [invitation-file]\n');
    process.exit(2);
  }
  try{
    const cfg=JSON.parse(protectedRead(path.resolve(configFile)));
    const result=command==='init'?initLocalIdentity(cfg)
      :command==='join'
        ?await requestEnrollment(cfg,protectedRead(path.resolve(inviteFile)).trim())
      :command==='wait' ?await waitForApproval(cfg)
      :command==='onboard' ?await (async()=>{
          const first=await requestEnrollment(cfg,
            protectedRead(path.resolve(inviteFile)).trim());
          // Only public identity is shown. Owner must approve its exact
          // fingerprint through an independent trusted owner channel.
          process.stdout.write(JSON.stringify({stage:'awaiting_approval',
            request_id:first.request_id,device_id:first.device_id,
            fingerprint:first.fingerprint})+'\n');
          return await waitForApproval(cfg);
        })()
      :await claimEnrollment(cfg);
    // Never print private keys, pending claim secret or final Host bearer.
    const {public_key_pem,...printable}=result;
    process.stdout.write(JSON.stringify(printable)+'\n');
    if(result.status==='pending')process.exitCode=3;
  }catch(e){
    process.stderr.write('Styx enrollment: '+e.message+'\n');process.exitCode=2;
  }
}
