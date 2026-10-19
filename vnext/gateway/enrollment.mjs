import fs from 'node:fs';
import {requirePrivateFile,ensurePrivateDirectory} from '../shared/private-file.mjs';
import path from 'node:path';
import {joinPayload,capabilityPayload} from '../shared/enrollment-protocol.mjs';
export {joinPayload};
import {
  randomBytes, createHash, timingSafeEqual, createPublicKey,
  verify, publicEncrypt, constants, createHmac
} from 'node:crypto';

const PENDING_LIMIT=64;
const ID=/^styx-[a-f0-9]{24}$/;
const FRIENDLY=/^[\p{L}\p{N} ._()-]{1,72}$/u;
const B64URL=/^[A-Za-z0-9_-]{32,}$/;
const ADMIN_HEADER=/^Bearer ([A-Za-z0-9_-]{32,})$/;
const INVITE_MS=10*60*1000;
const JOIN_MS=15*60*1000;
const CLAIM_MS=20*60*1000;
const MAX_BODY=16*1024;
const sha=data=>createHash('sha256').update(data).digest('hex');
const isObject=x=>x!==null && typeof x==='object' && !Array.isArray(x);
const nativePath=os=>os==='win32'?path.win32:path.posix;
const fail=(code,status=400)=>{const error=new Error(code);error.status=status;throw error};
function exact(obj,keys){
  if(!isObject(obj) || Object.keys(obj).some(k=>!keys.includes(k)))fail('invalid_fields');
}
function assert(condition,code,status=400){if(!condition)fail(code,status)}
function secretFile(filename){
  try{requirePrivateFile(filename)}catch{fail('credential_file_permissions',403)}
  const v=fs.readFileSync(filename,'utf8').trim();
  assert(B64URL.test(v),'invalid_owner_token',403);
  return v;
}
function commitFile(filename,content,mode=0o600){
  const tmp=filename+'.pending-'+randomBytes(8).toString('hex');
  const fd=fs.openSync(tmp,'wx',mode);
  try {fs.writeFileSync(fd,content);fs.fsyncSync(fd);}
  finally {fs.closeSync(fd);}
  try {fs.renameSync(tmp,filename)}
  catch(e){try{fs.unlinkSync(tmp)}catch{};throw e}
}
function validateJoin(body){
  exact(body,['invitation','device_id','label','platform','cwd','shell',
    'computer_requested','public_key_pem','signature']);
  assert(typeof body.invitation==='string'&&B64URL.test(body.invitation),'invalid_invitation');
  assert(typeof body.device_id==='string'&&ID.test(body.device_id),'invalid_device_id');
  assert(typeof body.label==='string'&&FRIENDLY.test(body.label),'invalid_label');
  assert(['linux','darwin','win32'].includes(body.platform),'invalid_platform');
  assert(typeof body.cwd==='string'&&nativePath(body.platform).isAbsolute(body.cwd) &&
    body.cwd.length<=512,'invalid_cwd');
  assert(typeof body.shell==='string'&&nativePath(body.platform).isAbsolute(body.shell)&&
    body.shell.length<=512,'invalid_shell');
  const shellName=nativePath(body.platform).basename(body.shell).toLowerCase();
  assert((body.platform==='win32'
    ? ['powershell.exe','pwsh.exe','pwsh'].includes(shellName)
    : ['sh','bash','zsh'].includes(shellName)),'unsupported_shell');
  assert(typeof body.computer_requested==='boolean','invalid_computer_flag');
  assert(typeof body.public_key_pem==='string'&&body.public_key_pem.length<=2400,
    'invalid_public_key');
  assert(typeof body.signature==='string'&&body.signature.length<=2048,
    'invalid_signature');
  let pub, signature;
  try {
    pub=createPublicKey(body.public_key_pem);
    signature=Buffer.from(body.signature,'base64url');
  }catch{fail('invalid_public_key')}
  assert(pub.asymmetricKeyType==='rsa'&&
    (pub.asymmetricKeyDetails?.modulusLength??0)>=3072 &&
    (pub.asymmetricKeyDetails?.modulusLength??0)<=4096,'unsupported_identity_key');
  const ok=verify('sha256',Buffer.from(joinPayload(body)),{
    key:pub,padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32
  },signature);
  assert(ok,'invalid_identity_proof',403);
  return {fingerprint:sha(pub.export({type:'spki',format:'der'})),publicKey:pub};
}

function stateShape(data) {
  assert(isObject(data) && data.version===1 && Array.isArray(data.invitations) &&
    Array.isArray(data.pending) && Array.isArray(data.devices),'invalid_enrollment_database',500);
  return data;
}

/**
 * Local-first provisioning controller. It is not exposed as a model-visible
 * execution tool. A trusted owner must explicitly approve the exact native
 * public-key fingerprint before a Host receives its first auth capability.
 *
 * Prototype: one Gateway process/one local state directory, no cluster lock.
 */
export class EnrollmentController {
  constructor({rootDir,adminTokenFile,registry,relay,now=()=>Date.now()}={}){
    assert(typeof rootDir==='string'&&path.isAbsolute(rootDir),'enrollment_dir_required');
    assert(typeof adminTokenFile==='string'&&path.isAbsolute(adminTokenFile),
      'enrollment_admin_token_required');
    assert(registry?.admitApprovedHost && registry?.revokeHost,'target_registry_required');
    this.root=path.resolve(rootDir);
    this.registry=registry;this.relay=relay;this.now=now;
    this.adminDigest=Buffer.from(sha(secretFile(adminTokenFile)),'hex');
    ensurePrivateDirectory(this.root);
    ensurePrivateDirectory(path.join(this.root,'tokens'));
    const file=path.join(this.root,'state.json');
    this.stateFile=file;
    if(fs.existsSync(file))requirePrivateFile(file);
    this.db=fs.existsSync(file)
      ?stateShape(JSON.parse(fs.readFileSync(file,'utf8')))
      :{version:1,invitations:[],pending:[],devices:[]};
    for(const rec of this.db.devices) {
      if(rec.status==='approved'){
        const token=rec.target?.exec?.token_file;
        assert(typeof token==='string'&&fs.existsSync(token) &&
          path.resolve(token).startsWith(path.join(this.root,'tokens')+path.sep),
          'approved_device_token_missing',500);
        this.registry.admitApprovedHost(rec.target);
      }
    }
    if(this.db.default_environment_id!==undefined){
      assert(this.db.devices.some(x=>x.id===this.db.default_environment_id&&x.status==='approved'),'invalid_default_device',500);
      this.registry.setDefault(this.db.default_environment_id);
    }
  }
  save(){commitFile(this.stateFile,JSON.stringify(this.db,null,2)+'\n')}
  authorizeAdmin(value){
    const m=ADMIN_HEADER.exec(value||'');
    if(!m)return false;
    const given=createHash('sha256').update(m[1]).digest();
    return timingSafeEqual(given,this.adminDigest);
  }
  invite({ttl_seconds=600}={}){
    assert(Number.isSafeInteger(ttl_seconds)&&ttl_seconds>=60&&ttl_seconds<=600,
      'invalid_invitation_ttl');
    const active=this.db.invitations.filter(x=>!x.used&&x.exp>this.now()).length;
    assert(active<64,'too_many_invitations',429);
    const code=randomBytes(32).toString('base64url');
    const entry={id:randomBytes(10).toString('hex'),hash:sha(code),
      exp:this.now()+ttl_seconds*1000,used:false};
    this.db.invitations.push(entry);this.save();
    return {invitation:code,expires_at:entry.exp,one_use:true};
  }
  join(body){
    const {fingerprint,publicKey}=validateJoin(body);
    const invite=this.db.invitations.find(x=>x.hash===sha(body.invitation));
    assert(invite && !invite.used && invite.exp>this.now(),'invitation_expired_or_used',403);
    assert(!this.db.devices.some(x=>x.status==='revoked'&&x.fingerprint===fingerprint),
      'device_identity_retired',403);
    assert(!this.db.pending.some(x=>x.device_id===body.device_id) &&
      !this.db.devices.some(x=>x.id===body.device_id) &&
      !this.registry.targets.has(body.device_id),'device_identity_conflict',409);
    assert(this.db.pending.filter(x=>x.status==='pending').length<PENDING_LIMIT,
      'too_many_pending_devices',429);
    const claimSecret=randomBytes(32).toString('base64url');
    const requestId=randomBytes(16).toString('hex');
    invite.used=true;
    this.db.pending.push({
      request_id:requestId,device_id:body.device_id,label:body.label,
      platform:body.platform,cwd:body.cwd,shell:body.shell,
      computer_requested:body.computer_requested,
      public_key_pem:publicKey.export({format:'pem',type:'spki'}),
      fingerprint,claim_hash:sha(claimSecret),
      exp:this.now()+JOIN_MS,status:'pending'
    });
    this.save();
    return {request_id:requestId,claim_secret:claimSecret,
      fingerprint,status:'pending',expires_at:this.now()+JOIN_MS};
  }
  listPending(){
    return this.db.pending.filter(x=>x.status==='pending'&&x.exp>this.now())
      .map(x=>({
        request_id:x.request_id,device_id:x.device_id,label:x.label,
        platform:x.platform,cwd:x.cwd,shell:x.shell,
        fingerprint:x.fingerprint,computer_requested:x.computer_requested,
        expires_at:x.exp
      }));
  }
  approve(body={}){
    exact(body,['request_id','fingerprint','enable_computer']);
    const {request_id,fingerprint,enable_computer=false}=body;
    assert(typeof request_id==='string'&&/^[a-f0-9]{32}$/.test(request_id),
      'invalid_request_id');
    assert(typeof fingerprint==='string'&&/^[a-f0-9]{64}$/.test(fingerprint),
      'invalid_fingerprint');
    assert(typeof enable_computer==='boolean','invalid_computer_approval');
    const pending=this.db.pending.find(x=>x.request_id===request_id);
    assert(pending&&pending.status==='pending'&&pending.exp>this.now(),
      'request_not_pending',409);
    assert(!this.db.devices.some(x=>x.status==='revoked'&&x.fingerprint===pending.fingerprint),
      'device_identity_retired',403);
    assert(timingSafeEqual(Buffer.from(fingerprint,'hex'),
      Buffer.from(pending.fingerprint,'hex')),'fingerprint_mismatch',403);
    assert(!enable_computer||pending.computer_requested,
      'computer_capability_not_requested',403);
    const tokenFile=path.join(this.root,'tokens',pending.device_id+'.token');
    assert(!fs.existsSync(tokenFile),'device_identity_conflict',409);
    const capability=randomBytes(48).toString('base64url');
    const pub=createPublicKey(pending.public_key_pem);
    const encrypted=publicEncrypt({key:pub,padding:constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash:'sha256'},Buffer.from(capability)).toString('base64url');
    const target={
      id:pending.device_id,kind:'host',platform:pending.platform,
      generation:'paired-'+randomBytes(8).toString('hex'),
      allowed:true,cwd:pending.cwd,shell:pending.shell,shells:[pending.shell],
      exec:{transport:'outbound',token_file:tokenFile},
      computer:{enabled:enable_computer,
        ...(enable_computer?{transport:'outbound',max_connections:2}:{})}
    };
    // Validate target schema before creating an approved credential.
    assert(!this.registry.targets.has(target.id),'device_identity_conflict',409);
    commitFile(tokenFile,capability+'\n');
    try {
      this.registry.admitApprovedHost(target);
      pending.status='approved';pending.approved_at=this.now();
      pending.claim_expires_at=this.now()+CLAIM_MS;
      pending.sealed_token=encrypted;
      this.db.devices.push({id:target.id,label:pending.label,
        fingerprint:pending.fingerprint,target,
        status:'approved',approved_at:this.now()});
      this.save();
    }catch(e){
      try{this.registry.revokeHost(target.id)}catch{}
      try{fs.unlinkSync(tokenFile)}catch{}
      throw e;
    }
    return {device_id:target.id,status:'approved',
      fingerprint:pending.fingerprint,
      approved_capabilities:{exec:true,computer:enable_computer}};
  }
  claim(body={}){
    exact(body,['request_id','claim_secret']);
    const {request_id,claim_secret}=body;
    assert(typeof request_id==='string'&&/^[a-f0-9]{32}$/.test(request_id),
      'invalid_request_id');
    assert(typeof claim_secret==='string'&&B64URL.test(claim_secret),
      'invalid_claim_secret',403);
    const req=this.db.pending.find(x=>x.request_id===request_id);
    assert(req&&req.claim_hash===sha(claim_secret),'invalid_claim',403);
    if(req.status==='pending'&&req.exp>this.now())
      return {status:'pending'};
    assert(req.status==='approved'&&req.claim_expires_at>this.now(),
      'claim_unavailable',403);
    const device=this.db.devices.find(x=>x.id===req.device_id);
    assert(device?.status==='approved','device_revoked',403);
    return {status:'approved',device_id:req.device_id,
      encrypted_credential:req.sealed_token,
      crypto:'RSA-OAEP-SHA256',
      approved_capabilities:{
        exec:true,computer:device.target.computer.enabled
      }
    };
  }
  confirm(body={}){
    exact(body,['request_id','claim_secret','confirmation']);
    const {request_id,claim_secret,confirmation}=body;
    assert(typeof confirmation==='string'&&/^[a-f0-9]{64}$/.test(confirmation),
      'invalid_confirmation');
    const req=this.db.pending.find(x=>x.request_id===request_id);
    assert(req&&req.claim_hash===sha(claim_secret) &&
      (req.status==='approved'||req.status==='claimed') &&
      req.claim_expires_at>this.now(),'claim_unavailable',403);
    const tokenFile=path.join(this.root,'tokens',req.device_id+'.token');
    const capability=secretFile(tokenFile);
    const expected=createHmac('sha256',capability)
      .update('styx-enrollment-confirm:'+request_id).digest();
    const actual=Buffer.from(confirmation,'hex');
    assert(timingSafeEqual(expected,actual),'confirmation_failed',403);
    if(req.status==='approved') {
      req.status='claimed';
      delete req.sealed_token;
      req.claimed_at=this.now();
      this.save();
    }
    return {status:'ready_to_connect',device_id:req.device_id};
  }
  devices(){
    return this.db.devices.map(x=>({
      device_id:x.id,label:x.label,platform:x.target.platform,
      is_default:this.db.default_environment_id===x.id,
      capabilities:{exec:x.status==='approved',
        computer:x.status==='approved'&&x.target.computer.enabled},
      status:x.status,generation:x.target.generation,
      online:x.status==='approved'&&Boolean(this.relay?.connected(x.id)),
      fingerprint:x.fingerprint
    }));
  }
  setDefault(body={}){
    exact(body,['device_id']);
    assert(typeof body.device_id==='string'&&ID.test(body.device_id),'invalid_device_id');
    assert(this.db.devices.some(x=>x.id===body.device_id&&x.status==='approved'),'device_not_found',404);
    this.registry.resolve(body.device_id);
    const previous=this.db.default_environment_id;
    this.db.default_environment_id=body.device_id;
    try{this.save()}catch(error){if(previous===undefined)delete this.db.default_environment_id;else this.db.default_environment_id=previous;throw error}
    this.registry.setDefault(body.device_id);
    return {status:'updated',default_environment_id:body.device_id};
  }
  capabilities(body={}){
    exact(body,['device_id','fingerprint','generation','enable_computer','public_key_pem','signature']);
    assert(typeof body.device_id==='string'&&ID.test(body.device_id),'invalid_device_id');
    assert(typeof body.fingerprint==='string'&&/^[a-f0-9]{64}$/.test(body.fingerprint),'invalid_fingerprint');
    assert(typeof body.generation==='string'&&body.generation.length<=128,'invalid_generation');
    assert(typeof body.enable_computer==='boolean','invalid_computer_approval');
    assert(typeof body.public_key_pem==='string'&&body.public_key_pem.length<=2400&&typeof body.signature==='string'&&body.signature.length<=2048,'invalid_identity_proof');
    const record=this.db.devices.find(x=>x.id===body.device_id);
    assert(record&&record.status==='approved','device_not_found',404);
    assert(record.fingerprint===body.fingerprint&&record.target.generation===body.generation,'capability_revision_mismatch',409);
    let pub,valid=false;
    try{pub=createPublicKey(body.public_key_pem);valid=pub.asymmetricKeyType==='rsa'&&
      sha(pub.export({type:'spki',format:'der'}))===record.fingerprint&&
      verify('sha256',Buffer.from(capabilityPayload(body)),{key:pub,padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32},Buffer.from(body.signature,'base64url'));}catch{}
    assert(valid,'invalid_identity_proof',403);
    const previous=record.target;
    const target={...previous,generation:'capability-'+randomBytes(8).toString('hex'),
      computer:{enabled:body.enable_computer,...(body.enable_computer?{transport:'outbound',max_connections:2}:{})}};
    // Synchronous validation/update/save prevents requests interleaving with intent.
    this.registry.replaceApprovedHost(target,previous.generation);
    record.target=target;
    try{this.save()}catch(error){record.target=previous;this.registry.replaceApprovedHost(previous,target.generation);throw error}
    this.relay?.disconnectHost(record.id);
    return {status:'updated',device_id:record.id,fingerprint:record.fingerprint,
      generation:target.generation,capabilities:{exec:true,computer:body.enable_computer}};
  }
  recover(body={}){
    exact(body,['device_id','fingerprint','generation']);
    const {device_id,fingerprint,generation}=body;
    assert(typeof device_id==='string'&&ID.test(device_id),'invalid_device_id');
    assert(typeof fingerprint==='string'&&/^[a-f0-9]{64}$/.test(fingerprint),
      'invalid_fingerprint');
    assert(typeof generation==='string'&&generation.length>0&&generation.length<=128,
      'invalid_generation');
    const record=this.db.devices.find(x=>x.id===device_id);
    assert(record&&record.status==='approved','device_not_found',404);
    assert(record.fingerprint===fingerprint&&record.target.generation===generation,
      'recovery_identity_mismatch',409);
    // Recovery retires an identity. New keys, a fresh one-use invitation and
    // independent owner approval are required; no automatic credential rollover.
    return {...this.revoke({device_id}),recovery:'fresh_enrollment_required'};
  }
  revoke(body={}){
    exact(body,['device_id']);
    const {device_id}=body;
    assert(typeof device_id==='string'&&ID.test(device_id),'invalid_device_id');
    const record=this.db.devices.find(x=>x.id===device_id);
    assert(record&&record.status==='approved','device_not_found',404);
    const before=structuredClone(this.db);
    if(this.db.default_environment_id===device_id)delete this.db.default_environment_id;
    record.status='revoked';
    record.revoked_at=this.now();
    for(const pending of this.db.pending.filter(x=>x.device_id===device_id)) {
      pending.status='revoked';delete pending.sealed_token;delete pending.claim_hash;
    }
    // Commit the tombstone before reporting success or disconnecting peers.
    // These operations are synchronous in the single-process control plane:
    // no HTTP or Exec callback can interleave between commit and denial.
    try{this.save()}catch(e){this.db=before;throw e}
    this.registry.revokeHost(device_id);
    if(this.registry.defaultId===device_id)this.registry.setDefault(undefined);
    this.relay?.disconnectHost(device_id);
    try{fs.unlinkSync(record.target.exec.token_file)}
    catch(e){if(e.code!=='ENOENT')throw e}
    return {device_id,status:'revoked'};
  }
}

async function jsonBody(req){
  if(!String(req.headers['content-type']??'').startsWith('application/json'))
    fail('json_content_type_required',415);
  let bytes=0;
  const parts=[];
  for await(const chunk of req){
    bytes+=chunk.length;
    if(bytes>MAX_BODY)fail('body_too_large',413);
    parts.push(chunk);
  }
  try{return JSON.parse(Buffer.concat(parts).toString('utf8'))}
  catch{fail('invalid_json')}
}
const send=(res,status,data)=>{
  res.writeHead(status,{'content-type':'application/json; charset=utf-8',
    'cache-control':'no-store','x-content-type-options':'nosniff'});
  res.end(JSON.stringify(data));
};
const isLoopback=req=>['127.0.0.1','::1','::ffff:127.0.0.1']
  .includes(req.socket.remoteAddress);

/** Narrow HTTP adapter for onboarding, separate from model MCP tools. */
export async function handleEnrollment(req,res,{controller,allowedHosts}={}){
  if(!controller || !req.url?.startsWith('/styx/enroll/'))return false;
  try{
    assert(allowedHosts.includes(req.headers.host),'host_not_allowed',403);
    assert(req.headers.origin===undefined,'origin_not_allowed',403);
    assert(req.socket.encrypted||isLoopback(req),'enrollment_requires_tls',403);
    const routes={
      '/styx/enroll/invitations':['POST',true,'invite'],
      '/styx/enroll/pending':['GET',true,'listPending'],
      '/styx/enroll/approve':['POST',true,'approve'],
      '/styx/enroll/devices':['GET',true,'devices'],
      '/styx/enroll/revoke':['POST',true,'revoke'],
      '/styx/enroll/recover':['POST',true,'recover'],
      '/styx/enroll/capabilities':['POST',true,'capabilities'],
      '/styx/enroll/set-default':['POST',true,'setDefault'],
      '/styx/enroll/join':['POST',false,'join'],
      '/styx/enroll/claim':['POST',false,'claim'],
      '/styx/enroll/confirm':['POST',false,'confirm']
    };
    const route=routes[req.url];
    assert(route,'not_found',404);
    const [method,admin,fn]=route;
    assert(req.method===method,'method_not_allowed',405);
    if(admin) {
      const present=(req.rawHeaders??[]).filter((_,i)=>i%2===0)
        .filter(s=>s.toLowerCase()==='authorization').length;
      assert(present===1&&controller.authorizeAdmin(req.headers.authorization),
        'unauthorized',401);
    } else {
      assert(!req.headers.authorization,'unauthorized',401);
    }
    const data=method==='POST'?await jsonBody(req):undefined;
    const result=controller[fn](data);
    send(res,fn==='join'?202:fn==='claim'&&result.status==='pending'?202:200,result);
  }catch(e){
    send(res,Number.isInteger(e.status)?e.status:500,
      {error:e.status?e.message:'enrollment_internal_error'});
  }
  return true;
}
