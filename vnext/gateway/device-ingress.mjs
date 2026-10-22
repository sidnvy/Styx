import fs from 'node:fs';
import path from 'node:path';
import {networkInterfaces} from 'node:os';
import {isIPv4} from 'node:net';
import {createServer} from 'node:https';
import {createPrivateKey,createHash,randomBytes,X509Certificate} from 'node:crypto';
import {requirePrivateFile} from '../shared/private-file.mjs';
import {handleEnrollment} from './enrollment.mjs';

const fail=(message,status=400,code)=>{const error=Error(message);error.status=status;if(code)error.code=code;throw error};
const exact=(value,keys)=>{
  if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).some(k=>!keys.includes(k)))fail('invalid_device_ingress_fields');
};
const generationOf=value=>{
  if(typeof value!=='string'||! /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(value))fail('invalid_device_ingress_generation');
  return value;
};
const ownedIPv4=host=>isIPv4(host)&&host!=='0.0.0.0'&&!host.startsWith('127.')&&
  Object.values(networkInterfaces()).flat().some(value=>value?.family==='IPv4'&&!value.internal&&value.address===host);
function material(descriptor){
  exact(descriptor,['generation','url','listenHost','tlsCertificateFile','tlsPrivateKeyFile','certificateSha256']);
  generationOf(descriptor.generation);
  let url;
  try{url=new URL(descriptor.url)}catch{fail('invalid_device_ingress_url')}
  if(url.protocol!=='https:'||url.username||url.password||url.search||url.hash||url.pathname!=='/'||
    !url.port||url.hostname!==descriptor.listenHost||!isIPv4(descriptor.listenHost)||descriptor.listenHost==='0.0.0.0'||descriptor.listenHost.startsWith('127.'))fail('owned_exact_ipv4_device_ingress_required');
  if(!ownedIPv4(descriptor.listenHost))fail('owned_exact_ipv4_device_ingress_required',400,'DEVICE_INGRESS_INTERFACE_UNAVAILABLE');
  for(const name of ['tlsCertificateFile','tlsPrivateKeyFile']){
    if(typeof descriptor[name]!=='string'||!path.isAbsolute(descriptor[name]))fail('absolute_device_ingress_tls_path_required');
  }
  requirePrivateFile(descriptor.tlsPrivateKeyFile);
  const cert=fs.readFileSync(descriptor.tlsCertificateFile),key=fs.readFileSync(descriptor.tlsPrivateKeyFile);
  const leaf=new X509Certificate(cert);
  const certificateSha256=createHash('sha256').update(leaf.raw).digest('hex');
  if(descriptor.certificateSha256!==undefined&&(! /^[a-f0-9]{64}$/.test(descriptor.certificateSha256)||descriptor.certificateSha256!==certificateSha256))fail('device_ingress_tls_pin_mismatch');
  if(leaf.checkIP(descriptor.listenHost)!==descriptor.listenHost||!leaf.checkPrivateKey(createPrivateKey(key)))fail('device_ingress_tls_identity_mismatch');
  const now=Date.now(),start=Date.parse(leaf.validFrom),end=Date.parse(leaf.validTo);
  if(!Number.isFinite(start)||!Number.isFinite(end)||start>now||end<=now)fail('device_ingress_certificate_not_current');
  return {descriptor:{generation:descriptor.generation,url:url.origin,listenHost:descriptor.listenHost,
      tlsCertificateFile:descriptor.tlsCertificateFile,tlsPrivateKeyFile:descriptor.tlsPrivateKeyFile,
      ...(descriptor.certificateSha256!==undefined?{certificateSha256:descriptor.certificateSha256}:{})},cert,key,
    ingress:{origin:url.origin,certificate_sha256:certificateSha256,generation:descriptor.generation},
    certificate:{valid_from:new Date(start).toISOString(),valid_to:new Date(end).toISOString(),renewal_required:end-now<7*24*60*60*1000}};
}

/** Additional transport only: registry, credentials, relay and approval remain owned by the primary Gateway. */
export class GatewayDeviceIngress {
  constructor({gateway,enrollment,restoreRetryIntervalsMs=[1000,2000,4000,8000,15000]}={}){
    if(!Array.isArray(restoreRetryIntervalsMs)||!restoreRetryIntervalsMs.length||restoreRetryIntervalsMs.some(value=>!Number.isSafeInteger(value)||value<1||value>15000))throw TypeError('invalid_device_ingress_restore_intervals');
    this.gateway=gateway;this.enrollment=enrollment;
    this.prepared=null;this.server=null;this.sockets=new Set();this.window=null;
    this.phase='absent';this.error=null;this.busy=null;this.closing=false;
    this.restoreRetryIntervalsMs=[...restoreRetryIntervalsMs];this.restoreEpoch=0;this.restoreDesired=null;this.restoreTimer=null;
  }
  status(){
    const prepared=this.prepared;
    return {schema:1,supported:true,status:this.phase,
      ...(prepared?{generation:prepared.descriptor.generation,url:prepared.descriptor.url,listenHost:prepared.descriptor.listenHost,
        ingress:{...prepared.ingress},certificate:{...prepared.certificate,
          renewal_required:Date.parse(prepared.certificate.valid_to)-Date.now()<7*24*60*60*1000}}:{}),
      pairing:this.window&&this.window.expires_at>this.enrollment.now()
        ?{status:'open',expires_at:this.window.expires_at,window_id:this.window.id}:{status:'closed'},
      ...(this.error?{error:this.error}:{}),...(this.busy?{operation:this.busy}:{}),
      ...(this.restoreDesired?{recovery:{status:this.restoreDesired.nextRetryAt?'waiting':'running',generation:this.restoreDesired.descriptor.generation,attempt:this.restoreDesired.attempt,
        ...(this.restoreDesired.nextRetryAt?{next_retry_at:this.restoreDesired.nextRetryAt}:{})}}:{})};
  }
  assertIdle(){if(this.busy||this.closing)fail('device_ingress_operation_in_progress',409)}
  cancelRestore(){
    this.restoreEpoch++;clearTimeout(this.restoreTimer);this.restoreTimer=null;this.restoreDesired=null;
  }
  assertGeneration(body,expected=this.prepared?.descriptor.generation){
    exact(body,['generation']);generationOf(body.generation);
    if(expected!==body.generation)fail('device_ingress_generation_mismatch',409);
  }
  prepare(descriptor){this.cancelRestore();return this.prepareEntry(descriptor)}
  prepareEntry(descriptor){
    this.assertIdle();
    if(!this.enrollment||!this.gateway.relay)fail('device_ingress_not_supported',409);
    if(this.server)fail('device_ingress_must_be_disabled',409);
    try{
      const prepared=material(descriptor);
      if(this.prepared?.descriptor.generation===descriptor.generation&&
        (JSON.stringify(this.prepared.descriptor)!==JSON.stringify(prepared.descriptor)||
          this.prepared.ingress.certificate_sha256!==prepared.ingress.certificate_sha256))fail('device_ingress_generation_identity_changed',409);
      this.closeWindow();this.prepared=prepared;this.phase='prepared';this.error=null;
      return this.status();
    }catch(error){this.phase='failed';this.error=error.message;throw error}
  }
  enable(body){this.cancelRestore();return this.enableEntry(body)}
  async enableEntry(body,restoreEpoch=null){
    this.assertIdle();this.assertGeneration(body);
    if(this.server)return this.status();
    this.busy='enable';
    const operation=(async()=>{
      let server;const sockets=new Set();
      try{
        // Recheck the exact address and material at listen time. Never substitute an interface or identity.
        const fresh=material(this.prepared.descriptor);
        if(fresh.ingress.certificate_sha256!==this.prepared.ingress.certificate_sha256)fail('device_ingress_generation_identity_changed',409);
        const allowedHosts=[new URL(fresh.descriptor.url).host];
        server=createServer({cert:fresh.cert,key:fresh.key,requestCert:true,rejectUnauthorized:false},async(req,res)=>{
          if(!['/styx/enroll/join','/styx/enroll/claim','/styx/enroll/confirm'].includes(req.url)){
            res.writeHead(404,{'content-type':'application/json','cache-control':'no-store'});res.end(JSON.stringify({error:'not_found'}));return;
          }
          const window=this.window&&this.window.expires_at>this.enrollment.now()?this.window:null;
          await handleEnrollment(req,res,{controller:this.enrollment,allowedHosts,allowAdmin:false,
            ingress:{...fresh.ingress,window_id:window?.id,requireScopedInvitation:true}});
        });
        server.on('error',error=>{if(this.server===server){this.phase='failed';this.error=error.message;}});
        server.on('connection',socket=>{sockets.add(socket);socket.once('close',()=>sockets.delete(socket))});
        this.gateway.relay.attach(server,{allowedHosts});
        await new Promise((resolve,reject)=>{
          const error=error=>{server.removeListener('listening',listening);reject(error)};
          const listening=()=>{server.removeListener('error',error);resolve()};
          server.once('error',error);server.once('listening',listening);
          server.listen(Number(new URL(fresh.descriptor.url).port),fresh.descriptor.listenHost);
        });
        if(restoreEpoch!==null&&restoreEpoch!==this.restoreEpoch)fail('device_ingress_restore_cancelled',409);
        this.server=server;this.sockets=sockets;this.prepared=fresh;this.phase='listening';this.error=null;
      }catch(error){
        if(server){
          this.gateway.relay.detach(server);const closed=new Promise(resolve=>server.close(resolve));
          for(const socket of sockets)socket.destroy();await closed;
        }
        this.phase='failed';this.error=error.message;throw error;
      }finally{this.busy=null}
      return this.status();
    })();
    this.operation=operation;
    try{return await operation}finally{if(this.operation===operation)this.operation=null}
  }
  closeWindow(){
    if(this.window){this.enrollment.closePairingWindow(this.window.id);this.window=null;}
  }
  openPairing(body={}){
    exact(body,['generation','ttl_seconds']);this.assertIdle();
    this.assertGeneration({generation:body.generation});
    if(!this.server)fail('device_ingress_not_listening',409);
    const ttl_seconds=body.ttl_seconds??600;
    if(!Number.isSafeInteger(ttl_seconds)||ttl_seconds<60||ttl_seconds>600)fail('invalid_invitation_ttl');
    this.closeWindow();
    const window={id:randomBytes(16).toString('hex'),expires_at:this.enrollment.now()+ttl_seconds*1000};
    const invitation=this.enrollment.invite({ttl_seconds},{...this.prepared.ingress,window_id:window.id});
    this.window=window;
    return {...invitation,ingress:{...this.prepared.ingress},window_id:window.id};
  }
  closePairing(body){
    this.assertIdle();this.assertGeneration(body);this.closeWindow();return this.status();
  }
  async stopListener(){
    let windowError;
    try{this.closeWindow()}catch(error){windowError=error;this.window=null;}
    const server=this.server;this.server=null;
    if(server){
      this.gateway.relay.detach(server);
      const stopped=new Promise(resolve=>server.close(resolve));
      for(const socket of this.sockets)socket.destroy();
      this.sockets.clear();await stopped;
    }
    this.phase=this.prepared?'prepared':'absent';this.error=windowError?.message??null;
    if(windowError)throw windowError;
  }
  async disable(body){
    const restoring=this.restoreDesired,generation=this.prepared?.descriptor.generation??restoring?.descriptor.generation;
    this.cancelRestore();if(restoring)await this.operation?.catch(()=>{});
    this.assertIdle();this.assertGeneration(body,generation);this.busy='disable';
    const operation=this.stopListener();this.operation=operation;
    try{await operation}finally{this.busy=null;if(this.operation===operation)this.operation=null}
    return this.status();
  }
  async close(){
    this.cancelRestore();this.closing=true;
    await this.operation?.catch(()=>{});
    await this.stopListener();
  }
  // Only a startup descriptor schedules retries. Explicit owner operations
  // retire its epoch, so a delayed or in-flight attempt cannot reopen an entry.
  async reconcileRestore(epoch){
    if(this.closing||epoch!==this.restoreEpoch||!this.restoreDesired)return this.status();
    const desired=this.restoreDesired;desired.attempt++;desired.nextRetryAt=null;
    try{
      this.prepareEntry(desired.descriptor);await this.enableEntry({generation:desired.descriptor.generation},epoch);
      if(epoch===this.restoreEpoch)this.restoreDesired=null;
    }catch(error){
      if(epoch===this.restoreEpoch&&!this.closing){
        this.phase='failed';this.error=error.message;
        if(['EADDRINUSE','EADDRNOTAVAIL','DEVICE_INGRESS_INTERFACE_UNAVAILABLE'].includes(error.code)){
          const intervals=this.restoreRetryIntervalsMs,delay=intervals[Math.min(desired.attempt-1,intervals.length-1)];
          desired.nextRetryAt=Date.now()+delay;
          this.restoreTimer=setTimeout(()=>{this.restoreTimer=null;void this.reconcileRestore(epoch).catch(error=>{
            if(epoch===this.restoreEpoch){this.cancelRestore();this.phase='failed';this.error=error.message;}
          })},delay);this.restoreTimer.unref?.();
        }else this.restoreDesired=null;
      }
    }
    return this.status();
  }
  async restore(descriptor){
    this.assertIdle();this.cancelRestore();const epoch=this.restoreEpoch;
    this.restoreDesired={descriptor:{...descriptor},attempt:0,nextRetryAt:null};
    return this.reconcileRestore(epoch);
  }
}
