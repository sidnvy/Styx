// Shared desired-config validation; no role inference from service state.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {isIP} from 'node:net';
const fail=code=>{throw Error(code)};
const obj=x=>x&&typeof x==='object'&&!Array.isArray(x);
const abs=x=>typeof x==='string'&&path.isAbsolute(x)&&path.normalize(x)===x;
const exact=(x,keys)=>{if(!obj(x)||Object.keys(x).some(k=>!keys.includes(k)))fail('invalid_configuration_fields')};
export function localGatewayAddresses(){return [...new Set(Object.values(os.networkInterfaces()).flatMap(items=>items??[]).filter(x=>!x.internal&&isIP(x.address)===4).map(x=>x.address))].sort();}
export function validateDeployment(config,{checkNetwork=true}={}){
 exact(config,['schema','mode','gateway','host','invitationFile','pairingMode']);
 if(config.schema!==1||!['create-local','join-existing'].includes(config.mode))fail('unsupported_deployment_schema_or_mode');
 if(config.pairingMode!==undefined&&!['manual','owner-local'].includes(config.pairingMode))fail('invalid_pairing_mode');
 if(config.mode==='join-existing'&&config.pairingMode==='owner-local')fail('join_requires_external_owner_approval');
 exact(config.gateway,['url','openssl','caFile','listenHost','allowRemoteHosts','runtime']);
 let u;try{u=new URL(config.gateway.url)}catch{fail('gateway_https_origin_required')}
 if(u.protocol!=='https:'||u.username||u.password||u.search||u.hash||u.pathname!=='/')fail('gateway_https_origin_required');
 if(config.mode==='create-local'){
  if(!u.port||Number(u.port)<1024||!abs(config.gateway.openssl)||config.gateway.caFile!==undefined)fail('local_gateway_requires_port_and_trusted_openssl');
  const listen=config.gateway.listenHost??'127.0.0.1';
  if(isIP(listen)!==4||u.hostname!==listen)fail('gateway_url_must_match_exact_bind_ip');
  if(config.gateway.allowRemoteHosts!==undefined&&typeof config.gateway.allowRemoteHosts!=='boolean')fail('invalid_network_exposure_authorization');
  if(listen!=='127.0.0.1'&&(config.gateway.allowRemoteHosts!==true||checkNetwork&&!localGatewayAddresses().includes(listen)))fail('explicit_owned_network_interface_required');
  const st=fs.lstatSync(config.gateway.openssl);if(!st.isFile()||st.isSymbolicLink())fail('trusted_openssl_regular_file_required');
 }else if(['openssl','listenHost','allowRemoteHosts','runtime'].some(k=>config.gateway[k]!==undefined))fail('join_cannot_prepare_gateway');
 if(config.gateway.caFile!==undefined&&!abs(config.gateway.caFile))fail('absolute_ca_file_required');
 if(config.gateway.runtime!==undefined){
  exact(config.gateway.runtime,['bundle','publisherKeyFile','publisherSha256','baseDir']);
  for(const k of ['bundle','publisherKeyFile','baseDir'])if(!abs(config.gateway.runtime[k]))fail('absolute_gateway_runtime_paths_required');
  if(!/^[a-f0-9]{64}$/.test(config.gateway.runtime.publisherSha256??''))fail('invalid_gateway_runtime_publisher');
 }
 if(config.host===undefined){
  if(config.mode!=='create-local'||!config.gateway.runtime)fail('gateway_only_requires_independent_runtime');
  if(config.invitationFile!==undefined||config.pairingMode!==undefined)fail('host_pairing_requires_host');
  return config;
 }
 exact(config.host,['bundle','publisherKeyFile','publisherSha256','baseDir','label','computer','browser','macTeamID','wayland','shell','macPreviewApp']);
 for(const k of ['bundle','publisherKeyFile','baseDir'])if(!abs(config.host[k]))fail('absolute_host_paths_required');
 if(!/^[a-f0-9]{64}$/.test(config.host.publisherSha256??'')||typeof config.host.label!=='string'||!config.host.label||config.host.label.length>72||typeof config.host.computer!=='boolean')fail('invalid_host_setup');
 if(config.host.browser!==undefined){
  exact(config.host.browser,['enabled','headless','executablePath']);
  if(typeof config.host.browser.enabled!=='boolean'||config.host.browser.headless!==undefined&&typeof config.host.browser.headless!=='boolean'||config.host.browser.executablePath!==undefined&&!abs(config.host.browser.executablePath))fail('invalid_browser_selection');
 }
 if(config.host.wayland!==undefined&&typeof config.host.wayland!=='boolean')fail('invalid_wayland_selection');
 if(config.host.shell!==undefined&&!abs(config.host.shell))fail('absolute_native_shell_required');
 if(config.host.macTeamID!==undefined&&!/^[A-Z0-9]{10}$/.test(config.host.macTeamID))fail('invalid_mac_team_identity');
 if(config.gateway.runtime){const a=config.gateway.runtime.baseDir,b=config.host.baseDir;if(a===b||a.startsWith(b+path.sep)||b.startsWith(a+path.sep))fail('gateway_and_host_runtime_roots_must_be_independent');}
 if(config.invitationFile!==undefined&&(!abs(config.invitationFile)||config.mode!=='join-existing'))fail('invalid_invitation_file');
 return config;
}
