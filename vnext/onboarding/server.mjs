// Local browser setup control plane. Does not expose an unauthenticated LAN API.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import {randomBytes,timingSafeEqual} from 'node:crypto';
import {fileURLToPath} from 'node:url';
const UI=fileURLToPath(new URL('./ui/',import.meta.url));
const STEPS=new Set(['gateway.prepare','gateway.start','host.prepare','host.invite','host.request','host.claim','host.doctor']);
const STATES=new Set(['pending','running','succeeded','failed','uncertain','blocked','skipped','awaiting_approval']);
const ERRORS=new Set(['interrupted_or_in_progress_do_not_replay','step_failed_inspect_local_evidence_no_automatic_replay']);
const MODES=new Set(['create-local','join-existing']);
const equal=(a,b)=>typeof a==='string'&&Buffer.byteLength(a)===Buffer.byteLength(b)&&timingSafeEqual(Buffer.from(a),Buffer.from(b));
const fail=code=>{throw Error(code)};
export function browserOrigin(value){
 const url=new URL(value);
 if(url.protocol!=='http:'||!['127.0.0.1','localhost','[::1]'].includes(url.hostname)||url.username||url.password||url.pathname!=='/'||url.search||url.hash)fail('trusted_loopback_browser_origin_required');
 return url.origin;
}
export function publicDeployment(value){
 if(value==null)return null;
 const steps=Array.isArray(value.steps)?value.steps:[];
 return {schema:1,mode:MODES.has(value.mode)?value.mode:null,
  activeStep:STEPS.has(value.activeStep)?value.activeStep:null,
  gatewayRuntime:typeof value.gatewayRuntime?.status==='string'&&['running','stopped','not_owned_by_current_process'].includes(value.gatewayRuntime.status)?value.gatewayRuntime.status:'unknown',
  steps:steps.filter(s=>s&&STEPS.has(s.id)).map(s=>({id:s.id,status:STATES.has(s.status)?s.status:'uncertain',
   ...(s.evidence?.ownerApproval==='REQUIRED'?{ownerApproval:'REQUIRED'}:{}),
   ...(/^[a-f0-9]{64}$/.test(s.evidence?.fingerprint??'')?{fingerprint:s.evidence.fingerprint}:{}),
   ...(s.error?{error:ERRORS.has(s.error)?s.error:'step_failed_inspect_local_state'}:{})}))};
}
const object=value=>value&&typeof value==='object'&&!Array.isArray(value);
function keys(value,allowed){if(!object(value)||Object.keys(value).some(k=>!allowed.includes(k)))fail('invalid_configuration_fields')}
export function validateUiConfig(config,{trustedOpenSSL}={}){
 keys(config,['schema','mode','gateway','host','invitationFile']);
 if(config.schema!==1||!MODES.has(config.mode))fail('invalid_configuration');
 keys(config.gateway,['url','caFile']);keys(config.host,['bundle','publisherKeyFile','publisherSha256','baseDir','label','computer','macTeamID','wayland']);
 for(const [name,value]of Object.entries(config.gateway))if(typeof value!=='string'||!value||value.length>4096)fail('invalid_gateway_field');
 for(const [name,value]of Object.entries(config.host)){
  if(['computer','wayland'].includes(name)){if(typeof value!=='boolean')fail('invalid_capability_selection')}
  else if(typeof value!=='string'||!value||value.length>4096)fail('invalid_host_field');
 }
 for(const name of ['bundle','publisherKeyFile','publisherSha256','baseDir','label'])if(typeof config.host[name]!=='string')fail('required_host_field');
 if(typeof config.host.computer!=='boolean')fail('required_capability_selection');
 if(config.invitationFile!==undefined&&(typeof config.invitationFile!=='string'||!config.invitationFile||config.invitationFile.length>4096))fail('invalid_invitation_file');
 if(config.mode==='join-existing'&&!config.invitationFile)fail('invitation_file_required');
 if(config.mode==='create-local'&&(!trustedOpenSSL||!path.isAbsolute(trustedOpenSSL)))fail('local_tls_helper_not_configured');
 return {...config,gateway:{...config.gateway,...(config.mode==='create-local'?{openssl:trustedOpenSSL}:{})}};
}
async function body(req){
 if(req.headers['content-type']!=='application/json')fail('json_required');
 req.setEncoding('utf8');let data='';for await(const chunk of req){data+=chunk;if(Buffer.byteLength(data)>65536)fail('body_too_large')}
 try{return JSON.parse(data)}catch{fail('invalid_json')}
}
export async function createOnboardingServer({stateDir,port=0,trustedForwardOrigin,trustedOpenSSL=process.platform==='win32'?undefined:'/usr/bin/openssl',core}={}){
 if(typeof stateDir!=='string'||!path.isAbsolute(stateDir))fail('absolute_state_directory_required');
 if(!Number.isInteger(port)||port<0||port>65535)fail('invalid_port');
 const forwarded=trustedForwardOrigin?browserOrigin(trustedForwardOrigin):null;
 const api=core??await import('./core.mjs');
 const session=randomBytes(32).toString('base64url'),csrf=randomBytes(32).toString('base64url');
 let origin,closed=false,busy=false;
 const assets=new Map([['/',['index.html','text/html; charset=utf-8']],['/ui/app.mjs',['app.mjs','text/javascript; charset=utf-8']],['/ui/style.css',['style.css','text/css; charset=utf-8']]]);
 const server=http.createServer(async(req,res)=>{
  const send=(status,value)=>{res.writeHead(status,{'Content-Type':'application/json; charset=utf-8'});res.end(JSON.stringify(value))};
  res.setHeader('Cache-Control','no-store');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'");
  const expectedHost=new URL(origin).host;
  if(req.headers.host!==expectedHost){send(403,{error:'host_refused'});return}
  let url;try{url=new URL(req.url,origin)}catch{send(400,{error:'invalid_url'});return}
  if(url.search){send(400,{error:'query_refused'});return}
  if(assets.has(url.pathname)&&req.method==='GET'){
   const[file,type]=assets.get(url.pathname);res.writeHead(200,{'Content-Type':type});res.end(fs.readFileSync(path.join(UI,file)));return;
  }
  if(!url.pathname.startsWith('/api/')){send(404,{error:'not_found'});return}
  if(!equal(req.headers.authorization,'Bearer '+session)){send(401,{error:'session_required'});return}
  if(req.headers.origin!==undefined&&req.headers.origin!==origin){send(403,{error:'origin_refused'});return}
  if(req.method==='POST'&&(req.headers.origin!==origin||!equal(req.headers['x-styx-csrf'],csrf))){send(403,{error:'mutation_refused'});return}
  if(req.method==='GET'&&url.pathname==='/api/session'){
   send(200,{csrf,platform:process.platform,localGatewayAvailable:!!trustedOpenSSL,pauseSupported:typeof api.stopDeploymentGateway==='function',startSupported:typeof api.startDeploymentGateway==='function',
    accountAcceptance:'NOT RUN',nativeInstaller:'NOT RUN',trustedForwarding:!!forwarded});return;
  }
  if(req.method==='GET'&&url.pathname==='/api/status'){
   try{
    const deployment=publicDeployment(await api.readDeployment(stateDir)),plan=await api.planDeployment(stateDir);
    const dependencies=Array.isArray(plan?.steps)?plan.steps.filter(s=>STEPS.has(s.id)).map(s=>({id:s.id,requires:Array.isArray(s.requires)?s.requires.filter(id=>STEPS.has(id)):[]})):[];
    send(200,{deployment,dependencies,busy});
   }catch{if(!fs.existsSync(stateDir))send(200,{deployment:null,dependencies:[],busy});else send(409,{error:'deployment_unavailable'})}return;
  }
  if(req.method!=='POST'){send(405,{error:'method_refused'});return}
  if(!['/api/create','/api/advance','/api/pause','/api/start'].includes(url.pathname)){send(404,{error:'not_found'});return}
  if(busy){send(409,{error:'operation_in_progress'});return}busy=true;
  try{
   const data=await body(req);
   if(url.pathname==='/api/create'){
    const config=validateUiConfig(data,{trustedOpenSSL});
    const temp=fs.mkdtempSync(path.join(os.tmpdir(),'styx-ui-config-'));fs.chmodSync(temp,0o700);
    try{const file=path.join(temp,'config.json');fs.writeFileSync(file,JSON.stringify(config),{mode:0o600});await api.createDeployment(file,{stateDir})}
    finally{fs.rmSync(temp,{recursive:true,force:true})}
   }else if(url.pathname==='/api/advance'){
    keys(data,['authorize']);if(!Array.isArray(data.authorize)||data.authorize.length!==1||!STEPS.has(data.authorize[0]))fail('one_known_step_required');
    await api.advanceDeployment(stateDir,{authorize:data.authorize});
   }else if(url.pathname==='/api/start'){
    keys(data,[]);if(typeof api.startDeploymentGateway!=='function'){send(409,{error:'start_not_supported'});return}
    await api.startDeploymentGateway(stateDir);
   }else{
    keys(data,[]);if(typeof api.stopDeploymentGateway!=='function'){send(409,{error:'pause_not_supported'});return}
    await api.stopDeploymentGateway(stateDir);
   }
   send(200,{deployment:publicDeployment(await api.readDeployment(stateDir))});
  }catch{send(409,{error:'operation_failed_check_status'})}finally{busy=false}
 });
 server.requestTimeout=30000;server.headersTimeout=10000;server.maxHeadersCount=30;
 await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,'127.0.0.1',resolve)});
 origin=forwarded??`http://127.0.0.1:${server.address().port}`;
 return {server,origin,url:origin+'/#session='+session,
  async close(){if(closed)return;closed=true;await new Promise(resolve=>server.close(resolve));await Promise.resolve().then(()=>api.stopDeploymentGateway?.(stateDir)).catch(()=>{})}};
}
if(process.argv[1]&&fs.realpathSync(process.argv[1])===fs.realpathSync(fileURLToPath(import.meta.url))){
 try{
  const[flag,stateDir]=process.argv.slice(2);if(flag!=='--state')fail('usage_server_state_absolute_directory');
  const instance=await createOnboardingServer({stateDir,port:Number(process.env.STYX_ONBOARDING_PORT??0),trustedForwardOrigin:process.env.STYX_ONBOARDING_BROWSER_ORIGIN,trustedOpenSSL:process.env.STYX_ONBOARDING_OPENSSL??(process.platform==='win32'?undefined:'/usr/bin/openssl')});
  // Local terminal bootstrap only: URL fragment never travels in HTTP requests.
  process.stdout.write('Open this private local setup URL in your browser:\n'+instance.url+'\n');
  for(const sig of['SIGINT','SIGTERM'])process.once(sig,()=>void instance.close().then(()=>process.exit(0)));
 }catch{process.stderr.write('Styx local setup could not start. Check the local state path and core installation.\n');process.exitCode=2}
}
