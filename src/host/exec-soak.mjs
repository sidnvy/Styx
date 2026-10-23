// Isolated Linux native Exec transport soak, never a production service.
import fs from 'node:fs';
import path from 'node:path';
import {createHash,randomBytes} from 'node:crypto';
import {spawn,execFileSync} from 'node:child_process';
import {once} from 'node:events';
import {fileURLToPath} from 'node:url';
import {performance} from 'node:perf_hooks';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {createStyxGateway} from '../gateway/index.mjs';
import {createGatewayHttp} from '../gateway/http.mjs';
const root=fileURLToPath(new URL('../',import.meta.url));
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const digest=file=>createHash('sha256').update(fs.readFileSync(file)).digest('hex');
export function soakOptions({directory,durationSeconds=86400,intervalSeconds=60}={}){
  if(typeof directory!=='string'||!path.isAbsolute(directory))throw Error('absolute_fresh_soak_directory_required');
  if(!Number.isSafeInteger(durationSeconds)||durationSeconds<1||durationSeconds>172800||
    !Number.isSafeInteger(intervalSeconds)||intervalSeconds<1||intervalSeconds>3600)
    throw Error('invalid_soak_duration_or_interval');
  return {directory,durationSeconds,intervalSeconds};
}
function save(file,value){
  const tmp=file+'.new';fs.writeFileSync(tmp,JSON.stringify(value,null,2)+'\n',{mode:0o600});
  fs.renameSync(tmp,file);
}
export async function runExecSoak(options,{signal}={}){
  const {directory,durationSeconds,intervalSeconds}=soakOptions(options);
  if(process.platform!=='linux'||process.arch!=='x64')throw Error('linux_x64_soak_only');
  const binary=path.join(root,'packages/styx-exec-adapter/.runtime/codex');
  // This is the verified executable from the fixed official archive, not
  // an arbitrary executable supplied by a model or mutable runtime manifest.
  if(digest(binary)!=='399ff69c431c066e40de318fba45c2b07f45a76b19939d247ee4828fc70c4215')
    throw Error('pinned_executor_digest_mismatch');
  fs.mkdirSync(directory,{mode:0o700});
  const receiptFile=path.join(directory,'receipt.json');
  const receipt={schema:1,status:'NOT RUN',phase:'starting',kind:'linux-native-exec-loopback',
    duration_seconds:durationSeconds,interval_seconds:intervalSeconds,passed_samples:0,
    elapsed_seconds:0,pid:process.pid,node:process.version,started_at:new Date().toISOString(),
    native_gui:'NOT RUN',installed_service:'NOT RUN',cold_install:'NOT RUN',
    signed_distribution:'NOT RUN',full_platform_soak_24h:'NOT RUN'};
  try{receipt.revision=execFileSync('git',['rev-parse','HEAD'],{cwd:root,encoding:'utf8'}).trim()}catch{}
  save(receiptFile,receipt);
  let server,child,client;
  const began=performance.now();
  try{
    const hostToken=randomBytes(32).toString('hex'),modelToken=randomBytes(32).toString('hex');
    const tokenFile=path.join(directory,'host.token');
    fs.writeFileSync(tokenFile,hostToken,{mode:0o600,flag:'wx'});
    const home=path.join(directory,'codex-home');fs.mkdirSync(home,{mode:0o700});
    const gateway=createStyxGateway({catalog:{version:1,targets:[{
      id:'soak-owned-host',kind:'host',platform:'linux',generation:'soak-generation-1',
      cwd:directory,shell:'/bin/sh',shells:['/bin/sh'],allowed:true,
      exec:{transport:'outbound',token_file:tokenFile}
    }]}});
    const allowedHosts=[];
    server=await createGatewayHttp(gateway,{token:modelToken,port:0,allowedHosts});
    const host='127.0.0.1:'+server.address.port;allowedHosts.push(host);
    const config={host_id:'soak-owned-host',gateway_ws_url:'ws://'+host,token_file:tokenFile,
      exec:{binary,cwd:directory,env:{PATH:'/usr/bin:/bin',HOME:directory,CODEX_HOME:home}}};
    const configFile=path.join(directory,'host.json');
    fs.writeFileSync(configFile,JSON.stringify(config),{mode:0o600,flag:'wx'});
    child=spawn(process.execPath,[path.join(root,'host/connect.mjs'),configFile],
      {cwd:root,stdio:'ignore'});
    const exited=once(child,'close');let spawnError=false;
    child.on('error',()=>{spawnError=true});
    // Consume rejection if spawn fails; receipts carry only a fixed error code.
    void exited.catch(()=>{});
    const deadline=performance.now()+10000;
    while(!gateway.relay.connected('soak-owned-host')){
      if(spawnError||child.exitCode!==null||performance.now()>deadline)throw Error('owned_host_startup_failed');
      if(signal?.aborted)throw Error('soak_interrupted');await sleep(50);
    }
    client=new Client({name:'styx-owned-exec-soak',version:'0.1.0'});
    await client.connect(new StreamableHTTPClientTransport(new URL('http://'+host+'/mcp'),
      {requestInit:{headers:{Authorization:'Bearer '+modelToken}}}));
    receipt.phase='running';save(receiptFile,receipt);
    const samplesFile=path.join(directory,'samples.jsonl');
    while(true){
      if(signal?.aborted)throw Error('soak_interrupted');
      const marker='STYX_SOAK_'+receipt.passed_samples;
      const callBegan=performance.now();
      let result=await client.callTool({name:'exec_command',arguments:{
        environment_id:'soak-owned-host',cmd:'printf '+marker,login:false,yield_time_ms:250}});
      let output=result.structuredContent?.output??'';
      for(let i=0;!result.isError&&result.structuredContent?.session_id&&i<10;i++){
        result=await client.callTool({name:'write_stdin',arguments:{
          session_id:result.structuredContent.session_id,chars:'',yield_time_ms:250}});
        output+=result.structuredContent?.output??'';
      }
      if(result.isError||result.structuredContent?.exit_code!==0||output!==marker)
        throw Error('native_exec_sample_failed_or_uncertain');
      receipt.passed_samples++;
      receipt.elapsed_seconds=Math.floor((performance.now()-began)/1000);
      const memory=process.memoryUsage();
      const sample={at:new Date().toISOString(),sample:receipt.passed_samples,status:'PASS',
        elapsed_seconds:receipt.elapsed_seconds,latency_ms:Math.round(performance.now()-callBegan),
        gateway_rss_bytes:memory.rss,gateway_heap_used_bytes:memory.heapUsed,
        gateway_cpu_microseconds:process.cpuUsage(),exec_transport_connected:gateway.relay.connected('soak-owned-host')};
      fs.appendFileSync(samplesFile,JSON.stringify(sample)+'\n',{mode:0o600});
      save(receiptFile,receipt);
      if(performance.now()-began>=durationSeconds*1000)break;
      const waitUntil=Math.min(began+durationSeconds*1000,performance.now()+intervalSeconds*1000);
      while(performance.now()<waitUntil&&!signal?.aborted)await sleep(Math.min(250,waitUntil-performance.now()));
    }
    receipt.status='PASS';receipt.phase='completed';
    receipt.exec_transport_soak_24h=durationSeconds>=86400?'PASS':'NOT RUN';
  }catch(error){
    receipt.status=error.message==='soak_interrupted'?'BLOCKED':'FAIL';receipt.phase='stopped';
    receipt.reason=error.message==='soak_interrupted'?'soak_interrupted':'isolated_exec_soak_failed';
  }finally{
    await client?.close().catch(()=>{});
    if(child&&child.exitCode===null&&child.signalCode===null){
      child.kill('SIGTERM');
      await Promise.race([once(child,'close').catch(()=>{}),sleep(3000)]);
      if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');
    }
    await server?.close().catch(()=>{});
    receipt.elapsed_seconds=Math.floor((performance.now()-began)/1000);
    receipt.completed_at=new Date().toISOString();save(receiptFile,receipt);
  }
  return receipt;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const [directory,seconds,interval]=process.argv.slice(2);
  const abort=new AbortController();
  process.once('SIGINT',()=>abort.abort());process.once('SIGTERM',()=>abort.abort());
  const result=await runExecSoak({directory,durationSeconds:seconds===undefined?86400:Number(seconds),
    intervalSeconds:interval===undefined?60:Number(interval)},{signal:abort.signal});
  console.log(JSON.stringify(result));process.exitCode=result.status==='PASS'?0:result.status==='BLOCKED'?2:1;
}
