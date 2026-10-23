#!/usr/bin/env node
// Unattended, read-only native Cua MCP smoke. Does not capture user's screen
// or mutate any third-party application; exercises the official stdio MCP.
const {spawn} = require('node:child_process');
const fs = require('node:fs');
const {createHash} = require('node:crypto');
const readline = require('node:readline');

const binary=process.argv[2];
if (!binary) {console.error('usage: node native-cua-smoke.cjs <absolute-cua-driver-path> [socket]');process.exit(2)}
const socket=process.argv[3];
const args=['mcp',...(socket?['--socket',socket]:[]),...(process.env.STYX_CUA_DIRECT==='1'?['--direct']:[])];
const child=spawn(binary,args,{windowsHide:true,
  env:{...process.env,DO_NOT_TRACK:'1',CUA_DRIVER_RS_TELEMETRY_ENABLED:'false',
    ...(process.platform==='linux' ? {CUA_DRIVER_RS_ENABLE_WAYLAND:'1'} : {})},
  stdio:['pipe','pipe','pipe']});
const pending=new Map();let next=0,done=false,stderr='';
const errors=[];
child.stderr.on('data',x=>{stderr+=x.toString().slice(0,300)});
child.on('error',e=>{errors.push('spawn_'+e.code);});
child.on('exit',(code)=>{errors.push('exit_'+code);for(const x of pending.values()) x.reject(new Error('native_client_exited'));pending.clear();});
const rl=readline.createInterface({input:child.stdout});
rl.on('line',line=>{
  try {
    const obj=JSON.parse(line);
    if(obj.id===undefined) return;
    const deferred=pending.get(obj.id);if(!deferred)return;
    clearTimeout(deferred.timer);pending.delete(obj.id);
    obj.error?deferred.reject(new Error(String(obj.error.code||'rpc_error'))):deferred.resolve(obj.result);
  }catch{errors.push('invalid_jsonrpc');}
});
function rpc(method,params={},timeoutMs=9000) {
  const id=++next;
  return new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>{pending.delete(id);reject(new Error(method+'_timeout'))},timeoutMs);
    pending.set(id,{resolve,reject,timer});
    child.stdin.write(JSON.stringify({jsonrpc:'2.0',id,method,params})+'\n');
  });
}
function notify(method,params={}){child.stdin.write(JSON.stringify({jsonrpc:'2.0',method,params})+'\n')}
const watchdog=setTimeout(()=>{errors.push('global_timeout');finish(2,{phase:'timeout'})},27000);
function finish(code,data){if(done)return;done=true;clearTimeout(watchdog);
  child.stdin.end();setTimeout(()=>{try{child.kill()}catch{}},500).unref();
  console.log(JSON.stringify({pilot:'styx-cua-native-stdio',os:process.platform,
    ...data,exitStatus:code===0?'PASS':'BLOCKED'}));process.exitCode=code;
}
(async()=>{
  const init=await rpc('initialize',{protocolVersion:'2025-06-18',
    capabilities:{},clientInfo:{name:'styx-native-pilot',version:'0.1.0'}});
  notify('notifications/initialized');
  const list=await rpc('tools/list');
  const names=(list.tools||[]).map(t=>t.name);
  const required=['list_apps','list_windows','get_window_state','click','type_text','press_key','verify_state'];
  const missing=required.filter(t=>!names.includes(t));
  const selected=(list.tools||[]).filter(t=>required.includes(t.name))
    .map(x=>({name:x.name,schema:x.inputSchema}));
  const hash=createHash('sha256').update(JSON.stringify(selected)).digest('hex').slice(0,16);
  if(process.env.STYX_CUA_SCHEMA_FILE) {
    fs.writeFileSync(process.env.STYX_CUA_SCHEMA_FILE, JSON.stringify({
      platform:process.platform,serverVersion:init.serverInfo?.version,
      tools:(list.tools||[]).filter(t=>[
        'list_apps','list_windows','get_window_state','get_desktop_state',
        'click','set_value','type_text','press_key','scroll','verify_state'
      ].includes(t.name))
    },null,2),{mode:0o600});
  }
  let compatible=true,compatReason=null;
  if(process.env.STYX_CUA_PORTABLE_MANIFEST){
    const manifest=JSON.parse(fs.readFileSync(process.env.STYX_CUA_PORTABLE_MANIFEST));
    compatible=manifest.version===init.serverInfo?.version;
    const cosmetic=new Set(['description','title','default','examples','$comment']);
    function norm(x){
      if(Array.isArray(x))return x.map(norm);
      if(x&&typeof x==='object')return Object.fromEntries(Object.entries(x)
        .filter(([k])=>!cosmetic.has(k)).map(([k,v])=>[k,norm(v)]));
      return x;
    }
    for(const tool of manifest.tools){
      const actual=(list.tools||[]).find(t=>t.name===tool.name);
      if(!actual){compatible=false;compatReason='missing_'+tool.name;break}
      const original=actual.inputSchema||{};
      for(const [field,schema] of Object.entries(tool.inputSchema.properties||{})){
        if(field==='environment_id')continue;
        if(!Object.hasOwn(original.properties||{},field) ||
           JSON.stringify(norm(original.properties[field]))!==JSON.stringify(norm(schema))){
          compatible=false;compatReason=tool.name+'_'+field+'_incompatible';break;
        }
      }
      if(!compatible)break;
      if((original.required||[]).some(x=>!(tool.inputSchema.required||[]).includes(x))){
        compatible=false;compatReason=tool.name+'_required_mismatch';break;
      }
    }
  }
  const schemaOnly=process.env.STYX_CUA_SCHEMA_ONLY==='1';
  const apps=schemaOnly?null:await rpc('tools/call',{name:'list_apps',arguments:{}});
  const p=apps?.structuredContent ?? {};
  const count=Array.isArray(p.apps)?p.apps.length:
    (Number.isInteger(p.count)?p.count:null);
  finish(missing.length===0 && compatible && apps?.isError!==true ? 0:2, {
    initialized:!!init,serverName:init.serverInfo?.name||'unknown',
    serverVersion:init.serverInfo?.version||null,
    toolCount:names.length,requiredToolSchemaHash:hash,missing,
    tools:selected.map(x=>({name:x.name,hash:createHash('sha256').update(JSON.stringify(x.schema)).digest('hex').slice(0,12),
      required:x.schema.required||[],properties:Object.keys(x.schema.properties||{})})),
    portableSchemaCompatible:compatible,compatReason,schemaOnly,
    listAppsError:apps?.isError===true,reportedAppCount:count,
    stdoutProtocol:'jsonrpc-lines',warnings:errors
  });
})().catch(e=>finish(2,{phase:String(e.message).slice(0,120),warnings:errors}));
