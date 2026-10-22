// Opt-in native Chrome/Edge acceptance; only new private profiles and our own
// loopback page are used. No account login or daily profile is inspected.
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import {fileURLToPath} from 'node:url';
import {HostBrowserSupervisor} from '../packages/styx-browser-provider/host.mjs';
const assert=(ok,why)=>{if(!ok)throw Error(why)};
const text=result=>(result.content??[]).filter(x=>x.type==='text').map(x=>x.text).join('\n');
export async function runLinuxBrowserAcceptance({directory,channel,executablePath}={}){
 assert(process.platform==='linux'&&process.env.STYX_RUN_LINUX_BROWSER_ACCEPTANCE==='1','explicit_linux_browser_acceptance_required');
 assert(['chrome','msedge'].includes(channel),'explicit_browser_channel_required');
 assert(typeof directory==='string'&&path.isAbsolute(directory)&&!fs.existsSync(directory),'fresh_private_acceptance_directory_required');
 assert(executablePath===undefined||path.isAbsolute(executablePath),'absolute_browser_executable_required');
 fs.mkdirSync(directory,{mode:0o700});const work=path.join(directory,'work');fs.mkdirSync(work,{mode:0o700});
 let stores=0,server,supervisor;const receipt={schema:1,status:'RUNNING',channel,desktop:'headless native browser',profile:'new task-private profiles',realAccountLogin:'NOT RUN',gates:[]};
 try{
  server=http.createServer((req,res)=>{
   if(req.url==='/store'&&req.method==='POST'){stores++;res.end('Saved native browser');return}
   res.setHeader('Content-Type','text/html');res.end('<!doctype html><title>Styx browser fixture</title><label>Name <input id="name"></label><button onclick="fetch(\'/store\',{method:\'POST\'}).then(r=>r.text()).then(t=>document.querySelector(\'output\').textContent=t)">Store</button><output></output>');
  });await new Promise(r=>server.listen(0,'127.0.0.1',r));
  supervisor=new HostBrowserSupervisor({browser:{enabled:true,headless:true,channel,persistLogin:true,profileRoot:path.join(directory,'profiles'),...(executablePath?{executablePath}:{})},cwd:work});
  const first='1'.repeat(64),second='2'.repeat(64),principal='3'.repeat(64),url='http://127.0.0.1:'+server.address().port;
  const call=async(name,args,owner=first)=>{const r=await supervisor.callTool(name,args,owner,principal);assert(!r.isError,'native_'+name+'_failed');return r};
  const ref=(snapshot,label)=>{const match=new RegExp('"'+label+'"[^\\n]*\\[ref=([^\\]]+)\\]').exec(text(snapshot));assert(match,'owned_reference_missing');return match[1]};
  await call('browser_navigate',{url});let snapshot=await call('browser_snapshot',{});
  await call('browser_type',{target:ref(snapshot,'Name'),text:channel});snapshot=await call('browser_snapshot',{});
  await call('browser_click',{target:ref(snapshot,'Store')});
  for(let i=0;i<30&&stores!==1;i++)await new Promise(r=>setTimeout(r,100));assert(stores===1,'independent_http_action_readback_failed');
  snapshot=await call('browser_snapshot',{});assert(text(snapshot).includes('Saved native browser'),'snapshot_readback_failed');receipt.gates.push('snapshot_type_click_independent_http_and_dom_readback');
  const shot=await call('browser_take_screenshot',{type:'png'});assert(shot.content?.some(x=>x.type==='image'&&x.mimeType==='image/png'),'native_screenshot_missing');receipt.gates.push('native_png_screenshot');
  receipt.browserVersion=supervisor.status(first).version;
  await call('browser_evaluate',{function:"()=>{document.cookie='styx_fixture=retained; path=/; max-age=3600';localStorage.setItem('styx_fixture','retained');return 'saved synthetic state'}"});
  const firstProfile=supervisor.leases.get(first).profile;await supervisor.closeOwner(first);
  await call('browser_navigate',{url},second);assert(supervisor.leases.get(second).profile!==firstProfile,'profile_reused');
  const state=await supervisor.leases.get(second).context.storageState();assert(state.cookies.some(c=>c.name==='styx_fixture'&&c.value==='retained')&&state.origins.some(o=>o.localStorage.some(x=>x.name==='styx_fixture'&&x.value==='retained')),'synthetic_state_not_restored');
  assert(stores===1,'browser_action_replayed');receipt.gates.push('new_owner_synthetic_state_restored_without_action_replay');receipt.status='PASS';receipt.independentActionCount=stores;
 }catch(error){receipt.status='FAIL';receipt.reason=error.message;}
 finally{await supervisor?.close();if(server)await new Promise(r=>server.close(r));for(const name of ['profiles','work'])fs.rmSync(path.join(directory,name),{recursive:true,force:true});receipt.cleanup='browser_closed_private_profiles_removed';fs.writeFileSync(path.join(directory,'receipt.json'),JSON.stringify(receipt,null,2)+'\n',{mode:0o600})}
 return receipt;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const result=await runLinuxBrowserAcceptance(JSON.parse(fs.readFileSync(process.argv[2],'utf8')));console.log(JSON.stringify(result));process.exitCode=result.status==='PASS'?0:1;
}
