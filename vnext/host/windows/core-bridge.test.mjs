import test from 'node:test';
import assert from 'node:assert/strict';
import {PassThrough} from 'node:stream';
import {bootstrap,createClient,serve} from './core-bridge.mjs';
const url='http://127.0.0.1:34991/#session='+'A'.repeat(43);
test('private bootstrap refuses remote credentials and unexpected URL components',()=>{assert.equal(bootstrap(url).token,'A'.repeat(43));for(const u of ['https://127.0.0.1:3/#session=abc',url.replace('127.0.0.1','example.com'),url.replace('/#','/?q=x#'),url.replace('127.0.0.1','u:p@127.0.0.1')])assert.throws(()=>bootstrap(u));});
function fixture(){const requests=[];let steps=[{id:'host.prepare',status:'pending'}];const fetchImpl=async(url,options)=>{const route=new URL(url).pathname.slice(5),body=options.body?JSON.parse(options.body):null;requests.push({route,options,body});let data={};if(route==='session')data={csrf:'B'.repeat(43),defaults:{bundle:'/signed/bundle',publisherKeyFile:'/signed/key',publisherSha256:'a'.repeat(64),baseDir:'/private/host',gatewayUrl:'https://127.0.0.1:22022'}};if(route==='status')data={ownerPairingScope:{gatewayUrl:'https://127.0.0.1:22022',label:'PC',enableComputer:true,enableBrowser:false},deployment:{mode:'create-local',steps,roles:{browser:'not_requested'}}};if(route==='local-setup')steps=[{id:'host.prepare',status:'succeeded'}];if(route==='pairing-link/inspect')data={inspectionId:'inspect',preview:{origin:'https://owner.example',caSha256:'c'.repeat(64)}};if(route==='pairing-link/accept')data={joinLinkId:'accepted',origin:'https://owner.example'};return {ok:true,headers:new Headers({'content-type':'application/json'}),text:async()=>JSON.stringify(data)};};return {requests,fetchImpl};}
const req=(operation,input={})=>({schema:1,id:1,operation,input});
test('native create uses authoritative Core defaults and CSRF, never arbitrary routes',async()=>{const f=fixture(),c=await createClient({url},{fetchImpl:f.fetchImpl});await c.dispatch(req('create',{label:'PC',computer:true,browser:true,browserChannel:'msedge',persistLogin:true}));const r=f.requests.at(-1);assert.equal(r.route,'create');assert.equal(r.body.host.bundle,'/signed/bundle');assert.equal(r.body.host.browser.channel,'msedge');assert.equal(r.options.headers['X-Styx-CSRF'],'B'.repeat(43));assert.equal(r.options.redirect,'error');await assert.rejects(c.dispatch(req('../secrets')));});
test('join requires explicit matching scope, then same Core accept/create API',async()=>{const f=fixture(),c=await createClient({url},{fetchImpl:f.fetchImpl});await assert.rejects(c.dispatch(req('join',{label:'PC'})));await c.dispatch(req('inspectJoin',{link:'private secret link'}));await assert.rejects(c.dispatch(req('join',{approvedGatewayOrigin:'https://attacker'})));await c.dispatch(req('join',{label:'PC',approvedGatewayOrigin:'https://owner.example',approvedCaSha256:'c'.repeat(64)}));assert.equal(f.requests.at(-1).body.joinLinkId,'accepted');});
test('prepare delegates to Core local workflow with exact owner scope',async()=>{const f=fixture(),c=await createClient({url},{fetchImpl:f.fetchImpl});await c.dispatch(req('prepare'));assert.deepEqual(f.requests.filter(x=>x.route==='local-setup')[0].body.ownerApproval,{gatewayUrl:'https://127.0.0.1:22022',label:'PC',enableComputer:true,enableBrowser:false,approve:true});assert(!f.requests.some(x=>x.route==='foreground'));});
test('join pauses for the main computer and resumes the same request without creating a Gateway',async()=>{
 let confirmed=false;const calls=[],steps=[{id:'host.prepare',status:'succeeded'},{id:'host.request',status:'succeeded',comparison_code:'ABCD-0123-EF45-6789'},{id:'host.claim',status:'awaiting_approval'},{id:'host.doctor',status:'pending'}];
 const client=await createClient({url},{fetchImpl:async(address,options)=>{const route=new URL(address).pathname.slice(5),body=options.body?JSON.parse(options.body):null;calls.push(route);let data={};
  if(route==='session')data={csrf:'B'.repeat(43)};
  if(route==='status'||route==='snapshot')data={deployment:{mode:'join-existing',roles:{browser:'disabled'},steps}};
  if(route==='advance'){assert.deepEqual(body.authorize,[confirmed&&steps[2].status==='succeeded'?'host.doctor':'host.claim']);if(confirmed)steps.find(s=>s.id===body.authorize[0]).status='succeeded';}
  return {ok:true,headers:new Headers({'content-type':'application/json'}),text:async()=>JSON.stringify(data)};
 }});
 await client.dispatch(req('prepare'));assert.equal(steps[2].status,'awaiting_approval');assert.equal(calls.filter(r=>r==='advance').length,1);
 confirmed=true;await client.dispatch(req('prepare'));assert.equal(steps[3].status,'succeeded');assert.equal(calls.filter(r=>r==='advance').length,3);assert(!calls.some(r=>['create','local-setup','foreground'].includes(r)));
 steps[0].status='uncertain';const before=calls.filter(r=>r==='advance').length;await client.dispatch(req('prepare'));assert.equal(calls.filter(r=>r==='advance').length,before);
});
test('pipe hides raw failures and closes owned Core on EOF',async()=>{const input=new PassThrough(),output=new PassThrough();let text='',closed=false;output.on('data',b=>text+=b);const f=fixture();const instance={url,close:async()=>{closed=true;}};input.end('{"secret":"never echo"}\n');await serve({input,output,instance,client:await createClient(instance,{fetchImpl:f.fetchImpl})});assert.equal(closed,true);assert(!text.includes('never echo'));assert.equal(JSON.parse(text.trim()).ok,false);});

test('native desktop entrypoint is package pinned and rejects noninteractive/secure contexts',async t=>{
 const fs=await import('node:fs'),os=await import('node:os'),path=await import('node:path'),{createHash}=await import('node:crypto'),{nativeDesktopAvailable}=await import('./core-bridge.mjs');
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-probe-pin-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));const file=path.join(root,'StyxSessionProbe.exe');fs.writeFileSync(file,'native-probe-fixture');const pin={path:'StyxSessionProbe.exe',sha256:createHash('sha256').update(fs.readFileSync(file)).digest('hex')};
 const ready={schema:1,status:'available',sessionId:2,interactive:true,windowStation:'WinSta0',inputDesktop:'Default'};let ran=false;
 const run=(binary,args,options)=>{ran=true;assert.equal(binary,file);assert.deepEqual(args,[]);assert.equal(options.timeout,5000);assert.equal(options.maxBuffer,4096);assert.deepEqual(options.stdio,['ignore','pipe','ignore']);assert(!Object.keys(options.env).some(k=>/KEY|TOKEN|STYX/i.test(k)));return JSON.stringify(ready);};
 assert.equal(nativeDesktopAvailable(root,pin,{run,platform:'win32'}),true);assert.equal(ran,true);
 for(const mutation of [{schema:2},{sessionId:0},{interactive:false},{windowStation:'Service-0'},{inputDesktop:'Winlogon'},{status:'session_unavailable'}])assert.equal(nativeDesktopAvailable(root,pin,{run:()=>JSON.stringify({...ready,...mutation}),platform:'win32'}),false);
 for(const invalid of [undefined,{...pin,path:'../probe.exe'},{...pin,sha256:'f'.repeat(64)}]){ran=false;assert.equal(nativeDesktopAvailable(root,invalid,{run,platform:'win32'}),false);assert.equal(ran,false);}
 assert.equal(nativeDesktopAvailable(root,pin,{run:()=>{throw Error('unavailable');},platform:'win32'}),false);
 assert.equal(nativeDesktopAvailable(root,pin,{run:()=>'x'.repeat(4097),platform:'win32'}),false);
});


test('concurrent status reads share one snapshot, then observe fresh state without mutations',async()=>{
 const routes=[];let release,count=0;
 const client=await createClient({url,desktopAcceptanceSupported:true},{fetchImpl:async(address,options)=>{
  const route=new URL(address).pathname.slice(5);routes.push(route);assert.equal(options.method,'GET');assert.equal(options.body,undefined);
  let data=route==='session'?{csrf:'B'.repeat(43)}:{};
  if(route==='snapshot'){count++;if(count===1)await new Promise(resolve=>release=resolve);data={status:{foreground:{status:count===1?'started':'connected'}}};}
  return {ok:true,headers:new Headers({'content-type':'application/json'}),text:async()=>JSON.stringify(data)};
 }});
 const first=client.dispatch(req('status')),second=client.dispatch(req('status'));assert.equal(count,1);release();
 const [a,b]=await Promise.all([first,second]);assert.deepEqual(a,b);assert.equal(a.session.desktopAcceptanceSupported,true);assert.equal(a.status.foreground.status,'started');
 assert.equal((await client.dispatch(req('status'))).status.foreground.status,'connected');assert.deepEqual(routes,['session','snapshot','snapshot']);
});

test('a failed observation is not cached and does not prevent a later refresh',async()=>{
 let count=0;const client=await createClient({url},{fetchImpl:async address=>{const route=new URL(address).pathname.slice(5);if(route==='snapshot'&&++count===1)throw Error('private transport details');const data=route==='session'?{csrf:'B'.repeat(43)}:{status:{foreground:{status:'connected'}}};return {ok:true,headers:new Headers({'content-type':'application/json'}),text:async()=>JSON.stringify(data)};}});
 await assert.rejects(client.dispatch(req('status')));assert.equal((await client.dispatch(req('status'))).status.foreground.status,'connected');assert.equal(count,2);
});

test('native desktop readback sends only current challenge evidence; unknown browser preferences stay omitted',async()=>{
 const f=fixture(),client=await createClient({url},{fetchImpl:f.fetchImpl});
 await client.dispatch(req('acceptanceDesktopReadback',{challengeId:'a'.repeat(32),value:'STYX_GUI_'+'b'.repeat(32),pid:123,windowId:456,authorize:false,nativeAppGeneration:'forged'}));
 assert.equal(f.requests.at(-1).route,'acceptance/desktop-readback');assert.deepEqual(f.requests.at(-1).body,{authorize:true,challengeId:'a'.repeat(32),value:'STYX_GUI_'+'b'.repeat(32),pid:123,windowId:456});
 await client.dispatch(req('setCapabilities',{computer:true,browser:false}));assert.deepEqual(f.requests.at(-1).body,{authorize:true,computer:true,browser:false});
});

test('only fixed actionable native failures cross HTTP and pipe boundaries',async()=>{
 for(const reason of ['windows_native_app_binding_required','desktop_acceptance_native_app_changed','work_in_progress','work_state_unknown','private-path-token-value']){
  const client=await createClient({url},{fetchImpl:async address=>{const session=new URL(address).pathname==='/api/session';return {ok:session,headers:new Headers({'content-type':'application/json'}),text:async()=>JSON.stringify(session?{csrf:'B'.repeat(43)}:{error:reason,detail:'NEVER_EXPOSE_PRIVATE_DETAIL'})};}});
  const input=new PassThrough(),output=new PassThrough();let result='';output.on('data',data=>result+=data);input.end(JSON.stringify(req('acceptanceBegin'))+'\n');await serve({input,output,instance:{url,close:async()=>{}},client});
  const response=JSON.parse(result.trim());assert.equal(response.ok,false);assert.equal(response.error,reason==='private-path-token-value'?'operation_failed_review_settings':reason);assert(!result.includes('NEVER_EXPOSE_PRIVATE_DETAIL'));assert(!result.includes('private-path-token-value'));
 }
});

test('native add-computer asks for an interface only when ambiguous and keeps invitation lifecycle explicit',async()=>{
 const calls=[];const client=await createClient({url},{fetchImpl:async(address,options)=>{
  const route=new URL(address).pathname.slice(5),body=options.body?JSON.parse(options.body):null;calls.push({route,body});
  const data=route==='session'?{csrf:'B'.repeat(43)}:route==='device-ingress/plan'?{ingress:{gateway:'local',blockers:[],requiresInterfaceChoice:true,candidates:['192.0.2.10','192.0.2.11']}}:route==='pairing-link/create'?{link:'private-fixture-invitation'}:{};
  return {ok:true,headers:new Headers({'content-type':'application/json'}),text:async()=>JSON.stringify(data)};
 }});
 assert.equal((await client.dispatch(req('inviteComputer'))).status,'select_network_interface');assert(!calls.some(x=>x.route==='pairing-link/create'));
 assert.equal((await client.dispatch(req('inviteComputer',{listenHost:'192.0.2.10',tlsPrivateKeyFile:'never forward'}))).status,'waiting_for_computer');assert.deepEqual(calls.at(-1),{route:'pairing-link/create',body:{authorize:true,listenHost:'192.0.2.10'}});
 await client.dispatch(req('pendingComputers'));assert.equal(calls.at(-1).route,'pending/list');assert(!calls.some(x=>x.route==='pairing-link/close'));
 await client.dispatch(req('closePairing'));assert.deepEqual(calls.at(-1),{route:'pairing-link/close',body:{authorize:true}});
});

test('save-and-connect retains the same explicit Tunnel resume choice as the Mac app',async()=>{
 const f=fixture(),client=await createClient({url},{fetchImpl:f.fetchImpl});
 await client.dispatch(req('tunnelSave',{tunnelId:'tunnel_owned_fixture',runtimeKey:'sk-fixture-not-a-real-key',autoStart:false,binary:'never-forward'}));
 assert.deepEqual(f.requests.at(-1).body,{authorize:true,tunnelId:'tunnel_owned_fixture',apiKey:'sk-fixture-not-a-real-key',autoStart:true});
 assert.equal(f.requests.at(-1).route,'tunnel/configure');
});

test('native component upgrade uses shared handoff APIs and only a trusted launch callback',async()=>{
 const f=fixture(),ticketId='a'.repeat(32),launches=[];
 const c=await createClient({url,launchHostPayloadHandoff:async id=>{launches.push(id);return {status:'launched',ticketId:id}}},{fetchImpl:f.fetchImpl});
 await c.dispatch(req('runtimeUpgradePrepare',{bundle:'C:\\foreign',publisher:'foreign'}));assert.deepEqual(f.requests.at(-1).body,{authorize:true});assert.equal(f.requests.at(-1).route,'host-payload/handoff/prepare');assert.equal(f.requests.at(-1).options.signal,undefined);
 await c.dispatch(req('runtimeUpgradeLaunch',{ticketId}));assert.deepEqual(launches,[ticketId]);await assert.rejects(c.dispatch(req('runtimeUpgradeLaunch',{ticketId:'../escape'})),/native_handoff_unavailable/);
 await c.dispatch(req('runtimeUpgradeStatus'));assert.equal(f.requests.at(-2).route,'host-payload/handoff/status');assert.equal(f.requests.at(-1).route,'host-payload/status');
 await c.dispatch(req('runtimeUpgradeCancel',{ticketId}));assert.deepEqual(f.requests.at(-1).body,{authorize:true,ticketId});
 const plain=await createClient({url},{fetchImpl:f.fetchImpl});await assert.rejects(plain.dispatch(req('runtimeUpgradeLaunch',{ticketId})),/native_handoff_unavailable/);
});

test("native quit requests shared work admission without accepting caller flags",async()=>{const f=fixture(),c=await createClient({url},{fetchImpl:f.fetchImpl});await c.dispatch(req("quitAdmission",{force:true,authorize:false}));assert.deepEqual(f.requests.at(-1).body,{authorize:true});assert.equal(f.requests.at(-1).route,"app/quit-admission");});
