import path from 'node:path';
import fs from 'node:fs';
import {pathToFileURL} from 'node:url';
import {createConnection} from '@playwright/mcp';
import {chromium} from 'playwright';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {Server} from '@modelcontextprotocol/sdk/server/index.js';
import {InMemoryTransport} from '@modelcontextprotocol/sdk/inMemory.js';
import {CallToolRequestSchema,ListToolsRequestSchema,ListRootsRequestSchema} from '@modelcontextprotocol/sdk/types.js';
import {ensurePrivateDirectory,requirePrivateDirectory} from '../../host/private-storage.mjs';
import {prepareManagedBrowser} from './prepare.mjs';
import {normalizeBrowserConfig} from './config.mjs';
import {BROWSER_CONTRACT,BROWSER_VERSION,BROWSER_META_OWNER,BROWSER_OWNER_CLOSED,BROWSER_STATE_CHANGED,browserTools,browserFailure} from './contract.mjs';
const ownerPattern=/^[a-f0-9]{64}$/;
const localFileURL=value=>{try{return new URL(value).protocol==='file:'}catch{return false}};
const referenceTarget=(value,key='')=>Array.isArray(value)?value.some(v=>referenceTarget(v)):value&&typeof value==='object'?Object.entries(value).some(([k,v])=>referenceTarget(v,k)):['target','startTarget','endTarget'].includes(key)&&typeof value==='string'&&/^(?:f\d+)?e\d+$/.test(value);
const exactContract=tools=>JSON.stringify(tools.filter(t=>!BROWSER_CONTRACT.omitted.includes(t.name)))===JSON.stringify(browserTools);

// One Host owns the real contexts. Transport reconnects do not recreate browsers,
// clear login profiles, repeat tool calls, or share an upstream current tab.
export class HostBrowserSupervisor{
  constructor({browser,cwd,idleMs=15*60*1000,clock=()=>Date.now(),operations={}}={}){
    this.config=normalizeBrowserConfig(browser);
    if(!this.config||typeof cwd!=='string'||!path.isAbsolute(cwd))throw Error('browser_workspace_required');
    if(!Number.isSafeInteger(idleMs)||idleMs<1000)throw Error('invalid_browser_idle_policy');
    if(!this.config.headless&&process.platform==='linux'&&!process.env.DISPLAY&&!process.env.WAYLAND_DISPLAY)throw Error('browser_gui_session_unavailable');
    this.operations=operations;this.abort=new AbortController();this.runtime=null;this.cwd=cwd;this.idleMs=idleMs;this.clock=clock;this.leases=new Map();this.stopped=false;this.servers=new Set();
    requirePrivateDirectory(path.dirname(this.config.profileRoot));
    ensurePrivateDirectory(this.config.profileRoot);
    const workspace=fs.realpathSync(cwd),profiles=fs.realpathSync(this.config.profileRoot);
    const inside=(base,file)=>{const relative=path.relative(base,file);return relative===''||(!relative.startsWith('..'+path.sep)&&relative!=='..'&&!path.isAbsolute(relative));};
    if(inside(workspace,profiles)||inside(profiles,workspace))throw Error('browser_workspace_profile_overlap');
    this.cwd=workspace;
    this.timer=setInterval(()=>{void this.reapIdle().catch(()=>{})},Math.min(idleMs,30000));this.timer.unref?.();
  }
  notify(owner,state){for(const server of this.servers)void server.notification({method:BROWSER_STATE_CHANGED,params:{owner,state}}).catch(()=>{});}
  status(owner){const lease=this.leases.get(owner);return {state:lease?.uncertain||lease?.closeError?'unknown':lease?.context&&!lease.closed?'ready_observed':'not_started',active:lease?.active??0,headless:this.config.headless,version:lease?.context?.browser()?.version()??'unknown'};}
  async lease(owner){
    if(this.stopped)throw Error('browser_provider_closed');
    if(!ownerPattern.test(owner??''))throw Error('browser_owner_required');
    const existing=this.leases.get(owner);if(existing){if(existing.closed){await existing.closing;return this.lease(owner);}return existing.opening;}
    const folder=path.join(this.config.profileRoot,owner),profile=path.join(folder,'profile'),output=path.join(folder,'output');
    for(const dir of [folder,profile,output])ensurePrivateDirectory(dir);
    const item={owner,context:null,client:null,server:null,tail:Promise.resolve(),active:0,queued:0,closed:false,uncertain:false,observation:0,snapshotObservation:null,lastUsed:this.clock(),profile,output};
    item.opening=(async()=>{
      const native=await (this.operations.createConnection??createConnection)({browser:{browserName:'chromium',isolated:false},capabilities:['core'],webmcp:false,
        outputDir:output,filePaths:'absolute',snapshot:{mode:'none'},imageResponses:'allow',timeouts:{idle:0}},async()=>{
          if(item.closed||this.stopped)throw Error('browser_owner_closed');
          if(!item.context){
            item.launching??=(async()=>{
              if(!this.config.executablePath){this.runtime??=prepareManagedBrowser({profileRoot:this.config.profileRoot,authorize:true,signal:this.abort.signal}).catch(error=>{this.runtime=null;throw error;});const prepared=await this.runtime;if(item.closed||this.stopped)throw Error('browser_owner_closed');item.executablePath=prepared.executablePath;}
              const launch=this.operations.launchContext??((profile,options)=>chromium.launchPersistentContext(profile,options));
              const context=await launch(profile,{headless:this.config.headless,chromiumSandbox:true,
                executablePath:this.config.executablePath??item.executablePath,acceptDownloads:true,downloadsPath:output,
                viewport:{width:1280,height:800}});
              item.context=context;
              const invalidate=()=>{item.observation++;item.snapshotObservation=null;this.notify(owner,{readiness:'ready_observed',observationChanged:true,headless:this.config.headless,version:context.browser()?.version()??'unknown'});};
              const observePage=page=>{page.on('framenavigated',invalidate);page.on('close',invalidate);};
              for(const page of context.pages?.()??[])observePage(page);
              context.on('page',page=>{observePage(page);invalidate();});
              context.once('close',()=>{if(item.context===context){item.context=null;item.launching=null;}this.notify(owner,{readiness:'not_started',headless:this.config.headless,version:'unknown'});});
              if(!item.closed&&!this.stopped)this.notify(owner,{readiness:'ready_observed',headless:this.config.headless,version:context.browser()?.version()??'unknown'});
              return context;
            })();
            await item.launching;
          }
          if(item.closed||this.stopped)throw Error('browser_owner_closed');
          return item.context;
        });
      const client=new Client({name:'styx-browser-owner',version:'0.1.0'},{capabilities:{roots:{listChanged:false}}});
      client.setRequestHandler(ListRootsRequestSchema,async()=>({roots:[{uri:pathToFileURL(this.cwd).href,name:'workspace'},{uri:pathToFileURL(output).href,name:'browser-output'}]}));
      const [a,b]=InMemoryTransport.createLinkedPair();item.client=client;item.server=native;
      await native.connect(a);await client.connect(b);
      if(!exactContract((await client.listTools()).tools))throw Error('browser_upstream_contract_changed');
      return item;
    })();
    this.leases.set(owner,item);
    try{return await item.opening;}catch(error){await this.closeOwner(owner);throw error;}
  }
  async callTool(name,args,owner){
    if(!browserTools.some(t=>t.name===name))return browserFailure('unknown_tool');
    const item=await this.lease(owner);
    const previous=item.tail;let release;item.tail=new Promise(r=>{release=r});item.queued++;
    await previous;item.queued--;item.active++;
    try{
      if(item.closed||this.stopped)throw Error('browser_owner_closed');
      // RPC rejection is not proof that a native operation stopped. Keep the
      // lease uncertain until explicit, confirmed context closure; never replay.
      if(item.uncertain){
        if(name!=='browser_close')return browserFailure('browser_result_unconfirmed_close_required',true);
        await this.closeOwner(owner);
        return {content:[{type:'text',text:'Browser context closed. The previous action outcome remains unconfirmed; do not replay it automatically.'}]};
      }
      if(['browser_navigate','browser_tabs'].includes(name)&&typeof args.url==='string'&&localFileURL(args.url))return browserFailure('browser_file_navigation_denied');
      if(referenceTarget(args)&&item.snapshotObservation!==item.observation)return browserFailure('browser_snapshot_required');
      const observation=item.observation;let result;
      try{result=await item.client.callTool({name,arguments:args});}
      catch(error){item.uncertain=true;this.notify(owner,{readiness:'unknown',headless:this.config.headless,version:'unknown'});throw error;}
      if(name==='browser_snapshot'&&!args.filename&&!result.isError&&observation===item.observation)item.snapshotObservation=item.observation;
      if(name==='browser_close'&&!result.isError)await this.closeOwner(owner);
      const status=this.status(owner);this.notify(owner,{readiness:status.state,headless:status.headless,version:status.version});
      return result;
    }finally{item.active--;item.lastUsed=this.clock();release();}
  }
  createServer(){
    const supervisor=this;
    const server=new Server({name:'styx-browser-host',version:BROWSER_VERSION},{capabilities:{tools:{}}});
    server.setRequestHandler(ListToolsRequestSchema,async()=>({tools:browserTools}));
    server.setRequestHandler(CallToolRequestSchema,async({params})=>{
      const owner=params._meta?.[BROWSER_META_OWNER];
      if(!ownerPattern.test(owner??''))return browserFailure('browser_owner_required');
      try{return await supervisor.callTool(params.name,params.arguments??{},owner);}
      catch(error){return browserFailure(['browser_upstream_contract_changed','browser_owner_closed'].includes(error.message)?error.message:'browser_native_unavailable',true);}
    });
    server.fallbackNotificationHandler=async({method,params})=>{if(method===BROWSER_OWNER_CLOSED&&ownerPattern.test(params?.owner??''))await supervisor.closeOwner(params.owner)};
    const onclose=server.onclose;server.onclose=()=>{this.servers.delete(server);onclose?.();};this.servers.add(server);
    return server;
  }
  async closeOwner(owner){
    const item=this.leases.get(owner);if(!item)return;if(item.closing)return item.closing;
    item.closed=true;
    item.closing=(async()=>{
      try{
        // Opening/launching can finish after shutdown begins. Retain ownership
        // until the actual context has settled and its closure is confirmed.
        await item.opening.catch(()=>{});
        await item.launching?.catch(()=>{});
        await item.context?.close();item.context=null;
        await item.client?.close();await item.server?.close();
        this.notify(owner,{readiness:'not_started',headless:this.config.headless,version:'unknown'});
        if(this.leases.get(owner)===item)this.leases.delete(owner);
      }catch(error){item.closeError=error;this.notify(owner,{readiness:'unknown',headless:this.config.headless,version:'unknown'});throw Error('browser_shutdown_unconfirmed');}
    })();try{return await item.closing;}catch(error){item.closing=null;throw error;}
  }
  async reapIdle(){for(const [owner,item]of this.leases)if(!item.active&&!item.queued&&this.clock()-item.lastUsed>=this.idleMs)await this.closeOwner(owner);}
  async close(){
    this.stopped=true;this.abort.abort();await this.runtime?.catch(()=>{});clearInterval(this.timer);
    const results=await Promise.allSettled([...this.leases.keys()].map(owner=>this.closeOwner(owner)));
    for(const server of this.servers)await server.close().catch(()=>{});this.servers.clear();
    if(results.some(result=>result.status==='rejected'))throw Error('browser_shutdown_unconfirmed');
  }
}
