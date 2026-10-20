import fs from 'node:fs';
import {requirePrivateFile} from '../shared/private-file.mjs';
import {EventEmitter} from 'node:events';
import {createHash,timingSafeEqual} from 'node:crypto';
import {WebSocket,WebSocketServer} from 'ws';
import {RpcClient} from '../packages/styx-exec-adapter/rpc.mjs';

const MAX_FRAME = 2 * 1024 * 1024;
const MAX_COMPUTER_FRAME = 8 * 1024 * 1024;
const HOST_PATH = /^\/styx\/hosts\/([A-Za-z0-9][A-Za-z0-9._-]{0,127})\/(exec|computer|browser)$/;
const TOKEN = /^Bearer ([A-Za-z0-9_-]{32,})$/;
function readToken(filename) {
  if (typeof filename !== 'string') throw Error('outbound_token_not_configured');
  requirePrivateFile(filename);
  const value=fs.readFileSync(filename,'utf8').trim();
  if (value.length<32 || /\s/.test(value) || !/^[A-Za-z0-9_-]+$/.test(value))
    throw Error('outbound_token_invalid');
  return createHash('sha256').update(value).digest();
}
function bearerCount(req) {
  return (req.rawHeaders??[]).filter((_,i)=>i%2===0)
    .filter(s=>s.toLowerCase()==='authorization').length;
}
function reject(socket,code) {
  if (!socket.destroyed) socket.end('HTTP/1.1 '+code+' Rejected\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
}
function disconnected() { return Error('host_disconnected'); }

// The outbound Host supplies a single WebSocket carrying unmodified Codex
// Exec JSON-RPC frames. No second RPC protocol is defined by Styx.
// The Host bearer is distinct from inbound MCP authorization.
export class OutboundHostRelay {
  constructor({registry,heartbeatMs=15000,computerAcquireWaitMs=5000}={}) {
    if (!registry || typeof registry.resolve!=='function') throw TypeError('Registry required');
    if(!Number.isSafeInteger(computerAcquireWaitMs)||computerAcquireWaitMs<0||computerAcquireWaitMs>30000)
      throw TypeError('Invalid Computer acquisition wait');
    this.registry=registry;this.heartbeatMs=heartbeatMs;
    this.computerAcquireWaitMs=computerAcquireWaitMs;
    this.sessions=new Map();this.computerPeers=new Map();this.browserPeers=new Map();
    this.stopped=false;this.attached=false;
    this.wss=new WebSocketServer({noServer:true,maxPayload:MAX_COMPUTER_FRAME,perMessageDeflate:false});
  }
  attach(server,{allowedHosts}={}) {
    if (this.attached) throw Error('host_relay_already_attached');
    if (!Array.isArray(allowedHosts)) throw Error('explicit_upgrade_hosts_required');
    this.attached=true;
    server.on('upgrade',(req,socket,head)=>{
      const path=(req.url??'').split('?')[0];
      if (!path.startsWith('/styx/hosts/')) {socket.destroy();return}
      const match=HOST_PATH.exec(req.url??'');
      if (!match || !allowedHosts.includes(req.headers.host)) {reject(socket,403);return}
      const hostId=match[1],lane=match[2];
      let target;
      try { target=this.registry.resolve(hostId); }
      catch {reject(socket,403);return}
      if (this.stopped || target.kind!=='host' || target.exec?.transport!=='outbound' ||
          (lane==='computer' && (target.computer?.enabled!==true ||
            target.computer?.transport!=='outbound')) ||
          (lane==='browser'&&(target.browser?.enabled!==true||target.browser?.transport!=='outbound'))) {
        reject(socket,403);return;
      }
      if (req.headers.origin!==undefined) {reject(socket,401);return}
      if (target.exec.client_certificate_sha256) {
        // The HTTPS server must request client certificates. A valid pinned
        // public certificate replaces a shared Host bearer; private keys stay
        // on their own hosts. Never accept an unencrypted peer as mTLS.
        const cert=req.socket.getPeerCertificate?.(true);
        const fingerprint=cert?.raw &&
          createHash('sha256').update(cert.raw).digest();
        const expected=Buffer.from(target.exec.client_certificate_sha256,'hex');
        if (!req.socket.encrypted || !fingerprint ||
            fingerprint.length!==expected.length ||
            !timingSafeEqual(fingerprint,expected) ||
            bearerCount(req)!==0) {reject(socket,401);return}
      } else {
        if(bearerCount(req)!==1) {reject(socket,401);return}
        const matchBearer=TOKEN.exec(req.headers.authorization??'');
        if (!matchBearer) {reject(socket,401);return}
        let digest;
        try {digest=readToken(target.exec.token_file);}
        catch {reject(socket,403);return}
        const supplied=createHash('sha256').update(matchBearer[1]).digest();
        if (!timingSafeEqual(digest,supplied)) {reject(socket,401);return}
      }
      const peers=this.computerPeers.get(hostId)??new Set();
      if(lane==='browser'&&this.browserPeers.has(hostId)){reject(socket,409);return;}
      if (lane==='exec' && this.sessions.has(hostId)) {reject(socket,409);return}
      if (lane==='computer' && peers.size >= (target.computer.max_connections??4)) {
        reject(socket,409);return;
      }
      // Reserve identity synchronously before handling the upgrade.
      const entry={id:hostId,lane,generation:target.generation,ws:null,
        closed:false,claimed:false,channel:null,computerTransport:null,browserTransport:null,alive:true};
      if (lane==='exec') this.sessions.set(hostId,entry);
      else if(lane==='browser')this.browserPeers.set(hostId,entry);
      else {peers.add(entry);this.computerPeers.set(hostId,peers)};
      try {
        this.wss.handleUpgrade(req,socket,head,ws=>{
          entry.ws=ws;
          ws.on('pong',()=>{entry.alive=true});
          ws.on('close',()=>this.drop(entry));
          ws.on('error',()=>this.drop(entry));
          ws.on('message',(data,isBinary)=>{
            const limit=lane==='exec'?MAX_FRAME:MAX_COMPUTER_FRAME;
            if (isBinary || entry.closed || data.length>limit) {
              ws.terminate();return;
            }
            if (lane==='exec') {
              if (!entry.channel) {ws.terminate();return}
              entry.channel.emit('message',data);return;
            }
            const mcpTransport=lane==='browser'?entry.browserTransport:entry.computerTransport;
            if (!mcpTransport) {ws.terminate();return}
            try {
              const message=JSON.parse(String(data));
              if (!message || Array.isArray(message) || typeof message!=='object')
                throw Error('invalid_computer_jsonrpc');
              mcpTransport.onmessage?.(message);
            } catch {ws.terminate()}
          });
        });
      } catch {
        this.drop(entry);socket.destroy();
      }
    });
    this.timer=setInterval(()=>{
      const all=[...this.sessions.values(),...this.browserPeers.values(),
        ...[...this.computerPeers.values()].flatMap(peers=>[...peers])];
      for(const entry of all) {
        if (!entry.ws) continue;
        let target;
        try {target=this.registry.resolve(entry.id);}
        catch {entry.ws.terminate();continue}
        if (target.generation!==entry.generation || target.exec?.transport!=='outbound' ||
            (entry.lane==='computer' && (target.computer?.enabled!==true ||
             target.computer?.transport!=='outbound')) ||
            (entry.lane==='browser'&&(target.browser?.enabled!==true||target.browser?.transport!=='outbound')) ||
            !entry.alive) {entry.ws.terminate();continue}
        entry.alive=false;
        try {entry.ws.ping()} catch {entry.ws.terminate()}
      }
    },this.heartbeatMs);
    this.timer.unref?.();
  }
  drop(entry) {
    if (entry.closed) return;
    entry.closed=true;
    if (entry.lane==='exec' && this.sessions.get(entry.id)===entry)
      this.sessions.delete(entry.id);
    if (entry.lane==='computer') {
      const peers=this.computerPeers.get(entry.id);
      peers?.delete(entry);
      if(peers?.size===0) this.computerPeers.delete(entry.id);
      if (entry.computerTransport) {
        entry.computerTransport.closed=true;
        entry.computerTransport.onclose?.();
      }
    }
    if(entry.lane==='browser'){if(this.browserPeers.get(entry.id)===entry)this.browserPeers.delete(entry.id);if(entry.browserTransport){entry.browserTransport.closed=true;entry.browserTransport.onclose?.();}}
    entry.channel?.emit('closed');
  }
  async acquire(target) {
    if (this.stopped) throw disconnected();
    const entry=this.sessions.get(target.id);
    if (!entry || entry.closed || !entry.ws || entry.ws.readyState!==WebSocket.OPEN ||
        entry.generation!==target.generation || entry.claimed) throw disconnected();
    this.registry.resolve(target.id);
    entry.claimed=true;
    const channel=new EventEmitter();
    channel.send=(text)=>{
      if (entry.closed || entry.ws.readyState!==WebSocket.OPEN) throw disconnected();
      if (Buffer.byteLength(text)>MAX_FRAME) {entry.ws.terminate();throw disconnected()}
      entry.ws.send(text,{binary:false});
    };
    channel.close=async ()=>{
      if (entry.ws.readyState===WebSocket.OPEN) entry.ws.close(1000,'styx_session_closed');
      else entry.ws.terminate();
      this.drop(entry);
    };
    entry.channel=channel;
    return new RpcClient(channel,{timeoutMs:target.exec.timeout_ms??35000});
  }
  async acquireComputer(target) {
    if (this.stopped || target.computer?.transport!=='outbound') throw disconnected();
    // Wait only for a fresh authenticated transport before ANY dispatch.
    // A completed model lease closes its native worker; a subsequent owner
    // can arrive during normal Host reconnect. No action is ever replayed.
    const deadline=performance.now()+this.computerAcquireWaitMs;
    let entry;
    while(!entry){
      if(this.stopped)throw disconnected();
      const current=this.registry.resolve(target.id);
      if(current.generation!==target.generation)throw Error('computer_generation_changed');
      const peers=this.computerPeers.get(target.id);
      const connected=[...(peers??[])].filter(e=>!e.closed &&
        e.generation===target.generation&&e.ws?.readyState===WebSocket.OPEN);
      if(connected.length){
        entry=connected.find(e=>!e.claimed);
        if(!entry)throw Error('computer_slots_busy');
        entry.claimed=true;break;
      }
      const remaining=deadline-performance.now();
      if(remaining<=0)throw Error('computer_host_offline');
      await new Promise(resolve=>setTimeout(resolve,Math.min(100,remaining)));
    }
    // Each MCP owner exclusively claims one independent Host-originated WS
    // connected to exactly one native Cua stdio MCP server process.
    const transport={
      closed:false,
      onclose:null,onerror:null,onmessage:null,
      async start() {
        if(entry.closed)throw disconnected();
      },
      async send(message) {
        if(entry.closed || entry.ws?.readyState!==WebSocket.OPEN)throw disconnected();
        const data=JSON.stringify(message);
        if(Buffer.byteLength(data)>MAX_COMPUTER_FRAME){
          entry.ws.terminate();throw Error('computer_frame_limit');
        }
        await new Promise((resolve,reject)=>{
          entry.ws.send(data,{binary:false},err=>err?reject(err):resolve());
        });
      },
      async close(){
        if(transport.closed)return;
        if(entry.ws?.readyState===WebSocket.OPEN)
          entry.ws.close(1000,'styx_computer_session_closed');
        else entry.ws?.terminate();
        thisRelay.drop(entry);
      }
    };
    const thisRelay=this;
    entry.computerTransport=transport;
    return transport;
  }
  async acquireBrowser(target){
    if(this.stopped||target.browser?.transport!=='outbound')throw Error('browser_host_offline');
    this.registry.resolve(target.id);
    const entry=this.browserPeers.get(target.id);
    if(!entry||entry.closed||entry.generation!==target.generation||entry.ws?.readyState!==WebSocket.OPEN||entry.claimed)throw Error('browser_host_offline');
    entry.claimed=true;const relay=this;
    const transport={closed:false,onmessage:null,onclose:null,onerror:null,async start(){if(entry.closed)throw Error('browser_host_offline');},
      async send(message){if(entry.closed||entry.ws?.readyState!==WebSocket.OPEN)throw Error('browser_host_offline');const data=JSON.stringify(message);if(Buffer.byteLength(data)>MAX_COMPUTER_FRAME)throw Error('browser_frame_limit');await new Promise((resolve,reject)=>entry.ws.send(data,{binary:false},error=>error?reject(error):resolve()));},
      async close(){if(transport.closed)return;entry.ws?.terminate();relay.drop(entry);}};
    entry.browserTransport=transport;return transport;
  }
  // Passive snapshot only: never claims a slot, probes a native process, or
  // trusts a connection from a previous catalog generation.
  status(target) {
    const current = this.registry.resolve(target.id);
    const valid = entry => !this.stopped && current.generation === target.generation &&
      entry?.generation === current.generation && !entry.closed &&
      entry.ws?.readyState === WebSocket.OPEN;
    return {
      browser: target.browser?.transport==='outbound'?(valid(this.browserPeers.get(target.id))?'connected':'offline'):'unknown',
      exec: target.exec.transport === 'outbound'
        ? (valid(this.sessions.get(target.id)) ? 'connected' : 'offline') : 'unknown',
      computer: target.computer?.transport === 'outbound'
        ? ([...(this.computerPeers.get(target.id) ?? [])].some(valid) ? 'connected' : 'offline')
        : 'unknown'
    };
  }
  computerConnected(id) {
    return [...(this.computerPeers.get(id)??[])].filter(
      e=>!e.closed && e.ws?.readyState===WebSocket.OPEN).length;
  }
  // Explicit owner-approved device revocation terminates both reverse
  // lanes. Connection closure makes old Codex/Cua identities unusable.
  disconnectHost(id) {
    const browser=this.browserPeers.get(id);if(browser){browser.ws?.terminate();this.drop(browser);}
    const exec = this.sessions.get(id);
    if (exec) {exec.ws?.terminate();this.drop(exec)}
    for (const peer of [...(this.computerPeers.get(id)??[])]) {
      peer.ws?.terminate();this.drop(peer);
    }
  }
  connected(id) {
    const e=this.sessions.get(id);
    return Boolean(e && !e.closed && e.ws?.readyState===WebSocket.OPEN);
  }
  async close() {
    this.stopped=true;clearInterval(this.timer);
    for(const entry of [...this.sessions.values(),...this.browserPeers.values(),
      ...[...this.computerPeers.values()].flatMap(peers=>[...peers])]) {
      entry.ws?.terminate();this.drop(entry);
    }
    this.sessions.clear();this.computerPeers.clear();this.browserPeers.clear();this.wss.close();
  }
}
