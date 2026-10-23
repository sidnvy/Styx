import {createServer} from 'node:http';
import {createServer as createSecureServer} from 'node:https';
import fs from 'node:fs';
import {randomUUID, createHash, timingSafeEqual} from 'node:crypto';
import {StreamableHTTPServerTransport} from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import {handleEnrollment} from './enrollment.mjs';
import {ConversationOwners} from './conversation-owners.mjs';
import {GatewayDeviceIngress} from './device-ingress.mjs';

function authorize(req, digest, hosts, origins) {
  if (!hosts.includes(req.headers.host)) return 403;
  if (req.headers.origin !== undefined && !origins.includes(req.headers.origin)) return 403;
  if ((req.rawHeaders ?? []).filter((_, i) => i % 2 === 0)
    .filter(k => k.toLowerCase() === 'authorization').length !== 1) return 401;
  const match = /^Bearer ([A-Za-z0-9_-]{32,})$/.exec(req.headers.authorization ?? '');
  if (!match) return 401;
  const actual = createHash('sha256').update(match[1]).digest();
  return timingSafeEqual(actual, digest) ? null : 401;
}

// Ordinary clients own resources per authenticated HTTP session. The private
// App-owned Tunnel may bind a verified conversation across transport sessions;
// neither bearer possession nor caller-selected metadata alone enables this.
export async function createGatewayHttp(gateway, {
  token, host = '127.0.0.1', port = 8795, allowedHosts, allowedOrigins = [],
  idleSessionTimeoutMs = 15 * 60 * 1000,
  tlsCertificateFile, tlsPrivateKeyFile, enrollment = null, tunnelContextToken = null, deviceIngress = null
} = {}) {
  if (typeof token !== 'string' || token.length < 32 || /\s/.test(token))
    throw new Error('Strong inbound bearer required');
  if (!Number.isInteger(port) || port < 0 || port > 65535)
    throw new Error('Invalid listen port');
  if (!Number.isInteger(idleSessionTimeoutMs) || idleSessionTimeoutMs < 0)
    throw new Error('Invalid MCP idle session timeout');
  if (!['127.0.0.1', '::1', 'localhost'].includes(host) &&
      (!allowedHosts || allowedHosts.length === 0))
    throw new Error('Explicit allowed hosts required for non-loopback binding');
  const hosts = allowedHosts ?? [host + ':' + port];
  const digest = createHash('sha256').update(token).digest();
  // Stable only within the explicitly shared bearer authority. This is not a
  // ChatGPT account ID. Domain separation keeps the auth digest off the wire.
  const browserPrincipal=createHash('sha256').update('styx/browser-profile/v1\0').update(digest).digest('hex');
  if(enrollment && timingSafeEqual(digest,enrollment.adminDigest))
    throw Error('Enrollment owner token must differ from MCP bearer');
  const sessions = new Map();
  const ingressManager=enrollment?new GatewayDeviceIngress({gateway,enrollment}):null;
  if(tunnelContextToken!==null&&!/^[a-f0-9]{64}$/.test(tunnelContextToken))throw Error('Invalid Tunnel context capability');
  const contextDigest=tunnelContextToken===null?null:createHash('sha256').update(tunnelContextToken).digest();
  const conversations=contextDigest?new ConversationOwners({key:tunnelContextToken,gateway,principal:browserPrincipal}):null;
  // Clients can abandon short-lived sessions without DELETE. There is no MCP
  // session-count cap: one account must not block another account from connecting.
  // Reclaim 15-minute idle sessions on new initialization, preserving in-flight
  // responses and owned Exec work. Zero explicitly disables idle cleanup.
  async function reapIdleSessions() {
    if (!idleSessionTimeoutMs) return;
    const threshold = Date.now() - idleSessionTimeoutMs;
    for (const [id, session] of sessions) {
      if (session.inFlight > 0 || session.lastActivityAt > threshold ||
          gateway.hasOwnerWork?.(session.owner)) continue;
      sessions.delete(id);
      await session.transport.close().catch(() => {});
      await session.server.close().catch(() => {});
      await gateway.closeOwner?.(session.owner).catch(() => {});
    }
    await conversations?.reap(idleSessionTimeoutMs);
  }
  if (Boolean(tlsCertificateFile) !== Boolean(tlsPrivateKeyFile))
    throw new Error('TLS certificate and key must be supplied together');
  const handler=async (req, res) => {
    const refuse = (code, message) => {
      if (!res.headersSent) {
        res.writeHead(code, {'content-type': 'application/json'});
        res.end(JSON.stringify({jsonrpc:'2.0',id:null,error:{code:-32000,message}}));
      }
    };
    if (req.url?.startsWith('/styx/enroll/')) {
      if(!enrollment) return refuse(404,'Not found');
      await handleEnrollment(req,res,{controller:enrollment,allowedHosts:hosts,deviceIngress:ingressManager});
      return;
    }
    if (req.url !== '/mcp') return refuse(404, 'Not found');
    const denied = authorize(req, digest, hosts, allowedOrigins);
    if (denied) return refuse(denied, 'Forbidden');
    const contextHeader=req.headers['x-styx-tunnel-context'];
    const trustedTunnel=typeof contextHeader==='string'&&contextDigest!==null&&
      timingSafeEqual(createHash('sha256').update(contextHeader).digest(),contextDigest);
    if(contextHeader!==undefined&&!trustedTunnel)return refuse(403,'Invalid Tunnel context');
    if (!['POST', 'GET', 'DELETE'].includes(req.method)) return refuse(405, 'Method not allowed');
    const sessionId = req.headers['mcp-session-id'];
    if (Array.isArray(sessionId)) return refuse(400, 'Invalid session');
    if (sessionId) {
      const established = sessions.get(sessionId);
      if (!established) return refuse(404, 'Session not found');
      if(established.trustedTunnel!==trustedTunnel)return refuse(403,'Session ingress changed');
      // A long-lived GET SSE subscription is passive, not an active tool call.
      // Otherwise an abandoned client with an open SSE stream is never reaped.
      const activeOperation = req.method !== 'GET';
      if (activeOperation) {
        established.inFlight++;
        let settled = false;
        const complete = () => {
          if (settled) return;
          settled = true;
          established.inFlight--;
          established.lastActivityAt = Date.now();
        };
        // SDK handleRequest can return before an async tools/call response.
        res.once('finish', complete); res.once('close', complete);
      }
      established.lastActivityAt = Date.now();
      try { await established.transport.handleRequest(req, res); }
      catch { refuse(500, 'Request failed'); }
      return;
    }
    if (req.method !== 'POST') return refuse(400, 'MCP initialization required');
    await reapIdleSessions();
    const owner = 'mcp-session:' + randomUUID();
    let sid;
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: id => {
        sid = id;
        sessions.set(id, {transport, server, owner, trustedTunnel, inFlight: 1, lastActivityAt: Date.now()});
      }
    });
    const server = gateway.serverForOwner(owner,{browserPrincipal,
      ...(trustedTunnel?{withOwner:(meta,operation)=>conversations.run(meta,operation)}:{})});
    transport.onclose = () => {
      if (sid) sessions.delete(sid);
      void gateway.closeOwner?.(owner).catch(() => {});
    };
    try {
      await server.connect(transport);
      await transport.handleRequest(req, res);
      if (sid && sessions.has(sid)) {
        const session = sessions.get(sid);
        session.inFlight--;
        session.lastActivityAt = Date.now();
      }
      if (!sid) { await transport.close(); await server.close(); }
    } catch {
      if (sid) sessions.delete(sid);
      await transport.close().catch(() => {});
      await server.close().catch(() => {});
      refuse(500, 'Initialization failed');
    }
  };
  const http=tlsCertificateFile
    ? createSecureServer({cert:fs.readFileSync(tlsCertificateFile),
        key:fs.readFileSync(tlsPrivateKeyFile),
        requestCert:true,rejectUnauthorized:false},handler)
    : createServer(handler);
  gateway.relay?.attach(http,{allowedHosts:hosts});
  try{
    await new Promise((resolve, reject) => {
      const onError=error=>{http.removeListener('listening',onListening);reject(error)};
      const onListening=()=>{http.removeListener('error',onError);resolve()};
      http.once('error',onError);http.once('listening',onListening);
      http.listen(port, host);
    });
  }catch(error){gateway.relay?.detach(http);http.close();throw error}
  if(deviceIngress&&ingressManager)await ingressManager.restore(deviceIngress);
  let closePromise;
  return {
    address: http.address(), sessions, deviceIngress:ingressManager,
    close() {
      if(closePromise)return closePromise;
      closePromise=(async()=>{
        let ingressError;
        try{await ingressManager?.close()}catch(error){ingressError=error;}
        await Promise.allSettled([...sessions.values()].map(async ({server, transport}) => {
          await transport.close(); await server.close();
        }));
        sessions.clear();
        // Upgraded Host sockets keep HTTP close pending. Stop owned relays first.
        await gateway.close();
        await new Promise(resolve => http.close(resolve));
        if(ingressError)throw ingressError;
      })();
      return closePromise;
    }
  };
}
