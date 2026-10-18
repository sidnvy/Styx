import {createServer} from 'node:http';
import {createServer as createSecureServer} from 'node:https';
import fs from 'node:fs';
import {randomUUID, createHash, timingSafeEqual} from 'node:crypto';
import {StreamableHTTPServerTransport} from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import {handleEnrollment} from './enrollment.mjs';

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

// MCP's HTTP session is the model invocation owner. A new authenticated
// connection cannot reuse an old process or GUI element reference.
export async function createGatewayHttp(gateway, {
  token, host = '127.0.0.1', port = 8795, allowedHosts, allowedOrigins = [],
  maxSessions = 32, idleSessionTimeoutMs = 0,
  tlsCertificateFile, tlsPrivateKeyFile, enrollment = null
} = {}) {
  if (typeof token !== 'string' || token.length < 32 || /\s/.test(token))
    throw new Error('Strong inbound bearer required');
  if (!Number.isInteger(port) || port < 0 || port > 65535)
    throw new Error('Invalid listen port');
  if (!Number.isInteger(maxSessions) || maxSessions < 1 ||
      !Number.isInteger(idleSessionTimeoutMs) || idleSessionTimeoutMs < 0)
    throw new Error('Invalid MCP session limits');
  if (!['127.0.0.1', '::1', 'localhost'].includes(host) &&
      (!allowedHosts || allowedHosts.length === 0))
    throw new Error('Explicit allowed hosts required for non-loopback binding');
  const hosts = allowedHosts ?? [host + ':' + port];
  const digest = createHash('sha256').update(token).digest();
  if(enrollment && timingSafeEqual(digest,enrollment.adminDigest))
    throw Error('Enrollment owner token must differ from MCP bearer');
  const sessions = new Map();
  // Optional cleanup for the isolated CAS research Gateway only. A model's MCP
  // client can abandon a session without sending DELETE; orphan sessions must
  // not permanently exhaust the capacity and block all future tool calls.
  async function reapIdleSessions() {
    if (!idleSessionTimeoutMs) return;
    const threshold = Date.now() - idleSessionTimeoutMs;
    for (const [id, session] of sessions) {
      if (session.inFlight > 0 || session.lastActivityAt > threshold) continue;
      sessions.delete(id);
      await session.transport.close().catch(() => {});
      await session.server.close().catch(() => {});
      await gateway.closeOwner?.(session.owner).catch(() => {});
    }
  }
  if (Boolean(tlsCertificateFile) !== Boolean(tlsPrivateKeyFile))
    throw new Error('TLS certificate and key must be supplied together');
  const handler=async (req, res) => {
    const refuse = (code, message) => {
      if (!res.headersSent) { res.writeHead(code, {'content-type': 'text/plain'}); res.end(message); }
    };
    if (req.url?.startsWith('/styx/enroll/')) {
      if(!enrollment) return refuse(404,'Not found');
      await handleEnrollment(req,res,{controller:enrollment,allowedHosts:hosts});
      return;
    }
    if (req.url !== '/mcp') return refuse(404, 'Not found');
    const denied = authorize(req, digest, hosts, allowedOrigins);
    if (denied) return refuse(denied, 'Forbidden');
    if (!['POST', 'GET', 'DELETE'].includes(req.method)) return refuse(405, 'Method not allowed');
    const sessionId = req.headers['mcp-session-id'];
    if (Array.isArray(sessionId)) return refuse(400, 'Invalid session');
    if (sessionId) {
      const established = sessions.get(sessionId);
      if (!established) return refuse(404, 'Session not found');
      // A long-lived GET SSE subscription is passive, not an active tool call.
      // Otherwise an abandoned client with an open SSE stream is never reaped.
      const activeOperation = req.method !== 'GET';
      if (activeOperation) established.inFlight++;
      established.lastActivityAt = Date.now();
      try { await established.transport.handleRequest(req, res); }
      catch { refuse(500, 'Request failed'); }
      finally {
        if (activeOperation) established.inFlight--;
        established.lastActivityAt = Date.now();
      }
      return;
    }
    if (req.method !== 'POST') return refuse(400, 'MCP initialization required');
    if (sessions.size >= maxSessions) await reapIdleSessions();
    if (sessions.size >= maxSessions) return refuse(503, 'Session capacity reached');
    const owner = 'mcp-session:' + randomUUID();
    let sid;
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: id => {
        sid = id;
        sessions.set(id, {transport, server, owner, inFlight: 1, lastActivityAt: Date.now()});
      }
    });
    const server = gateway.serverForOwner(owner);
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
  await new Promise((resolve, reject) => {
    http.once('error', reject);
    http.listen(port, host, resolve);
  });
  return {
    address: http.address(), sessions,
    async close() {
      await Promise.allSettled([...sessions.values()].map(async ({server, transport}) => {
        await transport.close(); await server.close();
      }));
      sessions.clear();
      await new Promise(resolve => http.close(resolve));
      await gateway.close();
    }
  };
}
