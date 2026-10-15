'use strict';
// Network layers that replace the in-page MockNet in live mode.
//
// RealNet:    real DNS (dns.lookup, all records) and real TCP/TLS sockets to the exact IP the engine validated.
// FixtureNet: the engine's fixture DNS table, but every request is a real HTTP request over a real socket to a
//             local fixture web server. Used for tests and offline demos; never enabled in real mode.
//
// In both, the engine (Warden.egress) has already classified the destination before connect() is called.
// connect() repeats the classification and checks the socket's actual remote address (defence in depth).
const http = require('node:http');
const https = require('node:https');
const dns = require('node:dns');
const net = require('node:net');

function makeGuardedRequest({ IP, connections }) {
  // Opens one HTTP(S) request to `ip` with Host/SNI set to `host`, reading at most maxBytes + 1 bytes.
  return function request({ ip, port, host, path, timeoutMs, ctx, maxBytes, scheme, routeTo, extraHeaders }) {
    const cls = IP.classify(ip);
    const target = routeTo || { ip, port };
    const rec = { ts: Date.now(), ip, port, host, path, ctx, internal: !cls.ok, real: true, via: routeTo ? 'fixture' : 'direct' };
    if (!cls.ok) return Promise.reject(Object.assign(new Error(`Socket guard refused ${ip} (${cls.cat})`), { code: 'EGUARD' }));
    connections.push(rec);
    const lib = scheme === 'https' && !routeTo ? https : http;
    return new Promise((resolve, reject) => {
      let done = false; const finish = (fn, v) => { if (!done) { done = true; clearTimeout(timer); fn(v); } };
      const req = lib.request({
        host: target.ip, port: target.port, path, method: 'GET', servername: net.isIP(host) ? undefined : host,
        headers: { Host: host, 'User-Agent': 'MCPWarden/1.0 (+web-mcp-security-proxy)', Accept: 'text/html,text/plain,application/json;q=0.9,*/*;q=0.1', 'Accept-Encoding': 'identity', Connection: 'close', ...(extraHeaders || {}) },
        agent: false,
      });
      const timer = setTimeout(() => { req.destroy(); finish(reject, Object.assign(new Error(`Connection to ${host} timed out after ${timeoutMs} ms`), { code: 'ETIMEDOUT' })); }, timeoutMs);
      req.on('socket', s => s.on('connect', () => {
        // The socket must be connected to exactly the address that was validated.
        const remote = (s.remoteAddress || '').replace(/^::ffff:/, '');
        if (remote !== target.ip.replace(/^\[|\]$/g, '')) { req.destroy(); finish(reject, Object.assign(new Error(`Socket connected to ${remote}, expected ${target.ip}`), { code: 'EGUARD' })); }
      }));
      req.on('error', e => finish(reject, e));
      req.on('response', res => {
        const headers = {}; for (const [k, v] of Object.entries(res.headers)) headers[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : v;
        const declared = +headers['content-length'] || 0;
        if (declared > maxBytes) { res.destroy(); return finish(resolve, { status: res.statusCode, headers, body: null }); }
        const chunks = []; let n = 0;
        res.on('data', c => { n += c.length; if (n > maxBytes) { res.destroy(); headers['content-length'] = String(n); finish(resolve, { status: res.statusCode, headers, body: null }); } else chunks.push(c); });
        res.on('end', () => { if (!done) { headers['content-length'] = String(n); finish(resolve, { status: res.statusCode, headers, body: Buffer.concat(chunks).toString('utf8') }); } });
        res.on('error', e => finish(reject, e));
      });
      req.end();
    });
  };
}

function makeRealNet({ IP }) {
  const connections = [];
  const request = makeGuardedRequest({ IP, connections });
  return {
    mode: 'real', connections,
    async resolve(host) {
      host = String(host).replace(/^\[|\]$/g, '');
      if (IP.isLiteral(host)) return [host];
      try { const r = await dns.promises.lookup(host, { all: true, verbatim: true }); return r.map(x => x.address); }
      catch (e) { const err = new Error(`DNS lookup failed for ${host} (${e.code || e.message})`); err.code = 'ENOTFOUND'; throw err; }
    },
    connect: o => request(o),
    hosts: () => [], resetRebind() { },
  };
}

function makeFixtureNet({ IP, MockNet, fixturePort }) {
  const connections = [];
  const request = makeGuardedRequest({ IP, connections });
  return {
    mode: 'fixture', connections,
    resolve: async host => MockNet.resolve(host), // fixture DNS table (same answers as the demo)
    // Real socket to the local fixture web server. The validated target IP travels in a header so the
    // fixture server can serve (and log) what that address would have returned.
    connect: o => request({ ...o, routeTo: { ip: '127.0.0.1', port: fixturePort }, extraHeaders: { 'X-Fixture-Target-IP': o.ip } }),
    hosts: () => MockNet.hosts(), resetRebind: () => MockNet.resetRebind(),
  };
}

// Local fixture web server. Serves the engine's fixture pages over real HTTP and logs every hit,
// including any hit for an internal address, so tests can prove such requests never arrived.
function startFixtureWeb({ MockNet, IP, port = 0 }) {
  const hits = [];
  const server = http.createServer(async (req, res) => {
    const host = String(req.headers.host || '').split(':')[0].toLowerCase();
    const ip = String(req.headers['x-fixture-target-ip'] || '');
    const hit = { ts: Date.now(), host, ip, path: req.url, internal: ip ? !IP.classify(ip).ok : false };
    hits.push(hit);
    try {
      const f = await MockNet.connect({ ip: ip || '0.0.0.0', port: 80, host, path: req.url, timeoutMs: 60000, ctx: 'fixture-web' });
      const headers = { ...f.headers };
      if (f.lazySize) { headers['content-length'] = String(f.lazySize); res.writeHead(f.status, headers); const chunk = Buffer.alloc(65536, 120); let left = f.lazySize; const pump = () => { while (left > 0) { const n = Math.min(left, chunk.length); left -= n; if (!res.write(n === chunk.length ? chunk : chunk.subarray(0, n))) return res.once('drain', pump); } res.end(); }; res.on('close', () => { left = 0; }); return pump(); }
      const body = Buffer.from(f.body || '', 'utf8'); headers['content-length'] = String(body.length);
      res.writeHead(f.status, headers); res.end(body);
    } catch (e) { res.writeHead(502, { 'content-type': 'text/plain' }); res.end('fixture error'); }
  });
  return new Promise(resolve => server.listen(port, '127.0.0.1', () => resolve({ server, port: server.address().port, hits, close: () => new Promise(r => server.close(r)) })));
}

module.exports = { makeRealNet, makeFixtureNet, startFixtureWeb };
