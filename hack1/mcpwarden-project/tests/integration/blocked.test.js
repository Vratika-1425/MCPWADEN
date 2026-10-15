'use strict';
// Prohibited destinations are denied before the protected tool executes, with zero connections.
const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const { startBackend, mcpClient } = require('./harness');

const PROHIBITED = [
  ['cloud metadata', 'http://169.254.169.254/latest/meta-data/iam/security-credentials/', 'dest'],
  ['loopback hostname', 'http://localtest.me/admin', 'dest'],
  ['private network', 'http://192.168.1.10/router', 'dest'],
  ['decimal-encoded loopback', 'http://2130706433/', 'dest'],
  ['IPv4-mapped IPv6 metadata', 'http://[::ffff:169.254.169.254]/', 'dest'],
  ['file scheme', 'file:///etc/passwd', 'url'],
];

// Counts tools/call messages MCPWarden sends to a protected server (tools/list for integrity checks is expected).
function countToolCalls(app, id) {
  const up = app.E.Registry.live.get(id).transport; const orig = up.request.bind(up); let n = 0;
  up.request = msg => { if (msg.method === 'tools/call') n++; return orig(msg); };
  return () => n;
}

test('prohibited destinations are denied before execution (fixture network, real sockets)', async t => {
  const app = await startBackend(); t.after(() => app.close());
  const toolCalls = countToolCalls(app, 'warden-web-demo');
  const c = await mcpClient(app); t.after(() => c.close());
  for (const [label, url, stage] of PROHIBITED) {
    await t.test(label, async () => {
      const hits = app.fixtureWeb.hits.length, conns = app.Net.connections.length, calls = toolCalls();
      const r = await c.callTool({ name: 'fetch_url', arguments: { url } });
      assert.strictEqual(r.isError, true);
      assert.strictEqual(r._meta['mcpwarden/verdict'], 'DENIED');
      const run = app.E.Warden.runs.get(r._meta['mcpwarden/requestId']);
      assert.strictEqual(run.blockingStage, stage);
      assert.strictEqual(run.stages.find(s => s.key === 'forward').status, 'skipped', 'tool must not be forwarded');
      assert.strictEqual(toolCalls(), calls, 'no tools/call reached the protected MCP server');
      assert.strictEqual(app.Net.connections.length, conns, 'no socket opened');
      assert.strictEqual(app.fixtureWeb.hits.length, hits, 'no request reached any web server');
    });
  }
  await t.test('malformed arguments are rejected at schema validation', async () => {
    const r = await c.callTool({ name: 'fetch_url', arguments: { url: 42, extra: true } });
    assert.strictEqual(r._meta['mcpwarden/verdict'], 'DENIED');
    assert.strictEqual(app.E.Warden.runs.get(r._meta['mcpwarden/requestId']).blockingStage, 'tool');
  });
});

test('real network mode: loopback is refused after real DNS resolution, canary server receives nothing', async t => {
  // A canary HTTP server on 127.0.0.1 counts every request it receives. Real DNS resolves "localhost" to it.
  let canaryHits = 0;
  const canary = http.createServer((req, res) => { canaryHits++; res.end('canary'); });
  await new Promise(r => canary.listen(0, '127.0.0.1', r)); t.after(() => new Promise(r => canary.close(r)));
  const port = canary.address().port;
  const app = await startBackend(undefined, { MCPWARDEN_NETWORK: 'real' }); t.after(() => app.close());
  // Allow the canary port so the port policy is not what stops it; only the address checks may.
  const p = JSON.parse(JSON.stringify(app.E.Warden.policy)); p.limits.allowedPorts.push(port);
  assert.strictEqual((await app.E.Warden.savePolicy(p, 'test: allow canary port')).ok, true);
  const c = await mcpClient(app); t.after(() => c.close());
  for (const url of [`http://localhost:${port}/`, `http://127.0.0.1:${port}/`, `http://[::1]:${port}/`]) {
    await t.test(url, async () => {
      const r = await c.callTool({ name: 'fetch_url', arguments: { url } });
      assert.strictEqual(r._meta['mcpwarden/verdict'], 'DENIED');
      const run = app.E.Warden.runs.get(r._meta['mcpwarden/requestId']);
      assert.strictEqual(run.blockingStage, 'dest');
      assert.match(run.reason, /loopback/);
    });
  }
  await t.test('canary received zero requests and no internal socket was opened', () => {
    assert.strictEqual(canaryHits, 0);
    assert.strictEqual(app.Net.connections.filter(x => x.internal).length, 0);
  });
});
