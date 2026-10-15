'use strict';
// Genuine MCP communication: official SDK client → MCPWarden (Streamable HTTP) → protected Web MCP server (stdio).
const test = require('node:test');
const assert = require('node:assert');
const { startBackend, mcpClient } = require('./harness');

test('genuine MCP: discovery, allowed call over the protected path, agent authentication', async t => {
  const app = await startBackend();
  t.after(() => app.close());

  await t.test('protected Web MCP servers run as stdio child processes on the official SDK', () => {
    for (const e of app.E.Registry.entries) {
      assert.strictEqual(e.connection, 'connected', `${e.id} should be connected`);
      assert.match(e.transportLabel, /MCP over stdio \(official SDK\), pid \d+/);
    }
    const pids = app.E.Registry.entries.map(e => app.E.Registry.live.get(e.id).transport.pid);
    for (const pid of pids) assert.doesNotThrow(() => process.kill(pid, 0), `child ${pid} should be alive`);
  });

  await t.test('identity verified from the real MCP handshake', () => {
    const demo = app.E.Registry.get('warden-web-demo');
    assert.strictEqual(demo.identity, 'match');
    assert.strictEqual(demo.serverInfo.name, 'warden-web-demo');
    assert.strictEqual(app.E.Registry.get('community-web-tools').identity, 'unpinned');
  });

  const c = await mcpClient(app);
  t.after(() => c.close());

  await t.test('an external MCP client discovers only approved, trusted tools through MCPWarden', async () => {
    const { tools } = await c.listTools();
    const names = tools.map(x => x.name).sort();
    assert.deepStrictEqual(names, ['extract_web_content', 'fetch_url', 'search_web', 'web-tools-mirror__fetch_url'].sort());
    assert.ok(!names.some(n => n.includes('browse_anything')), 'unreviewed community tool must not be exposed');
    assert.ok(!names.includes('web-tools-mirror__extract_web_content'), 'quarantined (poisoned) tool must not be exposed');
    for (const tool of tools) assert.strictEqual(tool.inputSchema.type, 'object');
  });

  await t.test('an allowed call passes the security engine and executes over a real socket', async () => {
    const hits = app.fixtureWeb.hits.length, up = app.E.Registry.live.get('warden-web-demo').transport; const orig = up.request.bind(up); let calls = 0; up.request = msg => { if (msg.method === 'tools/call') calls++; return orig(msg); };
    const r = await c.callTool({ name: 'fetch_url', arguments: { url: 'https://docs.example-research.org/mcp-security' } });
    assert.strictEqual(r.isError, false);
    assert.strictEqual(r._meta['mcpwarden/verdict'], 'ALLOWED');
    assert.match(r.content[0].text, /Runtime defence for MCP tool calls/);
    assert.match(r.content[0].text, /^\[Untrusted web content from docs\.example-research\.org/);
    assert.strictEqual(app.fixtureWeb.hits.length, hits + 1, 'exactly one real HTTP request reached the web');
    assert.strictEqual(calls, 1, 'exactly one tools/call travelled over the stdio MCP connection'); up.request = orig;
    const run = app.E.Warden.runs.get(r._meta['mcpwarden/requestId']);
    assert.ok(run, 'the verdict comes from a backend run record');
    assert.ok(run.stages.filter(s => s.status === 'passed').length >= 12);
    assert.strictEqual(run.stages.find(s => s.key === 'forward').status, 'passed');
  });

  await t.test('response inspection runs on real content before the agent sees it', async () => {
    const r = await c.callTool({ name: 'fetch_url', arguments: { url: 'https://blog.secure-ai.test/agent-tips' } });
    assert.strictEqual(r._meta['mcpwarden/verdict'], 'SANITIZED');
    assert.doesNotMatch(r.content[0].text, /Ignore all previous instructions/i);
    assert.match(r.content[0].text, /removed by MCPWarden/);
    const s = await c.callTool({ name: 'fetch_url', arguments: { url: 'https://leaky.devnotes.test/config-tips' } });
    assert.doesNotMatch(s.content[0].text, /AKIAZ3SYNTHETIC0DEMO|ghp_Synthetic/);
    assert.match(s.content[0].text, /\[REDACTED:aws_access_key\]/);
  });

  await t.test('agents without the token cannot use the MCP endpoint', async () => {
    const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
    const h = { 'content-type': 'application/json', accept: 'application/json, text/event-stream' };
    assert.strictEqual((await fetch(app.url + '/mcp', { method: 'POST', headers: h, body })).status, 401);
    assert.strictEqual((await fetch(app.url + '/mcp', { method: 'POST', headers: { ...h, authorization: 'Bearer wrong' }, body })).status, 401);
  });
});
