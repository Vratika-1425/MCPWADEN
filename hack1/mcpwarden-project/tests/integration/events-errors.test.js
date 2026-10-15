'use strict';
// Event streaming, backend errors and timeouts, and proof that the dashboard cannot override backend enforcement.
const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const { startBackend, mcpClient, openDashboard, sleep, TOKENS } = require('./harness');

const cookie = `mcpw_admin=${encodeURIComponent(TOKENS.MCPWARDEN_ADMIN_TOKEN)}`;
const admin = (app, path, body) => fetch(app.url + path, { method: 'POST', headers: { cookie, 'content-type': 'application/json', 'x-mcpwarden-csrf': '1' }, body: JSON.stringify(body || {}) });
function subscribe(app) { // reads the real SSE stream
  const events = []; let buf = '';
  const req = http.get(app.url + '/api/events', { headers: { cookie, accept: 'text/event-stream' } }, res => {
    res.setEncoding('utf8');
    res.on('data', d => { buf += d; let i; while ((i = buf.indexOf('\n\n')) >= 0) { const b = buf.slice(0, i); buf = buf.slice(i + 2); const line = b.split('\n').find(l => l.startsWith('data: ')); if (line) events.push(JSON.parse(line.slice(6))); } });
  });
  return { events, close: () => req.destroy() };
}

test('live event stream carries the real stage-by-stage execution of a call', async t => {
  const app = await startBackend(); t.after(() => app.close());
  const sse = subscribe(app); t.after(() => sse.close());
  const c = await mcpClient(app); t.after(() => c.close());
  await sleep(200);
  const r = await c.callTool({ name: 'fetch_url', arguments: { url: 'http://192.168.1.10/router' } });
  const id = r._meta['mcpwarden/requestId']; await sleep(300);
  const mine = sse.events.filter(e => e.run?.id === id);
  assert.strictEqual(mine[0].type, 'run');
  const settled = mine.filter(e => e.type === 'stage' && e.run.stages.find(s => s.key === e.stageKey).status !== 'running').map(e => e.stageKey);
  assert.deepStrictEqual(settled.slice(0, 5), ['intercept', 'server', 'tool', 'url', 'dest'], 'stages arrive in execution order');
  const done = mine.find(e => e.type === 'done');
  assert.strictEqual(done.run.verdict, r._meta['mcpwarden/verdict'], 'streamed verdict equals the verdict the agent received');
  assert.strictEqual(done.run.blockingStage, 'dest');
  assert.ok(sse.events.some(e => e.type === 'audit' && e.entry?.requestId === id), 'audit event streamed');
  assert.ok(sse.events.some(e => e.type === 'decision' && e.d?.requestId === id), 'decision record streamed');
});

test('backend errors and timeouts fail safely and visibly', async t => {
  const app = await startBackend(); t.after(() => app.close());
  const c = await mcpClient(app); t.after(() => c.close());

  await t.test('slow upstream page: real socket timeout, reported as FAILED, nothing delivered', async () => {
    const t0 = Date.now();
    const r = await c.callTool({ name: 'fetch_url', arguments: { url: 'https://slow.example-research.org/report' } });
    const run = app.E.Warden.runs.get(r._meta['mcpwarden/requestId']);
    assert.strictEqual(run.verdict, 'FAILED');
    assert.match(run.reason, /timed out after 3000 ms/);
    assert.strictEqual(r.isError, true);
    assert.ok(Date.now() - t0 < 6000, 'the policy timeout (3 s) applied, not the fixture delay (6 s)');
  });

  await t.test('crashed protected server: calls are denied at server verification, no hang', async () => {
    const pid = app.E.Registry.live.get('warden-web-demo').transport.pid;
    process.kill(pid, 'SIGKILL'); await sleep(500);
    const r = await c.callTool({ name: 'fetch_url', arguments: { url: 'https://docs.example-research.org/mcp-security' } });
    const run = app.E.Warden.runs.get(r._meta['mcpwarden/requestId']);
    assert.strictEqual(run.verdict, 'DENIED');
    assert.strictEqual(run.blockingStage, 'server');
    assert.match(run.reason, /not connected/);
  });

  await t.test('operator re-verification restarts the server and calls work again', async () => {
    assert.strictEqual((await admin(app, '/api/registry/warden-web-demo/verify')).status, 200);
    const r = await c.callTool({ name: 'fetch_url', arguments: { url: 'https://docs.example-research.org/mcp-security' } });
    assert.strictEqual(r._meta['mcpwarden/verdict'], 'ALLOWED');
  });

  await t.test('oversized arguments are rejected at interception', async () => {
    const r = await c.callTool({ name: 'search_web', arguments: { query: 'x'.repeat(20000) } });
    const run = app.E.Warden.runs.get(r._meta['mcpwarden/requestId']);
    assert.strictEqual(run.blockingStage, 'intercept');
  });

  await t.test('malformed MCP traffic gets a protocol error, and the server keeps working', async () => {
    const h = { 'content-type': 'application/json', accept: 'application/json, text/event-stream', authorization: `Bearer ${TOKENS.MCPWARDEN_AGENT_TOKEN}` };
    const bad = await fetch(app.url + '/mcp', { method: 'POST', headers: h, body: '{"jsonrpc":"2.0","method":' });
    assert.ok(bad.status >= 400 && bad.status < 500, `got HTTP ${bad.status}`);
    const r = await c.callTool({ name: 'search_web', arguments: { query: 'schema pinning' } });
    assert.strictEqual(r._meta['mcpwarden/verdict'], 'ALLOWED');
  });
});

test('the dashboard cannot override backend enforcement', async t => {
  const app = await startBackend(); t.after(() => app.close());

  await t.test('policy edits that weaken mandatory controls are rejected by the backend', async () => {
    const p = JSON.parse(JSON.stringify(app.E.Warden.policy)); p.limits.allowedSchemes.push('file'); p.domains.allow.push('169.254.169.254');
    const j = await (await admin(app, '/api/policy', { policy: p })).json();
    assert.strictEqual(j.ok, false);
    assert.ok(j.errs.some(e => /Mandatory/.test(e)));
    assert.ok(!app.E.Warden.policy.limits.allowedSchemes.includes('file'), 'backend policy unchanged');
  });

  await t.test('there is no API that executes a tool or sets a verdict outside the engine', async () => {
    for (const path of ['/api/call', '/api/decision', '/api/verdict']) assert.strictEqual((await admin(app, path, { tool: 'fetch_url', args: { url: 'http://169.254.169.254/' }, verdict: 'ALLOWED' })).status, 404);
    assert.strictEqual((await admin(app, '/api/approvals/not-a-real-approval', { approve: true })).status, 404);
  });

  await t.test('in the live dashboard, browser-side tool calls are disabled and changes to browser objects do not change backend decisions', async () => {
    const d = await openDashboard(app); t.after(() => d.close());
    await d.go('#/command'); // the landing page has no top bar; the app shell shows the mode pill
    assert.ok(await d.waitFor(() => /Live mode/.test(d.$('#pill-mode')?.textContent || '')));
    await assert.rejects(d.w.eval("Warden.call({ serverId: 'warden-web-demo', tool: 'fetch_url', args: { url: 'http://169.254.169.254/' } })"), /Live mode: tool calls go through the MCPWarden MCP endpoint/);
    d.w.eval("Warden.policy.domains.allow.push('169.254.169.254'); Warden.destinationSafety = async () => ({ ok: true })");
    const c = await mcpClient(app); t.after(() => c.close());
    const r = await c.callTool({ name: 'fetch_url', arguments: { url: 'http://169.254.169.254/latest/meta-data/' } });
    assert.strictEqual(r._meta['mcpwarden/verdict'], 'DENIED', 'backend decision unaffected by browser-side tampering');
    assert.ok(!app.E.Warden.policy.domains.allow.includes('169.254.169.254'));
  });
});
