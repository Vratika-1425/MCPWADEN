'use strict';
// The unmodified dashboard, served by the backend, shows real backend decisions and mode; bypass attempts fail.
const test = require('node:test');
const assert = require('node:assert');
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const { startBackend, mcpClient, openDashboard, sleep, ROOT } = require('./harness');

test('dashboard displays real backend decisions in live mode', async t => {
  const app = await startBackend(); t.after(() => app.close());
  const d = await openDashboard(app); t.after(() => d.close());
  await d.go('#/decisions');
  assert.ok(await d.waitFor(() => /Live mode: MCP backend/.test(d.$('#pill-mode')?.textContent || '')), 'mode pill shows live mode');
  assert.match(d.$('#pill-proxy').textContent, /Proxy enforcing/);

  // An external agent makes a call; the dashboard must show that exact backend decision.
  const c = await mcpClient(app); t.after(() => c.close());
  const r = await c.callTool({ name: 'fetch_url', arguments: { url: 'http://169.254.169.254/latest/meta-data/' } });
  const id = r._meta['mcpwarden/requestId'];
  const row = await d.waitFor(() => d.$(`[data-d="${id}"]`));
  assert.ok(row, 'decision from the backend appears in Decision Explorer via the event stream');
  row.dispatchEvent(new d.w.MouseEvent('click', { bubbles: true })); await sleep(100);
  const text = d.$('#dexp').textContent;
  assert.match(text, /DENIED/); assert.match(text, new RegExp(id)); assert.match(text, /mandatory\.destination\.metadata/);
  assert.match(text, new RegExp(`#${r._meta['mcpwarden/auditSeq']}`), 'audit reference matches the persisted record');

  await d.go('#/audit');
  assert.ok(await d.waitFor(() => d.$$('tr[data-seq]').some(tr => tr.textContent.includes('DENIED'))), 'audit explorer lists the backend record');
  assert.deepStrictEqual(d.errors, []);
});

test('dashboard shows a lost backend instead of implying enforcement', async t => {
  const app = await startBackend();
  const d = await openDashboard(app); t.after(() => d.close());
  await d.go('#/command');
  assert.ok(await d.waitFor(() => /Live mode: MCP backend/.test(d.$('#pill-mode')?.textContent || '')));
  await app.close();
  assert.ok(await d.waitFor(() => /disconnected/.test(d.$('#pill-mode')?.textContent || '')), 'mode pill reports disconnection');
  assert.match(d.$('#pill-proxy').textContent, /Backend unavailable, enforcement not confirmed/);
});

test('agents cannot bypass MCPWarden to reach the protected server or its egress', async t => {
  const app = await startBackend(); t.after(() => app.close());
  await t.test('protected server rejects tools/call without the MCPWarden-held token', async () => {
    const up = app.E.Registry.live.get('warden-web-demo').transport;
    await assert.rejects(up.client.callTool({ name: 'fetch_url', arguments: { url: 'https://docs.example-research.org/mcp-security' } }), /Unauthorized/);
  });
  await t.test('protected server refuses to start without the environment MCPWarden provides', () => {
    const r = spawnSync(process.execPath, [path.join(ROOT, 'server', 'web-mcp-server.js'), '--variant', 'demo'], { env: { PATH: process.env.PATH }, encoding: 'utf8', timeout: 10000 });
    assert.strictEqual(r.status, 2); assert.match(r.stderr, /refusing to start/);
  });
  await t.test('egress endpoint requires its token', async () => {
    const env = app.E.Registry.live.get('warden-web-demo').transport.env;
    assert.match(env.MCPWARDEN_EGRESS_URL, /^http:\/\/127\.0\.0\.1:\d+\/egress$/, 'egress listens on loopback only');
    const res = await fetch(env.MCPWARDEN_EGRESS_URL, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ url: 'http://169.254.169.254/', ctx: 'x' }) });
    assert.strictEqual(res.status, 401);
  });
  await t.test('egress with a valid token but no active proxied call is refused', async () => {
    const env = app.E.Registry.live.get('warden-web-demo').transport.env;
    const res = await fetch(env.MCPWARDEN_EGRESS_URL, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${env.MCPWARDEN_EGRESS_TOKEN}` }, body: JSON.stringify({ url: 'https://docs.example-research.org/mcp-security', ctx: 'forged' }) });
    const j = await res.json(); assert.match(j.error.message, /No active proxy context/);
  });
  await t.test('dashboard rejects requests with a foreign Host header', async () => {
    const res = await new Promise((resolve, reject) => require('node:http').get({ host: '127.0.0.1', port: app.port, path: '/api/health', headers: { host: 'attacker.example' } }, resolve).on('error', reject));
    assert.strictEqual(res.statusCode, 421);
  });
});
