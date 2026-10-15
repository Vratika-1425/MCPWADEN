'use strict';
// Audit records come from backend execution, persist in SQLite, survive a restart, and fail closed.
const test = require('node:test');
const assert = require('node:assert');
const { DatabaseSync } = require('node:sqlite');
const { startBackend, mcpClient, tmpDb, TOKENS } = require('./harness');

const admin = (app, path, body) => fetch(app.url + path, { method: body ? 'POST' : 'GET', headers: { cookie: `mcpw_admin=${TOKENS.MCPWARDEN_ADMIN_TOKEN}`, 'content-type': 'application/json', 'x-mcpwarden-csrf': '1' }, body: body ? JSON.stringify(body) : undefined });

test('audit records persist in SQLite and survive a backend restart', async t => {
  const db = tmpDb();
  let app = await startBackend(db);
  let c = await mcpClient(app);
  const ok = await c.callTool({ name: 'fetch_url', arguments: { url: 'https://docs.example-research.org/mcp-security' } });
  const no = await c.callTool({ name: 'fetch_url', arguments: { url: 'http://169.254.169.254/' } });
  const ids = [ok, no].map(r => r._meta['mcpwarden/requestId']);
  const seqs = [ok, no].map(r => r._meta['mcpwarden/auditSeq']);
  assert.ok(seqs.every(Number.isInteger));
  assert.ok([ok, no].every(r => r._meta['mcpwarden/auditPersisted'] === true));
  const head = app.E.Audit.list.at(-1).hash; const countBefore = app.E.Audit.list.length;
  await c.close(); await app.close();

  await t.test('rows are in the SQLite file with the decision the engine made', () => {
    const d = new DatabaseSync(db, { readOnly: true });
    const rows = d.prepare('SELECT seq, request_id, verdict, hash, prev_hash FROM audit WHERE request_id IN (?, ?) ORDER BY seq').all(...ids);
    d.close();
    assert.deepStrictEqual(rows.map(r => [r.request_id, r.verdict]), [[ids[0], 'ALLOWED'], [ids[1], 'DENIED']]);
    assert.deepStrictEqual(rows.map(r => r.seq), seqs);
  });

  app = await startBackend(db); t.after(() => app.close());
  await t.test('after restart the same entries load and the hash chain verifies', async () => {
    for (const id of ids) assert.ok(app.E.Audit.list.some(e => e.requestId === id), `${id} survived restart`);
    assert.ok(app.E.Audit.list.some(e => e.hash === head));
    const v = await (await admin(app, '/api/audit/verify', {})).json();
    assert.strictEqual(v.ok, true);
  });
  await t.test('a restart adds only its own start event (no re-recorded tool changes)', async () => {
    const added = app.E.Audit.list.slice(countBefore);
    assert.deepStrictEqual(added.map(e => e.action || e.kind), ['backend.start']);
  });
  await t.test('live mode refuses to tamper with or clear the real audit log', async () => {
    assert.strictEqual((await admin(app, '/api/audit/tamper', {})).status, 403);
    assert.strictEqual((await admin(app, '/api/audit/clear', {})).status, 403);
  });
  await t.test('dashboard API requires the admin session', async () => {
    assert.strictEqual((await fetch(app.url + '/api/state')).status, 401);
    assert.strictEqual((await fetch(app.url + '/')).status, 401);
  });
});

test('failed audit writes cannot appear successful', async t => {
  const app = await startBackend(); t.after(() => app.close());
  const c = await mcpClient(app); t.after(() => c.close());
  const rows = () => app.store.auditStore.count();

  await t.test('content is withheld from the agent when its audit record could not be written', async () => {
    const before = rows();
    app.store.setFailWrites(true);
    const r = await c.callTool({ name: 'fetch_url', arguments: { url: 'https://docs.example-research.org/mcp-security' } });
    app.store.setFailWrites(false);
    assert.strictEqual(r._meta['mcpwarden/auditPersisted'], false);
    assert.strictEqual(r.isError, true, 'the agent must not receive content whose decision was not recorded');
    assert.doesNotMatch(r.content[0].text, /Runtime defence for MCP tool calls/);
    assert.strictEqual(rows(), before, 'no phantom row');
    assert.ok(!app.E.Audit.list.some(e => e.requestId === r._meta['mcpwarden/requestId']), 'memory matches storage');
  });

  await t.test('while storage is failing, new calls are refused before execution', async () => {
    app.store.setFailWrites(true);
    const hits = app.fixtureWeb.hits.length;
    const r = await c.callTool({ name: 'fetch_url', arguments: { url: 'https://docs.example-research.org/mcp-security' } });
    app.store.setFailWrites(false);
    assert.strictEqual(r._meta['mcpwarden/verdict'], 'DENIED');
    assert.strictEqual(app.E.Warden.runs.get(r._meta['mcpwarden/requestId']).rule, 'audit.unavailable');
    assert.strictEqual(app.fixtureWeb.hits.length, hits, 'tool did not execute');
  });

  await t.test('calls succeed and are recorded again once storage recovers', async () => {
    const before = rows();
    const r = await c.callTool({ name: 'fetch_url', arguments: { url: 'https://docs.example-research.org/mcp-security' } });
    assert.strictEqual(r._meta['mcpwarden/verdict'], 'ALLOWED');
    assert.strictEqual(r._meta['mcpwarden/auditPersisted'], true);
    assert.strictEqual(rows(), before + 1);
  });
});
