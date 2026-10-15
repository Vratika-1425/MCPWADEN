'use strict';
// The existing Threat Sandbox scenarios, executed by the live backend over real MCP and real sockets.
const test = require('node:test');
const assert = require('node:assert');
const { startBackend, TOKENS } = require('./harness');

test('all existing security scenarios pass through the live backend', { timeout: 240000 }, async t => {
  const app = await startBackend(); t.after(() => app.close());
  const r = await fetch(app.url + '/api/lab/run-all', { method: 'POST', headers: { cookie: `mcpw_admin=${TOKENS.MCPWARDEN_ADMIN_TOKEN}`, 'content-type': 'application/json', 'x-mcpwarden-csrf': '1' }, body: '{}' });
  assert.strictEqual(r.status, 200);
  const { ran, metrics } = await r.json();
  const failed = Array.from(app.E.LAB).filter(s => !app.E.Lab.results[s.id]?.pass).map(s => `${s.id} ${s.name}: got ${app.E.Lab.results[s.id]?.actual.verdict}@${app.E.Lab.results[s.id]?.actual.stage}`);
  assert.deepStrictEqual(failed, [], 'every scenario matches its expectation');
  assert.strictEqual(ran, app.E.LAB.length);
  assert.strictEqual(metrics.FN, 0); assert.strictEqual(metrics.FP, 0);
  await t.test('scenarios ran over real sockets, never reaching an internal address', () => {
    assert.ok(app.Net.connections.length > 0, 'real connections were made');
    assert.ok(app.Net.connections.every(c => c.real === true));
    assert.strictEqual(app.Net.connections.filter(c => c.internal).length, 0);
    assert.strictEqual(app.fixtureWeb.hits.filter(h => h.internal).length, 0);
  });
  await t.test('scenario calls went through the agent MCP endpoint and were audited in SQLite', () => {
    const lab = app.E.Audit.list.filter(e => e.kind === 'request' && e.source === 'attack-lab');
    assert.ok(lab.length >= app.E.LAB.length);
    assert.ok(app.store.auditStore.count() >= lab.length);
  });
});
