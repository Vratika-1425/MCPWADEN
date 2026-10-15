'use strict';
// Every redirect hop is revalidated at connection time over real HTTP (fixture web server).
const test = require('node:test');
const assert = require('node:assert');
const { startBackend, mcpClient } = require('./harness');

test('redirects are revalidated hop by hop', async t => {
  const app = await startBackend(); t.after(() => app.close());
  const c = await mcpClient(app); t.after(() => c.close());

  await t.test('redirect to cloud metadata: first hop fetched, prohibited hop never contacted', async () => {
    const before = app.fixtureWeb.hits.length;
    const r = await c.callTool({ name: 'fetch_url', arguments: { url: 'https://redirect.example-cdn.test/go' } });
    assert.strictEqual(r._meta['mcpwarden/verdict'], 'DENIED');
    const run = app.E.Warden.runs.get(r._meta['mcpwarden/requestId']);
    assert.strictEqual(run.blockingStage, 'forward');
    assert.strictEqual(run.rule, 'mandatory.destination.metadata');
    const newHits = app.fixtureWeb.hits.slice(before);
    assert.strictEqual(newHits.length, 1, 'only the first hop reached a web server');
    assert.strictEqual(newHits[0].host, 'redirect.example-cdn.test');
    assert.strictEqual(app.fixtureWeb.hits.filter(h => h.internal).length, 0);
    assert.deepStrictEqual(Array.from(run.hops, h => h.ok), [true, false]); // Array.from: engine arrays come from the VM realm
  });

  await t.test('benign redirect to an approved page is followed and inspected', async () => {
    const before = app.fixtureWeb.hits.length;
    const r = await c.callTool({ name: 'fetch_url', arguments: { url: 'https://go.example-cdn.test/docs' } });
    assert.strictEqual(r._meta['mcpwarden/verdict'], 'ALLOWED');
    assert.deepStrictEqual(app.fixtureWeb.hits.slice(before).map(h => h.host), ['go.example-cdn.test', 'docs.example-research.org']);
  });

  await t.test('DNS rebinding between check and connect is refused', async () => {
    app.Net.resetRebind();
    const r = await c.callTool({ name: 'fetch_url', arguments: { url: 'https://rebind.lab-dns.test/' } });
    assert.strictEqual(r._meta['mcpwarden/verdict'], 'DENIED');
    assert.strictEqual(app.E.Warden.runs.get(r._meta['mcpwarden/requestId']).rule, 'mandatory.dns.rebinding');
  });
});
