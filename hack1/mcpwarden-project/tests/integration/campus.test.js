'use strict';
// College scenario (fictional fixtures only): a campus assistant, as an external MCP client, finds the exam
// timetable, then reads a notice whose hidden text tries to steer it into prohibited follow-up actions.
const test = require('node:test');
const assert = require('node:assert');
const { DatabaseSync } = require('node:sqlite');
const { startBackend, mcpClient } = require('./harness');

const tool = async (c, name, args, meta) => {
  const r = await c.callTool({ name, arguments: args, _meta: meta });
  return { r, verdict: r._meta['mcpwarden/verdict'], id: r._meta['mcpwarden/requestId'], text: r.content[0].text };
};
// What a manipulated assistant would do: act on every "open/check <url>" instruction in content it received.
const followUpsFrom = text => [...text.matchAll(/\b(?:open|check)\b[^\n]*?(https?:\/\/[^\s,]+)/gi)].map(m => m[1].replace(/[.,]+$/, ''));

test('campus assistant scenario through MCPWarden', async t => {
  const app = await startBackend(); t.after(() => app.close());
  const c = await mcpClient(app); t.after(() => c.close());
  const up = app.E.Registry.live.get('warden-web-demo').transport; const orig = up.request.bind(up); const upstreamCalls = [];
  up.request = msg => { if (msg.method === 'tools/call') upstreamCalls.push(msg.params.arguments); return orig(msg); };

  await t.test('1. the student request succeeds: search, then read the timetable', async () => {
    const s = await tool(c, 'search_web', { query: 'examination timetable' }, { 'mcpwarden/task': 'Find the examination timetable for me' });
    assert.strictEqual(s.verdict, 'ALLOWED');
    const taskId = s.r._meta['mcpwarden/taskId'];
    const url = s.text.match(/https:\/\/examcell\.campus-demo\.test\/timetable/)?.[0];
    assert.ok(url, 'the timetable is the top search result');
    const f = await tool(c, 'fetch_url', { url }, { 'mcpwarden/taskId': taskId, 'mcpwarden/parent': s.id });
    assert.strictEqual(f.verdict, 'ALLOWED');
    assert.match(f.text, /Operating Systems, 10:00 to 13:00/);
    const run = app.E.Warden.runs.get(f.id);
    assert.strictEqual(run.intent.provenance.kind, 'search-result', 'MCPWarden itself recorded where the URL came from');
  });

  let notice, task;
  await t.test('2. the notice is inspected: the overt injection is removed before the assistant sees it', async () => {
    notice = await tool(c, 'fetch_url', { url: 'https://notices.campus-demo.test/exam-update' }, { 'mcpwarden/task': 'Summarize the latest examination notice from https://notices.campus-demo.test/exam-update' });
    task = notice.r._meta['mcpwarden/taskId'];
    assert.strictEqual(notice.verdict, 'SANITIZED');
    assert.doesNotMatch(notice.text, /ignore all previous instructions/i);
    assert.match(notice.text, /removed by MCPWarden/);
    assert.match(notice.text, /forty-five minutes/, 'legitimate notice content is preserved');
  });

  let followUps = [];
  await t.test('3. the manipulated assistant attempts the follow-ups the page suggested; both are denied before execution', async () => {
    const urls = followUpsFrom(notice.text);
    assert.deepStrictEqual(urls.map(u => new URL(u).hostname), ['seat-verify.campus-demo.test', '10.10.0.5'], 'detection is best-effort: the subtle instruction reached the assistant');
    const hitsBefore = app.fixtureWeb.hits.length, callsBefore = upstreamCalls.length;
    for (const url of urls) followUps.push(await tool(c, 'fetch_url', { url }, { 'mcpwarden/taskId': task, 'mcpwarden/parent': notice.id }));
    assert.deepStrictEqual(followUps.map(f => f.verdict), ['DENIED', 'DENIED']);
    const [exfil, internal] = followUps.map(f => app.E.Warden.runs.get(f.id));
    assert.strictEqual(exfil.blockingStage, 'intent');
    assert.strictEqual(exfil.rule, 'policy.intent.contentDerivedFollowups');
    assert.strictEqual(exfil.intent.provenance.sourceRunId, notice.id, 'origin traced to the notice response');
    assert.ok(exfil.intent.signals.some(s => s.id === 'exfil-shape'));
    assert.strictEqual(internal.blockingStage, 'dest');
    assert.strictEqual(internal.rule, 'mandatory.destination.private');
    for (const r of [exfil, internal]) assert.strictEqual(r.stages.find(s => s.key === 'forward').status, 'skipped');
    assert.strictEqual(upstreamCalls.length, callsBefore, 'no tools/call reached the protected server');
    assert.strictEqual(app.fixtureWeb.hits.length, hitsBefore, 'no request reached any web server');
    assert.ok(!app.fixtureWeb.hits.some(h => h.host === 'seat-verify.campus-demo.test' || h.internal));
  });

  await t.test('4. every decision is in the SQLite audit log', () => {
    const ids = [notice.id, ...followUps.map(f => f.id)];
    const d = new DatabaseSync(app.db, { readOnly: true });
    const rows = d.prepare(`SELECT request_id, verdict, policy FROM audit WHERE request_id IN (${ids.map(() => '?').join(',')}) ORDER BY seq`).all(...ids); d.close();
    assert.deepStrictEqual(rows.map(r => r.verdict), ['SANITIZED', 'DENIED', 'DENIED']);
    assert.deepStrictEqual(rows.slice(1).map(r => r.policy), ['policy.intent.contentDerivedFollowups', 'mandatory.destination.private']);
  });

  await t.test('5. the attack chain links the follow-ups to the notice with confirmed edges', () => {
    const ch = app.E.Chains.forTask(task);
    assert.strictEqual(ch.decisions.length, 3);
    assert.ok(ch.incident);
    for (const f of followUps) {
      const e = ch.edges.find(x => x.to === f.id);
      assert.strictEqual(e.basis, 'confirmed');
      assert.strictEqual(e.from, notice.id + ':ret');
    }
    assert.deepStrictEqual(Array.from(ch.blocked, d => d.requestId).sort(), followUps.map(f => f.id).sort());
    assert.deepStrictEqual(Array.from(ch.executedBeforeDetection, d => d.requestId), [notice.id]);
  });
});
