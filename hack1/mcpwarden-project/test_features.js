// Feature + regression tests for the five advanced features. Runs the real engine in jsdom.
const { JSDOM } = require('jsdom'); const fs = require('fs');
const dom = new JSDOM('<!doctype html><body></body>', { url: 'https://example.test/', runScripts: 'outside-only' });
const w = dom.window; Object.defineProperty(w, 'crypto', { value: globalThis.crypto }); w.performance = globalThis.performance; w.TextEncoder = TextEncoder;
w.eval(['engine.js','sentinel.js','intent.js','lab.js'].map(f => fs.readFileSync(f, 'utf8')).join('\n') + ';window.__t={Sentinel,Tasks,Intent,Decisions,Chains,STAGE_IDX,STAGES,Warden,Registry,Lab,LAB,Audit,Agent,Inspector,MockNet,Store,validatePolicy};');
const T = w.__t; const results = []; let fail = 0;
const ok = (name, cond, info = '') => { results.push([cond ? 'PASS' : 'FAIL', name, info]); if (!cond) fail++; };
const call = (o) => T.Warden.call({ serverId: 'warden-web-demo', pace: 0, session: 's' + Math.random(), ...o });
(async () => {
  T.Warden.init(); await T.Registry.boot();
  // 1 safe request allowed
  let r = await call({ tool: 'fetch_url', args: { url: 'https://docs.example-research.org/mcp-security' } });
  ok('1. Safe web request is allowed', r.verdict === 'ALLOWED', r.verdict);
  // 2 prohibited destination blocked before connection
  const before = T.MockNet.connections.length;
  r = await call({ tool: 'fetch_url', args: { url: 'http://169.254.169.254/latest/meta-data/' } });
  ok('2. Prohibited destination blocked before connection', r.verdict === 'DENIED' && r.blockingStage === 'dest' && T.MockNet.connections.length === before && r.stages[T.STAGE_IDX.forward].status === 'skipped', `${r.blockingStage}, new connections ${T.MockNet.connections.length - before}`);
  // 3 suspicious instructions per policy (sanitize by default, block after policy change)
  r = await call({ tool: 'fetch_url', args: { url: 'https://blog.secure-ai.test/agent-tips' } });
  ok('3a. Injection sanitized under default policy', r.verdict === 'SANITIZED' && !/Ignore all previous/i.test(r.response.text), r.verdict);
  const p = JSON.parse(JSON.stringify(T.Warden.policy)); p.responsePolicy.promptInjection = 'block'; await T.Warden.savePolicy(p, 'test');
  r = await call({ tool: 'fetch_url', args: { url: 'https://blog.secure-ai.test/agent-tips' } });
  ok('3b. Injection blocked after policy change (policy affects decisions)', r.verdict === 'BLOCKED', r.verdict);
  p.responsePolicy.promptInjection = 'sanitize'; await T.Warden.savePolicy(p, 'test revert');
  // 4 schema change detected
  const mir = T.Registry.live.get('web-tools-mirror').server.state;
  mir.optionalParam = true; await T.Registry.verify('web-tools-mirror');
  const chg = T.Sentinel.pending().find(c => c.tool === 'fetch_url');
  ok('4. Unexpected schema change detected and classified', chg && chg.classification === 'benign' && chg.diff.addedProps.includes('timeout_ms'), chg && chg.classification);
  // 5 unapproved definitions cannot bypass trust policy (even via direct proxy call, and even if agent omits the new param)
  r = await call({ serverId: 'web-tools-mirror', tool: 'fetch_url', args: { url: 'https://docs.example-research.org/mcp-security' } });
  ok('5a. Changed tool blocked until approved', r.verdict === 'DENIED' && r.blockingStage === 'tool', r.rule);
  const appr = await T.Sentinel.approve(chg.id);
  r = await call({ serverId: 'web-tools-mirror', tool: 'fetch_url', args: { url: 'https://docs.example-research.org/mcp-security', timeout_ms: 500 } });
  ok('5b. Approved benign change becomes usable', appr.ok && r.verdict === 'ALLOWED', r.verdict + ' ' + r.reason);
  mir.optionalParam = false; await T.Registry.verify('web-tools-mirror'); // now differs from the new baseline -> pending again
  const back = T.Sentinel.pending().find(c => c.tool === 'fetch_url');
  ok('5c. Reverting upstream after approval is itself a reviewed change', !!back, back && back.classification);
  await T.Sentinel.approve(back.id);
  mir.addTool = true; await T.Registry.verify('web-tools-mirror');
  r = await call({ serverId: 'web-tools-mirror', tool: 'upload_page', args: { url: 'https://docs.example-research.org/x', snapshot: 'a' } });
  ok('5d. New tool on trusted server is not auto-trusted', r.verdict === 'DENIED' && T.Registry.get('web-tools-mirror').tools.upload_page.status === 'pending-review', r.reason);
  mir.addTool = false; await T.Registry.verify('web-tools-mirror');
  ok('5e. Withdrawn unapproved tool is dropped and logged', !T.Registry.get('web-tools-mirror').tools.upload_page && T.Sentinel.changes.some(c => c.tool === 'upload_page' && c.status === 'withdrawn'));
  mir.confidential = true; await T.Registry.verify('web-tools-mirror');
  const sus = T.Sentinel.pending().find(c => c.tool === 'fetch_url');
  const ap2 = await T.Sentinel.approve(sus.id);
  ok('5f. Suspicious definition (asks for confidential data) quarantined and not approvable', sus.classification === 'suspicious' && !ap2.ok && T.Registry.get('web-tools-mirror').tools.fetch_url.status === 'quarantined', ap2.msg);
  mir.confidential = false; await T.Registry.verify('web-tools-mirror');
  ok('5g. Integrity changes recorded in audit log', T.Audit.list.filter(e => e.kind === 'integrity').length >= 4, T.Audit.list.filter(e => e.kind === 'integrity').length);
  // 6 follow-up actions evaluated against policy
  const res = await T.Agent.runTask('Summarize https://blog.secure-ai.test/research-roundup', { mode: 'manipulable', source: 'test', pace: 0 });
  const [prim, f1, f2] = res.runs;
  ok('6a. Primary call allowed (subtle page evades injection detector: best-effort)', prim.verdict === 'ALLOWED', prim.verdict);
  ok('6b. Exfil follow-up blocked by intent firewall using recorded provenance', f1 && f1.verdict === 'DENIED' && f1.blockingStage === 'intent' && f1.intent.provenance.kind === 'page-content' && f1.intent.provenance.sourceRunId === prim.id, f1 && f1.rule);
  ok('6c. Internal follow-up blocked by mandatory destination check first', f2 && f2.verdict === 'DENIED' && f2.blockingStage === 'dest', f2 && f2.rule);
  ok('6d. No connection to exfil endpoint', !T.MockNet.connections.some(c => c.host === 'collect.datasink.test'));
  const ben = await T.Agent.runTask('Search for the SSRF primer and read the top result', { pace: 0, source: 'test' });
  ok('6e. Benign follow-up (search result) allowed', ben.runs.length === 2 && ben.runs[1].verdict === 'ALLOWED' && ben.runs[1].intent.provenance.kind === 'search-result', ben.runs.map(x => x.verdict).join(','));
  // classifier cannot relax a rule
  const p2 = JSON.parse(JSON.stringify(T.Warden.policy)); p2.intent.classifier = 'off'; await T.Warden.savePolicy(p2, 'x');
  const res2 = await T.Agent.runTask('Summarize https://blog.secure-ai.test/research-roundup', { mode: 'manipulable', source: 'test', pace: 0 });
  ok('6f. Rule still blocks with classifier off (classifier advisory only)', res2.runs[1].verdict === 'DENIED' && res2.runs[1].blockingStage === 'intent');
  p2.intent.contentDerivedFollowups = 'review'; p2.intent.exfiltrationShape = 'review'; await T.Warden.savePolicy(p2, 'review mode');
  const pr = T.Agent.runTask('Summarize https://blog.secure-ai.test/research-roundup', { mode: 'manipulable', source: 'test', pace: 0 });
  await new Promise(r => setTimeout(r, 300)); const ap = T.Warden.pendingApprovals().find(a => a.kind === 'intent');
  ok('6g. Review policy holds follow-up for an operator', !!ap); if (ap) T.Warden.decideApproval(ap.id, false);
  const res3 = await pr; ok('6h. Rejected review stays denied', res3.runs[1].verdict === 'DENIED');
  await T.Warden.savePolicy(JSON.parse(JSON.stringify({ ...p2, intent: { ...p2.intent, contentDerivedFollowups: 'block', exfiltrationShape: 'block', classifier: 'advisory' } })), 'restore');
  // 7 attack chain reflects records
  const ch = T.Chains.forTask(res.task.id);
  const conf = ch.edges.find(e => e.to === f1.id);
  ok('7a. Chain contains every call of the task and only those', ch.decisions.length === 3 && ch.decisions.every(d => d.taskId === res.task.id));
  ok('7b. Follow-up linked to parent retrieval node as confirmed', conf && conf.basis === 'confirmed' && conf.from === prim.id + ':ret', conf && conf.from);
  ok('7c. Blocked operations highlighted, executed-before-detection computed', ch.blocked.length === 2 && ch.executedBeforeDetection.map(d => d.requestId).includes(prim.id));
  const unrelated = T.Chains.forTask(ben.task.id); ok('7d. Unrelated task not merged', !unrelated.decisions.some(d => d.taskId === res.task.id));
  // 8 decision explainer accurate
  const d = T.Decisions.get(f2.id); const x = T.Decisions.explain(d);
  ok('8a. Denied explanation: failed stage, rule, no connection, not executed', x.failedStage.key === 'dest' && /mandatory\.destination/.test(x.rule) && /^No/.test(x.connection) && /^No/.test(x.executed));
  ok('8b. Skipped checks never counted as passed', x.passed.every(s => s.status === 'passed') && x.skipped.length > 0 && !x.passed.some(s => s.key === 'forward'));
  const da = T.Decisions.get(prim.id); const xa = T.Decisions.explain(da);
  ok('8c. Allowed decision lists passed checks with audit reference', xa.passed.length >= 10 && da.auditSeq && T.Audit.list.find(e => e.seq === da.auditSeq).requestId === prim.id && T.Audit.list.find(e => e.seq === da.auditSeq).hash === da.auditHash);
  ok('8d. No raw secrets in decisions/audit/intents storage', !/AKIAZ3SYNTHETIC0DEMO|ghp_Synthetic|Synth3tic!Pass/.test(JSON.stringify([T.Store.get('decisions'), T.Store.get('audit'), T.Store.get('intents')])));
  // 9 & 10 suite reflects actual outcomes; benign not blocked
  const lr = await T.Lab.runAll(); const m = T.Lab.metrics();
  ok('9. Security test suite: all scenarios match expectation', m.passed === T.LAB.length, `${m.passed}/${T.LAB.length} ` + lr.filter(r => !r.pass).map(r => r.id + ':' + r.actual.verdict + '@' + r.actual.stage).join(' '));
  ok('10. Benign cases not blocked (FP=0)', m.FP === 0 && m.TN === T.LAB.filter(s => !s.malicious).length, JSON.stringify(m));
  // policy change makes a scenario fail honestly (not hardcoded)
  const p3 = JSON.parse(JSON.stringify(T.Warden.policy)); p3.domains.deny.push('docs.example-research.org'); await T.Warden.savePolicy(p3, 'deny docs');
  const l1 = await T.Lab.run(T.LAB[0], { pace: 0 });
  ok('9b. Actual result follows policy, not expectation', !l1.pass && l1.actual.verdict === 'DENIED' && l1.outcome === 'FP');
  p3.domains.deny.pop(); await T.Warden.savePolicy(p3, 'undo');
  // 11 audit persists and verifies
  await T.Audit.lock; const v = await T.Audit.verify(); const stored = T.Store.get('audit', []);
  ok('11. Audit persisted and chain verifies', v.ok && stored.length === T.Audit.list.length && stored.length > 50, `${stored.length} entries`);
  // 12 existing functionality: rate limiter, redirect, rebinding, bypass already covered by suite; registry still trusts demo
  ok('12. Existing registry trust intact', T.Registry.get('warden-web-demo').tools.fetch_url.status === 'trusted');
  // 13 backend failure never silently skips mandatory checks
  const orig = T.Inspector.injection; T.Inspector.injection = () => { throw new Error('detector crashed'); };
  r = await call({ tool: 'fetch_url', args: { url: 'https://docs.example-research.org/mcp-security' } });
  T.Inspector.injection = orig;
  ok('13a. Response detector crash fails closed (BLOCKED, later stages not executed)', r.verdict === 'BLOCKED' && r.rule === 'engine.fail-closed' && r.stages[T.STAGE_IDX.secrets].status === 'skipped' && !r.response.text, r.verdict);
  const origD = T.Warden.destinationSafety; T.Warden.destinationSafety = async () => { throw new Error('resolver crashed'); };
  const b2 = T.MockNet.connections.length;
  r = await call({ tool: 'fetch_url', args: { url: 'https://docs.example-research.org/mcp-security' } });
  T.Warden.destinationSafety = origD;
  ok('13b. Request-phase crash denies with no connection', r.verdict === 'DENIED' && r.blockingStage === 'dest' && T.MockNet.connections.length === b2);
  const origI = T.Intent.evaluate; T.Intent.evaluate = () => { throw new Error('intent crashed'); };
  r = await call({ tool: 'fetch_url', args: { url: 'https://docs.example-research.org/mcp-security' } });
  T.Intent.evaluate = origI;
  ok('13c. Intent firewall crash denies (fail closed)', r.verdict === 'DENIED' && r.blockingStage === 'intent');
  ok('Internal connections ever opened', T.MockNet.connections.filter(c => c.internal).length === 0);
  for (const [s, n, i] of results) console.log(s, n, i ? '| ' + i : '');
  console.log(`\n${results.length - fail}/${results.length} passed`);
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
