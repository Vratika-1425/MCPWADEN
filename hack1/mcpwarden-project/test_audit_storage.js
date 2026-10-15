// Regression test for the audit finding: a failed audit write must never look successful.
const { JSDOM } = require('jsdom'); const fs = require('fs');
const d = new JSDOM('<!doctype html><body></body>', { url: 'https://example.test/', runScripts: 'outside-only' }); const w = d.window;
Object.defineProperty(w, 'crypto', { value: globalThis.crypto }); w.performance = globalThis.performance; w.TextEncoder = TextEncoder;
const events = [];
w.eval(['engine.js', 'sentinel.js', 'intent.js', 'lab.js'].map(f => fs.readFileSync(f, 'utf8')).join('\n') + ';window.__t={Warden,Registry,Audit,Store,Bus,STAGE_IDX};');
const T = w.__t; let fail = 0; const ok = (n, c, i = '') => { console.log(c ? 'PASS' : 'FAIL', n, i ? '| ' + i : ''); if (!c) fail++; };
const call = () => T.Warden.call({ serverId: 'warden-web-demo', tool: 'fetch_url', args: { url: 'https://docs.example-research.org/mcp-security' }, pace: 0 });
(async () => {
  T.Bus.on(e => { if (/audit-failed|storage-error/.test(e.type)) events.push(e.type); });
  T.Warden.init(); await T.Registry.boot();
  let r = await call(); await T.Audit.lock;
  ok('baseline call audited', r.auditPersisted === true && T.Store.get('audit', []).length === T.Audit.list.length);
  let size = 512 * 1024, i = 0; while (size >= 16) { try { w.localStorage.setItem('fill' + i++, 'x'.repeat(size)); } catch { size >>= 1; } }
  const memBefore = T.Audit.list.length, diskBefore = T.Store.get('audit', []).length;
  r = await call();
  ok('failed write is reported on the run, not hidden', r.auditPersisted === false && /could not be persisted/.test(r.auditError || ''), r.auditError);
  ok('memory and storage stay consistent (no phantom entry)', T.Audit.list.length === memBefore && T.Store.get('audit', []).length === diskBefore);
  ok('audit-failed event raised for the UI', events.includes('audit-failed'), events.join(','));
  const r2 = await call();
  ok('next call refused while audit storage is unavailable (fail closed, tool not executed)', r2.verdict === 'DENIED' && r2.rule === 'audit.unavailable' && r2.stages[T.STAGE_IDX.forward].status === 'skipped');
  for (let k = 0; k < i; k++) w.localStorage.removeItem('fill' + k);
  const r3 = await call(); await T.Audit.lock;
  ok('recovers once the real audit log can be written again', r3.verdict === 'ALLOWED' && r3.auditPersisted === true && (await T.Audit.verify()).ok);
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
