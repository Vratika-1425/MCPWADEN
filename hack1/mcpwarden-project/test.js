const { JSDOM } = require('jsdom');
const fs = require('fs');
const dom = new JSDOM('<!doctype html><body></body>', { url: 'https://example.test/', runScripts: 'outside-only' });
const w = dom.window;
w.crypto = globalThis.crypto; // node webcrypto
Object.defineProperty(w, 'crypto', { value: globalThis.crypto });
w.performance = globalThis.performance; w.TextEncoder = TextEncoder;
const code = ['engine.js','sentinel.js','intent.js','lab.js'].map(f=>fs.readFileSync(f,'utf8')).join('\n') + `
;window.__t = { Sentinel, Tasks, Intent, Decisions, Chains, STAGE_IDX, Rate, Warden, Registry, Lab, LAB, Audit, Agent, IP, Inspector, MockNet, Settings, validatePolicy, DEFAULT_POLICY };`;
w.eval(code);
const T = w.__t;
(async () => {
  T.Warden.init(); await T.Registry.boot();
  for (const e of T.Registry.entries) console.log(e.id, e.connection, e.identity, e.trusted, Object.entries(e.tools).map(([k,v])=>k+':'+v.status).join(','));
  let fails=0;
  for (const sc of T.LAB) {
    const r = await T.Lab.run(sc, { pace: 0 });
    if(!r.pass) fails++;
    console.log(r.pass?'PASS':'FAIL', sc.id, sc.name, '=>', r.actual.verdict, r.actual.stage, '|', r.actual.rule, '|', (r.actual.reason||'').slice(0,110), r.note||'', 'conns', r.connections, 'internal', r.internalConnections);
  }
  console.log('metrics', JSON.stringify(T.Lab.metrics()));
  console.log('internal connections ever:', T.MockNet.connections.filter(c=>c.internal).length);
  await T.Audit.lock;
  console.log('audit', T.Audit.list.length, JSON.stringify(await T.Audit.verify()));
  // show sanitized outputs
  for (const u of ['https://blog.secure-ai.test/agent-tips','https://leaky.devnotes.test/config-tips']) {
    const run = await T.Warden.call({serverId:'warden-web-demo', tool:'fetch_url', args:{url:u}, pace:0, session:'t2'});
    console.log('----', run.verdict, run.reason); console.log(run.response.text);
    console.log('AGENT:', T.Agent.answer(run));
  }
  const s = await T.Warden.call({serverId:'warden-web-demo', tool:'search_web', args:{query:'recent AI security research'}, pace:0, session:'t3'});
  console.log('search', s.verdict, s.response.text.slice(0,400)); console.log('AGENT:', T.Agent.answer(s));
  const x = await T.Warden.call({serverId:'warden-web-demo', tool:'extract_web_content', args:{url:'https://docs.example-research.org/mcp-security'}, pace:0, session:'t3'});
  console.log('extract', x.verdict, x.reason); console.log('AGENT:', T.Agent.answer(x));
  console.log(T.Agent.plan('Attempt to retrieve content from http://169.254.169.254/latest/meta-data/'));
  console.log(T.Agent.plan('Search the web for recent AI security research.'));
  // policy change effect: block injection
  const p = JSON.parse(JSON.stringify(T.Warden.policy)); p.responsePolicy.promptInjection='block';
  console.log('save', JSON.stringify(await T.Warden.savePolicy(p,'block injection')));
  const b = await T.Warden.call({serverId:'warden-web-demo', tool:'fetch_url', args:{url:'https://blog.secure-ai.test/agent-tips'}, pace:0, session:'t4'});
  console.log('after policy', b.verdict, b.blockingStage, b.rule);
  const bad = JSON.parse(JSON.stringify(p)); bad.limits.allowedSchemes.push('file'); bad.domains.allow.push('127.0.0.1');
  console.log('validate', T.validatePolicy(bad));
  // tamper
  T.Audit.tamper(); console.log('after tamper', JSON.stringify(await T.Audit.verify()));
  // approval flow
  const pr = T.Warden.call({serverId:'warden-web-demo', tool:'fetch_url', args:{url:'https://files.partner-share.test/q3-report'}, pace:0, session:'t5'});
  await new Promise(r=>setTimeout(r,50)); const ap = T.Warden.pendingApprovals(); console.log('pending', ap.length);
  T.Warden.decideApproval(ap[0].id, true); const ar = await pr; console.log('approval run', ar.verdict);
  process.exit(fails?1:0);
})().catch(e=>{console.error(e);process.exit(2)});
