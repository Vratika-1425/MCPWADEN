#!/usr/bin/env node
'use strict';
// Guided campus demonstration. Fictional fixtures only: no real student records or university systems.
//
//   npm run demo:campus              start a private backend and print the evidence
//   npm run demo:campus -- --live    use the backend started by `npm start`, so the dashboard shows each step
//                                    (needs MCPWARDEN_AGENT_TOKEN and MCPWARDEN_ADMIN_TOKEN, e.g. from .env)
//   add --sandbox to also run the Threat Sandbox at the end
const path = require('node:path');
const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { StreamableHTTPClientTransport } = require('@modelcontextprotocol/sdk/client/streamableHttp.js');

const argv = process.argv.slice(2);
const LIVE = argv.includes('--live'), SANDBOX = argv.includes('--sandbox');
const say = (...a) => console.log(...a);
const hr = t => say(`\n━━ ${t} ${'━'.repeat(Math.max(0, 66 - t.length))}`);
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function main() {
  let app = null, url, agentToken, adminToken;
  if (LIVE) {
    url = process.env.MCPWARDEN_URL || `http://127.0.0.1:${process.env.MCPWARDEN_PORT || 8787}`;
    agentToken = process.env.MCPWARDEN_AGENT_TOKEN; adminToken = process.env.MCPWARDEN_ADMIN_TOKEN;
    if (!agentToken || !adminToken) throw new Error('--live needs MCPWARDEN_AGENT_TOKEN and MCPWARDEN_ADMIN_TOKEN (set them in .env before `npm start`)');
  } else {
    const os = require('node:os'), fs = require('node:fs');
    agentToken = 'demo-agent-' + Date.now(); adminToken = 'demo-admin-' + Date.now();
    const { start } = require(path.join(__dirname, '..', 'server', 'index.js'));
    app = await start({ MCPWARDEN_PORT: '0', MCPWARDEN_DB: path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'mcpw-demo-')), 'mcpwarden.db'), MCPWARDEN_QUIET: 'true', MCPWARDEN_NETWORK: 'fixture', MCPWARDEN_AGENT_TOKEN: agentToken, MCPWARDEN_ADMIN_TOKEN: adminToken });
    url = app.url;
  }
  const health = await (await fetch(url + '/api/health')).json();
  const cookie = `mcpw_admin=${encodeURIComponent(adminToken)}`;
  const api = async (p, body) => { const r = await fetch(url + p, { method: body ? 'POST' : 'GET', headers: { cookie, 'content-type': 'application/json', 'x-mcpwarden-csrf': '1' }, body: body ? JSON.stringify(body) : undefined }); if (!r.ok) throw new Error(`${p}: HTTP ${r.status}`); return r.json(); };
  const decision = async id => (await api('/api/state')).decisions.find(d => d.requestId === id);

  const client = new Client({ name: 'campus-assistant', version: '1.0.0' });
  await client.connect(new StreamableHTTPClientTransport(new URL(url + '/mcp'), { requestInit: { headers: { authorization: `Bearer ${agentToken}` } } }));
  say(`MCPWarden ${health.mode} backend at ${url} (network: ${health.network}). Campus assistant connected over MCP.`);
  if (health.network === 'fixture') say('All web pages below are fictional local fixtures reached over real sockets. No real university system is contacted.');

  const call = async (name, args, meta) => {
    const r = await client.callTool({ name, arguments: args, _meta: { 'mcpwarden/source': 'mcp-agent', ...meta } });
    const id = r._meta['mcpwarden/requestId']; await sleep(150);
    const d = await decision(id);
    const st = d.stages, by = k => st.filter(s => s.status === k);
    say(`  ${name} ${JSON.stringify(args)}`);
    say(`  → ${d.verdict}  (request ${id}, audit #${d.auditSeq})`);
    say(`    checks executed: ${by('passed').length} passed, ${by('failed').length} flagged, ${by('blocked').length} blocked; ${by('skipped').length} not executed`);
    if (d.decision === 'DENY') {
      const b = st.find(s => s.key === d.blockingStage);
      say(`    stopped at stage ${b.n} "${b.name}" by ${d.rule}`);
      say(`    reason: ${d.reason}`);
      say(`    protected tool executed: ${d.toolExecuted}; network connections opened: ${d.connections}`);
    } else if (d.verdict === 'SANITIZED') say(`    response policy: ${d.reason}`);
    return { r, id, d, text: r.content[0].text };
  };

  hr('1. Student: "Find the examination timetable for me"');
  const s = await call('search_web', { query: 'examination timetable' }, { 'mcpwarden/task': 'Find the examination timetable for me' });
  const top = s.text.match(/https?:\/\/\S+/)?.[0];
  const t = await call('fetch_url', { url: top }, { 'mcpwarden/taskId': s.r._meta['mcpwarden/taskId'], 'mcpwarden/parent': s.id });
  say('  assistant reads: ' + (t.text.match(/[^\n]*Operating Systems[^\n]*/) || [''])[0].replace(/^\W+/, ''));

  hr('2. Student: "Summarize the latest examination notice"');
  const n = await call('fetch_url', { url: 'https://notices.campus-demo.test/exam-update' }, { 'mcpwarden/task': 'Summarize the latest examination notice from https://notices.campus-demo.test/exam-update' });
  const task = n.r._meta['mcpwarden/taskId'];
  say(`    injection detector: score ${n.d.findings.injectionScore} (${n.d.findings.injectionHits.join(', ')}); flagged sentences removed before the assistant saw them`);

  hr('3. A manipulated assistant acts on links the notice suggested');
  say('  Detection is best-effort: the notice also contains a subtle instruction that does not look like an attack.');
  const urls = [...n.text.matchAll(/\b(?:open|check)\b[^\n]*?(https?:\/\/[^\s,]+)/gi)].map(m => m[1].replace(/[.,]+$/, ''));
  for (const u of urls) await call('fetch_url', { url: u }, { 'mcpwarden/taskId': task, 'mcpwarden/parent': n.id });
  if (app) say(`  local fixture web server: ${app.fixtureWeb.hits.filter(h => h.host === 'seat-verify.campus-demo.test' || h.internal).length} requests received for the prohibited destinations`);

  hr('4. Audit and attack chain');
  const v = await api('/api/audit/verify', {});
  say(`  audit log (SQLite): ${v.ok ? `chain intact, ${v.count} entries verified` : `BROKEN at #${v.seq}: ${v.why}`}`);
  const st = await api('/api/state'); const chain = st.decisions.filter(d => d.taskId === task).sort((a, b) => a.ts - b.ts);
  for (const d of chain) say(`  ${d.parentRequestId ? '  └─ follow-up' : 'notice fetch '} ${d.destination}  ${d.verdict}${d.rule ? '  [' + d.rule + ']' : ''}  origin: ${d.provenance?.label || 'n/a'}`);
  say(`  dashboard: open Attack Chain Explorer and select "${chain[0]?.taskText}"`);

  hr('5. Destination protection (safe controlled test)');
  await call('fetch_url', { url: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/' }, { 'mcpwarden/task': 'Fetch http://169.254.169.254/latest/meta-data/iam/security-credentials/' });

  if (SANDBOX) {
    hr('6. Threat Sandbox (real engine, fixture web)');
    const r = await api('/api/lab/run-all', {});
    say(`  ${r.metrics.passed}/${r.ran} scenarios matched expectation; attacks let through: ${r.metrics.FN}; benign cases blocked: ${r.metrics.FP}`);
  }
  await client.close(); if (app) await app.close();
  say('\nDone.');
}
main().catch(e => { console.error('campus demo failed:', e.message); process.exit(1); });
