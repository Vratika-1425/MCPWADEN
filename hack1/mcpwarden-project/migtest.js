const { JSDOM } = require('jsdom'); const fs = require('fs');
const dom = new JSDOM('<!doctype html><body></body>', { url: 'https://example.test/', runScripts: 'outside-only' });
const w = dom.window; Object.defineProperty(w, 'crypto', { value: globalThis.crypto }); w.performance = globalThis.performance; w.TextEncoder = TextEncoder;
// Old-format storage written by the previous version
const oldPolicy = { version: 4, servers: { allow: ['warden-web-demo', 'web-tools-mirror'] }, tools: { search_web: { enabled: true, destination: 'none' }, fetch_url: { enabled: true, destination: 'public' }, extract_web_content: { enabled: true, destination: 'allowlist' } }, domains: { allow: ['docs.example-research.org'], deny: ['*.attacker.test', 'evil.example'] }, requireApproval: { domains: [], tools: [] }, limits: { allowedSchemes: ['https', 'http'], allowedPorts: [80, 443], maxRedirects: 3, maxResponseBytes: 200000, timeoutMs: 3000, allowedContentTypes: ['text/html', 'text/plain', 'application/json'] }, rateLimit: { perToolPerMinute: 20, perDestinationPerMinute: 12 }, responsePolicy: { promptInjection: 'sanitize', injectionThreshold: 4, blockAtScore: 24, secrets: 'redact', pii: ['email'], toolSteering: 'sanitize' } };
w.localStorage.setItem('mcpw:policy', JSON.stringify(oldPolicy));
w.eval(['engine.js','sentinel.js','intent.js','lab.js'].map(f => fs.readFileSync(f, 'utf8')).join('\n') + ';window.__t={Warden,Registry,Sentinel};');
const T = w.__t;
(async () => {
  T.Warden.init();
  console.log('policy kept user edits:', T.Warden.policy.version, T.Warden.policy.domains.deny.includes('evil.example'), 'intent added:', !!T.Warden.policy.intent);
  await T.Registry.boot();
  // simulate old registry format by rewriting statuses then rebooting
  const reg = JSON.parse(w.localStorage.getItem('mcpw:registry')); for (const e of reg) { delete e.baselineAt; delete e.baselineApproved; for (const t of Object.values(e.tools)) { if (t.status === 'trusted' || t.status==='pending-review') { t.status = 'ok'; if(!t.fp){t.fp=t.pendingFp;} } delete t.baseStatus; } }
  w.localStorage.setItem('mcpw:registry', JSON.stringify(reg)); T.Registry.live.clear();
  await T.Registry.boot();
  console.log('migrated statuses:', T.Registry.entries.map(e => e.id + ':' + Object.values(e.tools).map(t => t.status).join('/')).join('  '));
  const r = await T.Warden.call({ serverId: 'warden-web-demo', tool: 'fetch_url', args: { url: 'https://docs.example-research.org/mcp-security' }, pace: 0 });
  console.log('call after migration:', r.verdict, 'pending changes:', T.Sentinel.pending().length);
})();
