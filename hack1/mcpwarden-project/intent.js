// ---------------- Task tracking and provenance ----------------
const STOPWORDS = new Set('the a an and or of to for from in on at by with this that these those is are be it its into about please then also web page pages site search find look up read fetch extract main points point summarize summarise summary recent latest what which how use using get give me my our your https http www com org test'.split(' '));
const URL_RE = /\b(?:https?|file|gopher|ftp|data|javascript):[^\s"'<>\])]+/gi;
const termsOf = s => [...new Set(String(s || '').toLowerCase().split(/[^a-z0-9]+/).filter(w => w.length > 3 && !STOPWORDS.has(w)))];
const cleanUrl = u => u.replace(/[.,;:)]+$/, '');
function normUrl(u) { try { const x = new URL(u); x.hash = ''; return x.href; } catch { return u; } }
function hostOf(u) { try { return new URL(u).hostname.toLowerCase().replace(/^\[|\]$/g, ''); } catch { return null; } }

const Tasks = {
  map: new Map(Store.get('tasks', []).map(t => [t.id, t])), eph: new Map(),
  save() { const arr = [...this.map.values()].sort((a, b) => b.ts - a.ts).slice(0, 200); Store.set('tasks', arr); this.map = new Map(arr.map(t => [t.id, t])); },
  profile(text) {
    const urls = [...String(text).matchAll(URL_RE)].map(m => normUrl(cleanUrl(m[0])));
    const hosts = [...new Set(urls.map(hostOf).filter(Boolean))];
    const category = urls.length ? (/\b(extract|main points|key points|headings|outline)\b/i.test(text) ? 'extract' : 'read') : /\b(search|find|look up|research|latest|recent)\b/i.test(text) ? 'research' : 'general';
    const permittedTools = { read: ['fetch_url', 'extract_web_content'], extract: ['fetch_url', 'extract_web_content'], research: ['search_web', 'fetch_url', 'extract_web_content'], general: ['search_web'] }[category];
    return { category, urls, hosts, permittedTools, expectsFollowups: category === 'research', readsResults: category === 'research' && /\b(read|open|summari[sz]e|top result)\b/i.test(text), terms: termsOf(text.replace(URL_RE, ' ')).slice(0, 20) };
  },
  begin(text, { source = 'playground', implicit = false, persist = true } = {}) {
    const t = { id: rid('task'), ts: now(), text: safeText(String(text)).slice(0, 300), source, implicit, profile: this.profile(text), observed: [], calls: [] };
    (persist ? this.map : this.eph).set(t.id, t);
    if (persist) { this.save(); Bus.emit({ type: 'task', task: t }); }
    else if (this.eph.size > 30) this.eph.delete(this.eph.keys().next().value);
    return t;
  },
  get(id) { return this.map.get(id) || this.eph.get(id) || null; },
  touch(t) { if (this.map.has(t.id)) this.save(); },
  // Record every URL MCPWarden itself delivered to the agent, so provenance never depends on agent claims.
  observe(task, run, text) {
    if (!task || !text) return;
    const kind = run.tool === 'search_web' ? 'search-result' : 'page-content';
    for (const m of text.matchAll(URL_RE)) {
      const url = normUrl(cleanUrl(m[0]));
      if (task.observed.some(o => o.url === url && o.sourceRunId === run.id)) continue;
      const ls = text.lastIndexOf('\n', m.index) + 1; const le = text.indexOf('\n', m.index);
      task.observed.push({ url, host: hostOf(url), kind, sourceRunId: run.id, ts: now(), excerpt: safeText(text.slice(ls, le < 0 ? undefined : le).trim().slice(0, 220)) });
    }
    task.observed = task.observed.slice(-80); this.touch(task);
  }
};

// ---------------- Agent Intent Firewall ----------------
const EXFIL_KEYS = /^(d|data|ctx|context|payload|token|secret|session|key|creds?|dump|q|exfil|blob)$/i;
const EXFIL_PATH = /(upload|collect|exfil|sink|beacon|webhook|ingest|track|c2)/i;
const ACTION_RANK = { allow: 0, review: 1, block: 2 };
const Intent = {
  list: Store.get('intents', []),
  save() { this.list = this.list.slice(0, 300); Store.set('intents', this.list); Bus.emit({ type: 'intent' }); },
  provenance(task, n) {
    if (!n) return { kind: 'no-destination', label: 'No destination (search provider)' };
    const url = normUrl(n.url);
    if (task.profile.urls.includes(url)) return { kind: 'user-task', match: 'exact', label: 'URL named in the original task' };
    if (task.profile.hosts.includes(n.host)) return { kind: 'user-task', match: 'host', label: 'Host named in the original task' };
    const exact = [...task.observed].reverse().find(o => o.url === url);
    const o = exact || [...task.observed].reverse().find(o => o.host === n.host);
    if (o) return { kind: o.kind, match: exact ? 'exact' : 'host', sourceRunId: o.sourceRunId, excerpt: o.excerpt, label: o.kind === 'search-result' ? 'Taken from a search result MCPWarden returned in this task' : 'Taken from web page content MCPWarden returned in this task' };
    return { kind: 'unknown', label: 'Not in the task and never returned by a tool in this task' };
  },
  evaluate(task, run, n) {
    const P = Warden.policy.intent; const prof = task.profile;
    const prior = task.calls.filter(id => id !== run.id);
    const isFollowup = prior.length > 0;
    const prov = this.provenance(task, n);
    const signals = [];
    const rule = (id, label, policyKey, evidence) => signals.push({ id, label, kind: 'rule', policy: `policy.intent.${policyKey}`, action: P[policyKey], evidence });
    if (!prof.permittedTools.includes(run.tool)) rule('out-of-scope-tool', `${run.tool} is outside what a "${prof.category}" task needs (${prof.permittedTools.join(', ')})`, 'outOfScopeTools', { category: prof.category, permitted: prof.permittedTools });
    if (prior.length >= P.maxCallsPerTask) signals.push({ id: 'call-budget', label: `Task already made ${prior.length} tool calls; limit is ${P.maxCallsPerTask}`, kind: 'rule', policy: 'policy.intent.maxCallsPerTask', action: 'block', evidence: { prior: prior.length } });
    if (n && prov.kind === 'page-content') rule('content-derived', `Destination ${n.host} was suggested by web page content, not by the user`, 'contentDerivedFollowups', { sourceRunId: prov.sourceRunId, excerpt: prov.excerpt });
    if (n && prov.kind === 'unknown') rule('unknown-provenance', `Destination ${n.host} was neither named by the user nor returned by any tool in this task`, 'unknownProvenance', null);
    if (n && prov.kind !== 'user-task') {
      let q = []; try { q = [...new URL(n.url).searchParams.entries()]; } catch { }
      const keys = q.filter(([k, v]) => EXFIL_KEYS.test(k) || v.length >= 16).map(([k]) => k);
      const pathHit = EXFIL_PATH.test(n.host + n.path.split('?')[0]);
      if (keys.length || pathHit) rule('exfil-shape', `Request is shaped like data exfiltration (${[keys.length ? 'parameters ' + keys.join(', ') : null, pathHit ? 'collector-style host or path' : null].filter(Boolean).join('; ')})`, 'exfiltrationShape', { parameters: keys, collectorPattern: pathHit });
    }
    if (n && prov.kind === 'search-result' && prof.category === 'research') signals.push({ id: 'expected-followup', label: 'Following a search result is expected for a research task', kind: 'info', action: 'allow' });
    if (!isFollowup && (!n || prov.kind === 'user-task')) signals.push({ id: 'primary', label: n ? 'First call of the task goes where the user asked' : 'First call of the task matches its category', kind: 'info', action: 'allow' });
    // Advisory contextual classifier: lexical relevance between the task and the action. Can only escalate allow → review.
    let relevance = null;
    if (P.classifier === 'advisory' && isFollowup && n) {
      const terms = prof.terms; const hay = new Set(termsOf(`${n.host} ${n.path} ${prov.excerpt || ''}`));
      relevance = terms.length ? +(terms.filter(t => hay.has(t)).length / Math.min(terms.length, 6)).toFixed(2) : null;
      if (relevance !== null && relevance < 0.15) signals.push({ id: 'low-relevance', label: `Low relevance to the task (score ${relevance})`, kind: 'advisory', action: 'review', policy: 'policy.intent.classifier', evidence: { taskTerms: terms.slice(0, 8), relevance } });
    }
    let decision = 'allow', decisive = null;
    for (const s of signals.filter(s => s.kind === 'rule')) if (ACTION_RANK[s.action] > ACTION_RANK[decision]) { decision = s.action; decisive = s; }
    const adv = signals.find(s => s.kind === 'advisory');
    if (adv && decision === 'allow') { decision = 'review'; decisive = adv; }
    if (!P.enabled) { decision = 'allow'; decisive = null; }
    const fired = signals.filter(s => s.kind !== 'info' && s.action !== 'allow');
    const explanation = !P.enabled ? 'Intent firewall is disabled by policy; signals were recorded but not enforced.'
      : decision === 'allow' ? (fired.length ? 'Signals were raised but policy allows them: ' + fired.map(s => s.label).join('; ') : (signals.find(s => s.kind === 'info')?.label || 'Action is consistent with the original task.'))
        : `${decision === 'block' ? 'Blocked' : 'Held for review'}: ${decisive.label}. Policy ${decisive.policy} = ${decisive.kind === 'advisory' ? 'review (advisory classifier)' : decisive.action}.`;
    return { id: rid('int'), ts: now(), requestId: run.id, taskId: task.id, taskText: task.text, profile: { category: prof.category, permittedTools: prof.permittedTools, hosts: prof.hosts }, tool: run.tool, destination: n ? sanitizeUrl(n.url) : null, isFollowup, priorCalls: prior.length, provenance: prov, signals, relevance, decision, rule: decisive?.policy || 'policy.intent', explanation, policyVersion: Warden.policy.version, enforced: P.enabled };
  },
  store(ev) { if (!ev) return; this.list.unshift(ev); this.save(); }
};

// ---------------- Explainable decision records ----------------
const Decisions = {
  list: Store.get('decisions', []),
  save() { this.list = this.list.slice(0, 250); Store.set('decisions', this.list); Bus.emit({ type: 'decision' }); },
  get(id) { return this.list.find(d => d.requestId === id); },
  build(run, task, auditEntry) {
    const fwd = run.stages[STAGE_IDX.forward];
    const toolExecuted = fwd.status === 'passed' ? 'yes' : (fwd.status === 'blocked' || fwd.status === 'failed') && run.hops?.some(h => h.ok) ? 'partial' : 'no';
    const toolEv = run.stages[STAGE_IDX.tool].evidence;
    return {
      requestId: run.id, ts: run.ts, source: run.source, session: run.session, taskId: run.taskId, taskText: task?.text || null, implicitTask: !!task?.implicit,
      parentRequestId: run.parentRequestId || null, provenance: run.intent?.provenance || run.provenance || null, intentId: run.intent?.id || null,
      server: run.serverId, tool: run.tool, args: safeText(JSON.stringify(run.args ?? null)).slice(0, 400), destination: run.destination || (run.tool === 'search_web' ? 'search provider' : null),
      stages: run.stages.map(s => ({ n: s.n, key: s.key, name: s.name, phase: s.phase, status: s.status, result: s.result ? safeText(String(s.result)).slice(0, 400) : null, rule: s.rule || null, ms: s.ms ?? null, at: s.at || null, evidence: s.evidence ? safeText(JSON.stringify(s.evidence, null, 1)).slice(0, 1600) : null })),
      decision: run.decision, verdict: run.verdict, rule: run.rule || null, blockingStage: run.blockingStage || null, reason: run.reason ? safeText(String(run.reason)).slice(0, 300) : null,
      connections: run.connections || 0, internalConnections: run.internalConnections || 0, hops: (run.hops || []).map(h => ({ hop: h.hop, url: h.url, ok: h.ok, status: h.status, reason: h.reason })),
      toolExecuted, responseOutcome: run.response?.outcome || null, responseBytes: run.response?.meta?.bytes ?? null,
      findings: run.findings ? { injectionScore: run.findings.injection.score, injectionHits: run.findings.injection.hits.filter(h => !h.discounted).map(h => h.label), steering: run.findings.steering.length, secrets: run.findings.sensitive.filter(f => f.kind === 'secret').length, pii: run.findings.sensitive.filter(f => f.kind === 'pii').length } : null,
      changeId: toolEv?.changeId || null, latency: run.latency, auditSeq: auditEntry?.seq ?? null, auditHash: auditEntry?.hash ?? null, policyVersion: Warden.policy.version
    };
  },
  add(run, task, auditEntry) { const d = this.build(run, task, auditEntry); this.list.unshift(d); this.save(); return d; },
  // Explanations are composed only from recorded stage results.
  explain(d) {
    const st = d.stages; const by = k => st.filter(s => s.status === k);
    const ran = st.filter(s => ['passed', 'failed', 'blocked'].includes(s.status));
    const fwd = st.find(s => s.key === 'forward');
    const out = { ran: ran.length, passed: by('passed'), flagged: by('failed'), blocked: by('blocked'), skipped: by('skipped'), pending: by('pending') };
    if (d.decision === 'DENY') {
      const b = st.find(s => s.key === d.blockingStage) || by('blocked')[0];
      out.failedStage = b; out.rule = d.rule;
      out.why = d.reason;
      out.connection = d.connections > 0 ? `Yes. ${d.connections} connection(s) were opened (${d.hops.filter(h => h.ok).map(h => h.url).join(', ') || 'see hops'}); ${d.internalConnections} to internal addresses.` : fwd.status === 'skipped' ? `No. The request was stopped at stage ${b?.n}, before stage ${fwd.n} (forwarding) where connections happen.` : 'No. The egress layer refused before opening a connection.';
      out.executed = d.toolExecuted === 'yes' ? 'Yes' : d.toolExecuted === 'partial' ? 'Partially: an earlier hop was fetched, the blocked operation never ran' : 'No. The protected operation did not execute.';
    }
    return out;
  }
};

// ---------------- Attack chain correlation ----------------
// Builds a graph from persisted decision records of one task. Every edge carries its basis:
// "confirmed" edges come from IDs MCPWarden recorded itself; "inferred" edges come only from
// agent-declared parents or ordering, and are drawn differently.
const Chains = {
  forTask(taskId) {
    const task = Tasks.get(taskId); const ds = Decisions.list.filter(d => d.taskId === taskId).sort((a, b) => a.ts - b.ts);
    if (!task && !ds.length) return null;
    const nodes = [], edges = [];
    const add = n => { nodes.push(n); return n.id; };
    const root = add({ id: 'task', type: 'task', col: 0, row: 0, title: 'Original user task', sub: task?.text || ds[0]?.taskText || '(unknown task)', status: 'info', ts: task?.ts, evidence: task ? { task: task.text, category: task.profile.category, permittedTools: task.profile.permittedTools, namedHosts: task.profile.hosts, implicit: task.implicit } : null });
    const detectTs = (ds.find(d => d.verdict !== 'ALLOWED' || (d.findings && (d.findings.injectionHits.length || d.findings.secrets || d.findings.steering))) || {}).ts ?? Infinity;
    const lastNodeOf = {};
    ds.forEach((d, i) => {
      const col = i; let row = 1;
      const isFollow = !!(d.provenance && ['page-content', 'search-result', 'unknown'].includes(d.provenance.kind) && i > 0) || !!d.parentRequestId;
      const unexpected = d.provenance && ['page-content', 'unknown'].includes(d.provenance.kind);
      const callId = add({ id: d.requestId, type: isFollow ? (unexpected ? 'followup' : 'call') : 'call', col, row: row++, title: isFollow ? (unexpected ? 'Unexpected follow-up action' : 'Follow-up tool call') : 'MCP tool call', sub: `${d.tool} ${d.destination || ''}`, status: d.verdict === 'ALLOWED' ? 'ok' : d.verdict === 'SANITIZED' ? 'warn' : 'bad', ts: d.ts, executed: d.toolExecuted, beforeDetection: d.toolExecuted !== 'no' && d.ts <= detectTs, ref: d.requestId, evidence: { requestId: d.requestId, tool: d.tool, server: d.server, destination: d.destination, provenance: d.provenance, toolExecuted: d.toolExecuted, connections: d.connections } });
      // Edge into the call
      let from = root, basis = 'confirmed', why = 'Task ID recorded by MCPWarden on this call';
      if (d.provenance?.sourceRunId && lastNodeOf[d.provenance.sourceRunId]) { from = lastNodeOf[d.provenance.sourceRunId].src; why = `${d.provenance.label} (${d.provenance.match} match, recorded by MCPWarden)`; }
      else if (d.parentRequestId && lastNodeOf[d.parentRequestId]) { from = lastNodeOf[d.parentRequestId].src; basis = 'inferred'; why = 'Parent declared by the agent; MCPWarden found no matching URL in that response'; }
      edges.push({ from, to: callId, basis, why });
      let prev = callId; let src = callId;
      if (d.changeId) { const c = Sentinel.find(d.changeId); const id = add({ id: d.requestId + ':chg', type: 'integrity', col, row: row++, title: 'Tool definition changed', sub: c ? `${c.tool}: ${c.classification}` : d.changeId, status: 'bad', ts: c?.ts, evidence: c ? { change: c.kind, classification: c.classification, reasons: c.reasons, status: c.status, beforeFp: c.beforeFp, afterFp: c.afterFp } : { changeId: d.changeId } }); edges.push({ from: prev, to: id, basis: 'confirmed', why: 'Blocking rule references this change record' }); prev = id; }
      if (d.responseOutcome) { const id = add({ id: d.requestId + ':ret', type: 'retrieved', col, row: row++, title: 'Webpage retrieved', sub: `${(d.responseBytes || 0).toLocaleString()} bytes, ${d.responseOutcome}`, status: 'ok', ts: d.stages.find(s => s.key === 'received')?.at, evidence: { received: d.stages.find(s => s.key === 'received')?.result, hops: d.hops } }); edges.push({ from: prev, to: id, basis: 'confirmed', why: 'Same request ID' }); prev = id; src = id; }
      const f = d.findings;
      if (f && (f.injectionHits.length || f.steering || f.secrets || f.pii)) {
        const id = add({ id: d.requestId + ':sus', type: 'suspicious', col, row: row++, title: 'Suspicious content detected', sub: [f.injectionHits.length ? `injection ${f.injectionScore}` : null, f.steering ? `${f.steering} tool refs` : null, f.secrets ? `${f.secrets} secrets` : null, f.pii ? `${f.pii} PII` : null].filter(Boolean).join(', '), status: 'warn', ts: d.stages.find(s => s.key === 'injection')?.at, evidence: { injection: d.stages.find(s => s.key === 'injection')?.result, steering: d.stages.find(s => s.key === 'poisoning')?.result, secrets: d.stages.find(s => s.key === 'secrets')?.result } });
        edges.push({ from: prev, to: id, basis: 'confirmed', why: 'Same request ID' }); prev = id;
      }
      if (d.rule) { const bs = d.stages.find(s => s.key === d.blockingStage) || d.stages.find(s => s.key === 'rpolicy'); const id = add({ id: d.requestId + ':pol', type: 'policy', col, row: row++, title: 'Security policy triggered', sub: d.rule, status: d.verdict === 'SANITIZED' ? 'warn' : 'bad', ts: bs?.at, evidence: { stage: bs ? `${bs.n}. ${bs.name}` : null, rule: d.rule, result: bs?.result } }); edges.push({ from: prev, to: id, basis: 'confirmed', why: 'Same request ID' }); prev = id; }
      const id = add({ id: d.requestId + ':dec', type: 'decision', col, row: row++, title: d.verdict, sub: d.reason ? d.reason.slice(0, 70) : 'All checks passed', status: d.verdict === 'ALLOWED' ? 'ok' : d.verdict === 'SANITIZED' ? 'warn' : 'bad', ts: d.ts + (d.latency || 0), ref: d.requestId, evidence: { decision: d.decision, verdict: d.verdict, auditSeq: d.auditSeq, latencyMs: d.latency } });
      edges.push({ from: prev, to: id, basis: 'confirmed', why: 'Same request ID' });
      lastNodeOf[d.requestId] = { src };
    });
    const incident = ds.some(d => d.verdict !== 'ALLOWED') || ds.some(d => d.findings && (d.findings.injectionHits.length || d.findings.secrets || d.findings.steering));
    return { task, decisions: ds, nodes, edges, incident, executedBeforeDetection: ds.filter(d => d.toolExecuted !== 'no' && d.ts <= detectTs), blocked: ds.filter(d => d.verdict === 'DENIED' || d.verdict === 'BLOCKED') };
  },
  list() {
    const ids = [...new Set(Decisions.list.map(d => d.taskId).filter(Boolean))];
    return ids.map(id => { const ds = Decisions.list.filter(d => d.taskId === id); const t = Tasks.get(id); return { taskId: id, text: t?.text || ds[0].taskText, ts: Math.min(...ds.map(d => d.ts)), calls: ds.length, implicit: t?.implicit ?? ds[0].implicitTask, incident: ds.some(d => d.verdict !== 'ALLOWED') || ds.some(d => d.findings && (d.findings.injectionHits.length || d.findings.secrets || d.findings.steering)), worst: ds.some(d => d.verdict === 'DENIED' || d.verdict === 'BLOCKED') ? 'bad' : ds.some(d => d.verdict === 'SANITIZED') ? 'warn' : 'ok' }; }).sort((a, b) => b.ts - a.ts);
  }
};
