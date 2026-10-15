// =====================================================================
// Live mode client
// When this page is served by the MCPWarden backend, the dashboard stops running the in-browser engine.
// The same objects the pages read (Warden, Registry, Audit, Sentinel, Decisions, Intent, Tasks, Lab) become
// a mirror of backend state, every action is sent to the backend API, and backend events are replayed on
// the page's Bus so the existing pages update exactly as before. Nothing security-relevant runs here.
// When no backend answers (for example the published demo), this file does nothing.
// =====================================================================
const LIVE = { on: false, connected: false, network: null, labLastAll: null, mirrorState: {}, fixtureHosts: 0, allowDestructiveDemo: false };
const Api = {
  async req(method, path, body) {
    let r;
    try { r = await fetch(path, { method, credentials: 'same-origin', cache: 'no-store', headers: method === 'GET' ? {} : { 'content-type': 'application/json', 'x-mcpwarden-csrf': '1' }, body: method === 'GET' ? undefined : JSON.stringify(body || {}) }); }
    catch { throw new Error('The MCPWarden backend is unreachable'); }
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || `Backend returned HTTP ${r.status}`);
    return j;
  },
  get: p => Api.req('GET', p), post: (p, b) => Api.req('POST', p, b),
};
const LiveClient = {
  async detect() {
    try {
      const c = new AbortController(); const t = setTimeout(() => c.abort(), 1500);
      const r = await fetch('/api/health', { signal: c.signal, cache: 'no-store', credentials: 'same-origin' }); clearTimeout(t);
      if (!r.ok) return null; const j = await r.json();
      return j && j.product === 'mcpwarden' && j.mode === 'live' ? j : null;
    } catch { return null; }
  },
  async start(health) {
    LIVE.on = true; LIVE.network = health.network;
    this.hydrate(await Api.get('/api/state'));
    this.override();
    this.connect();
  },
  hydrate(s) {
    Warden.policy = s.policy; Warden.policyHistory = s.policyHistory;
    Registry.entries = s.registry; Registry.live = new Map();
    Audit.list = s.audit; Audit.healthy = s.auditHealthy;
    Sentinel.changes = s.integrity; Decisions.list = s.decisions; Intent.list = s.intents;
    Tasks.map = new Map(s.tasks.map(t => [t.id, t])); Tasks.eph = new Map();
    Lab.results = s.lab || {}; LIVE.labLastAll = s.labLastAll;
    Warden.runs = new Map(s.runs.map(r => [r.id, r]));
    Warden.approvals = new Map(s.approvals.map(a => [a.id, a]));
    LIVE.mirrorState = s.mirrorState || {}; LIVE.fixtureHosts = s.fixtureHosts || 0; LIVE.allowDestructiveDemo = !!s.allowDestructiveDemo;
    this.setNet(s.netInternal || 0);
  },
  setNet(internal) { Net = { connections: Array.from({ length: internal }, () => ({ internal: true })), hosts: () => [] }; },
  upsertRun(snap) {
    const cur = Warden.runs.get(snap.id);
    if (!cur) { Warden.runs.set(snap.id, snap); if (Warden.runs.size > 80) Warden.runs.delete(Warden.runs.keys().next().value); return snap; }
    for (const k of Object.keys(cur)) if (!(k in snap)) delete cur[k];
    Object.assign(cur, snap); return cur; // keep the same object so pages holding a reference stay current
  },
  override() {
    const fail = e => { toast(e.message); return null; };
    Warden.call = async () => { throw new Error('Live mode: tool calls go through the MCPWarden MCP endpoint'); };
    Warden.savePolicy = async (p, note) => { try { const r = await Api.post('/api/policy', { policy: p, note }); if (r.policy) { Warden.policy = r.policy; Warden.policyHistory = r.policyHistory; } return r; } catch (e) { return { ok: false, errs: [e.message] }; } };
    Warden.decideApproval = (id, approve) => { Api.post(`/api/approvals/${id}`, { approve }).catch(fail); };
    Warden.destinationSafety = async n => { try { return await Api.post('/api/policy/destination', { url: n.url }); } catch (e) { return { ok: false, reason: e.message, rule: 'backend.unreachable' }; } };
    Warden.adminEvent = async () => { };
    const reg = (id, action) => Api.post(`/api/registry/${encodeURIComponent(id)}/${action}`).then(r => r.result).catch(fail);
    Registry.boot = async () => { };
    Registry.verify = id => reg(id, 'verify');
    Registry.pinIdentity = id => reg(id, 'pin');
    Registry.setTrusted = async (id, v) => (await reg(id, v ? 'trust' : 'untrust')) || { ok: false, msg: 'Backend request failed' };
    Registry.setEnabled = (id, v) => reg(id, v ? 'enable' : 'disable');
    Registry.remove = id => reg(id, 'remove');
    Registry.register = async body => { try { return await Api.post('/api/registry', body); } catch (e) { return { ok: false, errs: [e.message] }; } };
    Sentinel.scanAll = () => Api.post('/api/sentinel/scan').catch(fail);
    Sentinel.simulate = (flag, on) => Api.post('/api/sentinel/simulate', { flag, on }).catch(fail);
    Sentinel.approve = async id => { try { return await Api.post(`/api/sentinel/changes/${id}/approve`); } catch (e) { return { ok: false, msg: e.message }; } };
    Sentinel.reject = async id => { try { return await Api.post(`/api/sentinel/changes/${id}/reject`); } catch (e) { return { ok: false, msg: e.message }; } };
    Sentinel.mirror = () => LIVE.mirrorState;
    Audit.verify = async () => { try { return await Api.post('/api/audit/verify'); } catch (e) { return { ok: false, seq: '?', why: e.message }; } };
    Audit.tamper = async () => { try { return (await Api.post('/api/audit/tamper')).seq; } catch (e) { toast(e.message); return null; } };
    Audit.clear = async () => { try { await Api.post('/api/audit/clear'); return true; } catch (e) { toast(e.message); return false; } };
    Agent.runTask = async (text, { mode = 'standard', serverId = 'warden-web-demo', pace, onPlan } = {}) => {
      const plan = Agent.plan(text); onPlan?.(plan);
      if (plan.error) return { plan, runs: [] };
      const r = await Api.post('/api/agent/run', { task: text, mode, serverId, pace: pace ?? Settings.pace }).catch(e => { toast(e.message); return null; });
      if (!r) return { plan, runs: [] };
      return { plan, task: Tasks.get(r.taskId) || { id: r.taskId }, runs: r.runIds.map(id => Warden.runs.get(id)).filter(Boolean) };
    };
    Lab.run = async sc => { try { return await Api.post('/api/lab/run', { id: sc.id, pace: 30 }); } catch (e) { toast(e.message); return null; } };
    Lab.runAll = async onEach => {
      const off = Bus.on(e => { if (e.type === 'lab') onEach?.(e.result); });
      try { await Api.post('/api/lab/run-all'); } catch (e) { toast(e.message); } finally { off(); }
      return LAB.map(s => Lab.results[s.id]).filter(Boolean);
    };
    Rate.resetAll = () => { Api.post('/api/rate/reset').catch(fail); };
    MockNet.hosts = () => Array(LIVE.fixtureHosts).fill('');
    const get = Store.get.bind(Store);
    Store.get = (k, d) => k === 'labLastAll' ? (LIVE.labLastAll ?? d) : get(k, d);
  },
  async resetRegistry() { await Api.post('/api/reset/registry').catch(e => toast(e.message)); },
  async clearLab() { await Api.post('/api/lab/clear').catch(e => toast(e.message)); },
  connect() {
    const es = new EventSource('/api/events');
    es.onopen = () => { if (!LIVE.connected) { LIVE.connected = true; updateModePill(); } };
    es.onerror = () => { if (LIVE.connected) { LIVE.connected = false; this.needResync = true; updateModePill(); } };
    es.onmessage = ev => { let m; try { m = JSON.parse(ev.data); } catch { return; } this.handle(m); };
  },
  async handle(m) {
    switch (m.type) {
      case 'hello':
        LIVE.connected = true;
        if (this.needResync) { this.needResync = false; try { this.hydrate(await Api.get('/api/state')); } catch { } route(); }
        updateModePill(); break;
      case 'run': case 'stage': case 'done': {
        const run = this.upsertRun(m.run);
        if (m.task) Tasks.map.set(m.task.id, m.task);
        if (m.netInternal != null) this.setNet(m.netInternal);
        Bus.emit({ type: m.type, run, stage: m.stageKey ? run.stages[STAGE_IDX[m.stageKey]] : undefined }); break;
      }
      case 'audit':
        if (m.entry) { if (!Audit.list.some(e => e.seq === m.entry.seq)) Audit.list.push(m.entry); } else if (m.reload) Audit.list = m.reload;
        Bus.emit({ type: 'audit', entry: m.entry }); break;
      case 'approval': {
        Warden.approvals.set(m.approval.id, m.approval);
        const run = Warden.runs.get(m.approval.runId); if (run) run.approvalId = m.approval.id; // the backend sets this after the last stage event
        Bus.emit({ type: 'approval', approval: m.approval }); break;
      }
      case 'registry': Registry.entries = m.entries; Bus.emit({ type: 'registry' }); break;
      case 'policy': Warden.policy = m.policy; Warden.policyHistory = m.policyHistory; Bus.emit({ type: 'policy' }); break;
      case 'integrity': {
        const byId = new Map(Sentinel.changes.map(c => [c.id, c])); for (const c of m.changes) byId.set(c.id, c);
        Sentinel.changes = [...byId.values()].sort((a, b) => b.ts - a.ts); LIVE.mirrorState = m.mirrorState || {};
        Bus.emit({ type: 'integrity' }); break;
      }
      case 'intent': if (m.ev) { Intent.list = [m.ev, ...Intent.list.filter(x => x.id !== m.ev.id)]; } Bus.emit({ type: 'intent' }); break;
      case 'decision': if (m.d) { Decisions.list = [m.d, ...Decisions.list.filter(x => x.requestId !== m.d.requestId)]; } Bus.emit({ type: 'decision' }); break;
      case 'task': if (m.task) Tasks.map.set(m.task.id, m.task); Bus.emit({ type: 'task', task: m.task }); break;
      case 'lab': if (m.result) Lab.results[m.result.id] = m.result; LIVE.labLastAll = m.labLastAll; Bus.emit({ type: 'lab', result: m.result }); break;
      case 'lab-reset': Lab.results = {}; LIVE.labLastAll = null; Bus.emit({ type: 'lab' }); break;
      default: Bus.emit(m);
    }
  }
};
