// =====================================================================
// Advanced features UI
// =====================================================================
const rerender = page => { if (UI.page !== page) return; const y = $('#view').scrollTop; $('#view').innerHTML = page.render(); page.mount?.(); icons(); $('#view').scrollTop = y; };
const statusBadge = s => `<span class="badge ${{ passed: 'allow', blocked: 'deny', failed: 'warn', running: 'info' }[s] || 'mute'}">${s === 'failed' ? 'flagged' : s === 'skipped' ? 'not executed' : s}</span>`;

// ---------------- Threat Sandbox ----------------
const expStr = sc => [].concat(sc.expect.verdict).join(' or ') + (sc.expect.stage ? ` at ${STAGE_NAME(sc.expect.stage).toLowerCase()}` : '') + (sc.expect.classification ? `, change classified ${sc.expect.classification}` : '');
function policyDiffFromDefault() { const P = Warden.policy; return Object.keys(DEFAULT_POLICY).filter(k => k !== 'version' && canon(P[k]) !== canon(DEFAULT_POLICY[k])); }
PAGES.lab = {
  title: 'Threat Sandbox', sub: `${LAB.length} synthetic web threats and benign cases, run against the real engine and a controlled mock network`,
  render() {
    const m = Lab.metrics(); const internal = Net.connections.filter(c => c.internal).length;
    const pct = x => x == null ? '—' : (100 * x).toFixed(0) + '%';
    const diff = policyDiffFromDefault();
    const cats = [...new Set(LAB.map(s => s.cat))];
    const f = this.f || {};
    const rows = LAB.filter(sc => { const r = Lab.results[sc.id]; return (!f.cat || sc.cat === f.cat) && (!f.res || (f.res === 'fail' ? r && !r.pass : f.res === 'pass' ? r?.pass : !r)) && (!f.q || (sc.name + sc.id + sc.cat).toLowerCase().includes(f.q.toLowerCase())); });
    return `<div class="stack">
    <div class="row wrap"><button class="btn primary lg" id="runall">${ic('play')}Run Security Test Suite</button><span class="muted" style="font-size:12.5px" id="labprog">${Store.get('labLastAll') ? 'Last full run ' + fmtTime(Store.get('labLastAll')) : 'Not run yet in this browser'}</span></div>
    ${diff.length ? `<div class="banner warn">${ic('file-cog')}<div><b>Policy v${Warden.policy.version} differs from the defaults in: ${diff.join(', ')}.</b> Expected results describe the default policy, so some scenarios may now legitimately produce a different outcome. Rerun the suite to see how your changes behave.</div></div>` : ''}
    <div class="metrics">
      <div><div class="v ${m.ran && m.passed === m.ran ? 'g' : m.ran ? 'r' : ''}">${m.passed}/${m.ran}</div><div class="l">Matching expectation (of ${LAB.length})</div></div>
      <div><div class="v">${pct(m.detectionRate)}</div><div class="l">Detection rate, TP/(TP+FN)</div></div>
      <div><div class="v">${pct(m.fpr)}</div><div class="l">False-positive rate, FP/(FP+TN)</div></div>
      <div><div class="v ${m.FN ? 'r' : ''}">${m.FN}</div><div class="l">Attacks let through</div></div>
      <div><div class="v ${m.FP ? 'r' : ''}">${m.FP}</div><div class="l">Benign cases blocked</div></div>
      <div><div class="v ${internal ? 'r' : 'g'}">${internal}</div><div class="l">Connections ever opened to internal addresses</div></div>
    </div>
    <div class="banner">${ic('shield')}<div>${isLive() ? 'Live mode: requests travel over real MCP and real sockets to a local fixture web server; prohibited destinations exist only as fixtures there, so no real internal or third-party system is ever contacted.' : 'Prohibited destinations exist only as fixtures in an in-page mock network, so no real internal or third-party system is ever contacted.'} Expected results are fixed labels written before execution; actual results are read from the engine's run records. ${LAB.filter(s => s.malicious).length} malicious and ${LAB.filter(s => !s.malicious).length} benign cases. Benign case L28 counts as a false positive only if a harmless tool change is classified as suspicious.</div></div>
    <div class="row wrap"><input class="input" id="lq" placeholder="Search scenarios" style="max-width:260px" value="${esc(f.q || '')}"><select class="input" id="lc" style="max-width:240px"><option value="">All threat categories</option>${cats.map(c => `<option ${f.cat === c ? 'selected' : ''}>${esc(c)}</option>`).join('')}</select><select class="input" id="lr" style="max-width:160px"><option value="">Any result</option><option value="pass" ${f.res === 'pass' ? 'selected' : ''}>Pass</option><option value="fail" ${f.res === 'fail' ? 'selected' : ''}>Fail</option><option value="none" ${f.res === 'none' ? 'selected' : ''}>Not run</option></select></div>
    <div class="panel flush"><div class="pb scroll-x"><table class="t" id="labt"><thead><tr><th>#</th><th>Scenario</th><th>Threat category</th><th>Expected</th><th>Actual</th><th>Checks executed</th><th>Triggered policy</th><th>Time</th><th>Result</th><th></th></tr></thead><tbody>
    ${rows.map(sc => { const r = Lab.results[sc.id]; return `<tr class="click ${UI.labSel === sc.id ? 'sel' : ''}" data-id="${sc.id}"><td class="mono dim">${sc.id}</td><td>${esc(sc.name)}</td><td><span class="badge ${sc.malicious ? 'purple' : 'info'}">${esc(sc.cat)}</span></td>
      <td style="font-size:12px">${esc(expStr(sc))}</td><td>${r ? vbadge(r.actual.verdict) + (r.actual.stage ? `<div class="dim" style="font-size:11.5px;margin-top:3px">${esc(STAGE_NAME(r.actual.stage))}</div>` : '') + (r.actual.classification ? `<div class="dim" style="font-size:11.5px">classified ${esc(r.actual.classification)}</div>` : '') : '<span class="dim">not run</span>'}</td>
      <td class="mono" style="font-size:12px">${r?.checks ? `${r.checks.executed}/${STAGES.length}<div class="dim">${r.checks.skipped} skipped</div>` : r ? '<span class="dim">transport</span>' : ''}</td>
      <td class="mono dim" style="font-size:11.5px">${esc(r?.actual.rule || '')}</td><td class="mono" style="font-size:12px">${r ? fmtMs(r.engineMs || r.ms) : ''}</td><td>${r ? (r.pass ? '<span class="badge allow">PASS</span>' : '<span class="badge deny">FAIL</span>') : ''}</td>
      <td><button class="btn sm" data-run="${sc.id}">Run</button></td></tr>`; }).join('') || '<tr><td colspan="10" class="dim">No scenarios match the filters</td></tr>'}
    </tbody></table></div></div>
    <div id="labd">${this.detail()}</div></div>`;
  },
  detail() {
    const sc = LAB.find(s => s.id === UI.labSel); if (!sc) return '';
    const r = Lab.results[sc.id];
    return `<div class="panel"><div class="ph"><h3>${sc.id}: ${esc(sc.name)}</h3><span class="grow"></span>${r ? `<span class="dim mono" style="font-size:11.5px">policy v${r.policyVersion}, ${fmtTime(r.ts)}</span>` + (r.pass ? '<span class="badge allow">PASS</span>' : '<span class="badge deny">FAIL</span>') : ''}</div><div class="pb">
      <div class="split"><div><dl class="kv">
        <dt>Threat category</dt><dd>${esc(sc.cat)} (${sc.malicious ? 'malicious' : 'benign'})</dd>
        <dt>Test input</dt><dd><pre class="code">${esc(JSON.stringify(sc.task ? { task: sc.task, agentBehaviour: sc.mode } : { server: sc.server, tool: sc.tool, arguments: sc.args, upstreamChange: sc.mutate || sc.setup || undefined }, null, 2))}</pre></dd>
        <dt>Expected</dt><dd>${esc(expStr(sc))}</dd>
        <dt>Actual</dt><dd>${r ? `${vbadge(r.actual.verdict)} ${r.actual.stage ? 'at ' + esc(STAGE_NAME(r.actual.stage)) : ''}${r.actual.classification ? `, classified ${esc(r.actual.classification)}` : ''}` : 'Not run'}</dd>
        <dt>Triggered policy</dt><dd class="mono">${esc(r?.actual.rule || '—')}</dd>
        <dt>Reason</dt><dd>${esc(r?.actual.reason || '—')}</dd>
        ${r?.note ? `<dt>Execution notes</dt><dd>${esc(r.note)}</dd>` : ''}
        <dt>Execution evidence</dt><dd>${r ? `${r.connections} connection(s) opened, ${r.internalConnections} to internal addresses; ${r.runIds.length} proxied call(s); classified ${r.outcome}` : '—'}</dd>
        <dt>Processing time</dt><dd>${r ? `${fmtMs(r.engineMs)} engine time, ${fmtMs(r.ms)} wall time including pacing` : '—'}</dd>
        ${sc.bypass ? '<dt>How it runs</dt><dd>Sends tools/call straight to the server transport without the proxy token, as a compromised agent would.</dd>' : ''}
        ${sc.mutate || sc.setup === 'rugpull' ? '<dt>How it runs</dt><dd>The mirror server changes its tool list upstream, the call is made, and the change is reverted afterwards. The sentinel records the change and the revert in the audit log.</dd>' : ''}
        ${sc.task ? '<dt>How it runs</dt><dd>The demo agent runs the task; follow-up calls it decides to make go through the proxy like any other call.</dd>' : ''}
      </dl>
      ${r ? `<div class="row wrap" style="margin-top:12px">${r.actual.runId ? `<a class="btn sm" href="#/decisions/${r.actual.runId}">${ic('file-search')}Explain decision</a>` : ''}${r.taskId ? `<a class="btn sm" href="#/chains/${r.taskId}">${ic('waypoints')}Attack chain</a>` : ''}${r.changeId ? `<a class="btn sm" href="#/sentinel">${ic('fingerprint')}Change record</a>` : ''}${r.actual.runId && Warden.runs.has(r.actual.runId) ? `<button class="btn sm" id="labpipe">${ic('git-commit-vertical')}Open in pipeline</button>` : ''}</div>` : ''}</div>
      <div>${r?.stages ? `<label class="f">Security checks executed (pipeline timeline)</label>${r.stages.map(s => `<div class="row" style="font-size:12.5px;padding:3px 0"><span class="mono dim" style="width:20px;text-align:right">${s.n}</span><span class="stlabel ${s.status}" style="width:64px">${s.status === 'skipped' ? 'not run' : s.status}</span><span class="grow" title="${esc(s.result || '')}">${esc(s.name)}</span><span class="mono dim">${fmtMs(s.ms)}</span></div>`).join('')}` : r ? '<div class="dim">This scenario does not go through the proxy pipeline; the server transport rejected it directly.</div>' : '<div class="dim">Run the scenario to see its timeline.</div>'}</div></div>
    </div></div>`;
  },
  mount() {
    $('#runall').onclick = async () => {
      $('#runall').disabled = true; let k = 0;
      try { await Lab.runAll(() => { k++; const p = $('#labprog'); if (p) p.textContent = `Running ${k}/${LAB.length}…`; }); }
      catch (e) { toast('Suite stopped: ' + e.message); }
      rerender(this); toast(`Security test suite finished: ${Lab.metrics().passed}/${LAB.length} matched expectation`);
    };
    $$('[data-run]').forEach(b => b.onclick = async ev => { ev.stopPropagation(); b.disabled = true; b.textContent = 'Running…'; UI.labSel = b.dataset.run; try { await Lab.run(LAB.find(s => s.id === b.dataset.run)); } catch (e) { toast('Scenario error: ' + e.message); } rerender(this); });
    $$('#labt tr.click').forEach(tr => tr.onclick = () => { UI.labSel = tr.dataset.id; $$('#labt tr').forEach(x => x.classList.toggle('sel', x === tr)); $('#labd').innerHTML = this.detail(); this.bindD(); icons(); });
    const setF = (k, v) => { this.f = { ...(this.f || {}), [k]: v }; rerender(this); };
    $('#lc').onchange = e => setF('cat', e.target.value); $('#lr').onchange = e => setF('res', e.target.value);
    $('#lq').oninput = e => { clearTimeout(this.t); this.t = setTimeout(() => { setF('q', e.target.value); const i = $('#lq'); i.focus(); i.setSelectionRange(i.value.length, i.value.length); }, 250); };
    this.bindD();
  },
  bindD() { const b = $('#labpipe'); if (b) b.onclick = () => { UI.focusRun = Lab.results[UI.labSel].actual.runId; UI.selStage = null; PAGES.pipeline.follow = false; location.hash = '#/pipeline'; }; }
};

// ---------------- Decision Explorer ----------------
PAGES.decisions = {
  title: 'Decision Explorer', sub: 'Evidence-backed explanation for every tool request, built only from recorded checks',
  render() {
    const f = this.f || {};
    const list = Decisions.list.filter(d => (!f.v || d.verdict === f.v) && (!f.tool || d.tool === f.tool) && (!f.q || canon([d.requestId, d.taskText, d.destination, d.rule, d.reason]).toLowerCase().includes(f.q.toLowerCase())));
    if (this.arg && Decisions.get(this.arg)) UI.decSel = this.arg;
    if (!UI.decSel || !Decisions.get(UI.decSel)) UI.decSel = list[0]?.requestId;
    const tools = [...new Set(Decisions.list.map(d => d.tool))];
    return `<div class="split" style="grid-template-columns:minmax(0,.75fr) minmax(0,1.25fr)">
      <div class="stack">
        <div class="row wrap"><input class="input" id="dq" placeholder="Search ID, task, destination, rule" value="${esc(f.q || '')}"><select class="input" id="dv" style="max-width:140px"><option value="">All verdicts</option>${['ALLOWED', 'SANITIZED', 'DENIED', 'BLOCKED', 'FAILED'].map(v => `<option ${f.v === v ? 'selected' : ''}>${v}</option>`).join('')}</select><select class="input" id="dt2" style="max-width:170px"><option value="">All tools</option>${tools.map(t => `<option ${f.tool === t ? 'selected' : ''}>${esc(t)}</option>`).join('')}</select></div>
        <div class="panel flush"><div class="pb" style="max-height:calc(100vh - 230px);overflow:auto">${list.length ? `<table class="t"><tbody>${list.slice(0, 150).map(d => `<tr class="click ${UI.decSel === d.requestId ? 'sel' : ''}" data-d="${d.requestId}"><td>${vbadge(d.verdict)}</td><td style="font-size:12px"><div class="mono">${esc(d.tool)} <span class="dim">${esc(d.destination || '')}</span></div><div class="dim" style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(d.taskText || '')}</div></td><td class="mono dim" style="font-size:11.5px">${fmtTime(d.ts)}</td></tr>`).join('')}</tbody></table>` : `<div class="pb"><div class="empty"><b>No decisions recorded</b>Run a task in the playground or the security test suite.</div></div>`}</div></div>
      </div>
      <div id="dexp">${this.detail(Decisions.get(UI.decSel))}</div></div>`;
  },
  detail(d) {
    if (!d) return '<div class="empty"><b>Select a decision</b>Every proxied request gets a record here.</div>';
    const x = Decisions.explain(d);
    const cls = VCLS[d.verdict] === 'allow' ? 'allow' : VCLS[d.verdict] === 'warn' ? 'warn' : 'deny';
    const group = (title, arr, note) => arr.length ? `<div style="margin-top:14px"><label class="f">${title} (${arr.length})${note ? ` <span class="dim">${note}</span>` : ''}</label>${arr.map(s => `<details class="ev"><summary><span class="mono dim" style="width:22px;display:inline-block">${s.n}</span>${statusBadge(s.status)}<span>${esc(s.name)}</span><span class="grow"></span><span class="mono dim" style="font-size:11px">${s.ms != null ? fmtMs(s.ms) : ''}</span></summary>
      <dl class="kv" style="margin:10px 0 4px"><dt>Result</dt><dd>${esc(s.result || '—')}</dd><dt>Rule</dt><dd class="mono">${esc(s.rule || '—')}</dd><dt>Recorded at</dt><dd class="mono">${s.at ? new Date(s.at).toISOString() : '—'}</dd></dl>${s.evidence ? `<pre class="code">${esc(s.evidence)}</pre>` : '<div class="dim" style="font-size:12px">No structured evidence recorded for this check.</div>'}</details>`).join('')}</div>` : '';
    return `<div class="stack">
      <div class="dc ${cls}"><div class="top"><div class="ic">${ic(cls === 'allow' ? 'shield-check' : cls === 'warn' ? 'shield-alert' : 'shield-x')}</div><div class="grow" style="min-width:0"><div class="vd">${d.verdict}</div><div class="why">${esc(d.verdict === 'ALLOWED' ? `All ${x.ran} executed checks passed. ${x.skipped.length} did not apply and were not executed.` : d.reason || '')}</div></div><span class="badge mute">${fmtMs(d.latency)}</span></div>
      <div class="body"><dl class="kv">
        <dt>Request ID</dt><dd class="mono">${esc(d.requestId)}</dd>
        <dt>Original task</dt><dd>${esc(d.taskText || '—')}${d.implicitTask ? ' <span class="dim">(direct call, no user task)</span>' : ''}</dd>
        <dt>Requested tool</dt><dd class="mono">${esc(d.tool)} on ${esc(d.server)}</dd>
        <dt>Arguments</dt><dd class="mono" style="font-size:12px">${esc(d.args)}</dd>
        <dt>Destination</dt><dd class="mono">${esc(d.destination || '—')}</dd>
        <dt>Checks performed</dt><dd>${x.ran} of ${d.stages.length} executed: ${x.passed.length} passed, ${x.flagged.length} flagged, ${x.blocked.length} blocked. ${x.skipped.length} not executed.</dd>
        <dt>Applicable policy</dt><dd class="mono">${esc(d.rule || 'all checks passed')} <span class="dim">(policy v${d.policyVersion})</span></dd>
        <dt>Decision</dt><dd>${esc(d.decision)} → ${vbadge(d.verdict)}</dd>
        <dt>Tool executed</dt><dd>${{ yes: 'Yes', partial: 'Partially (an earlier redirect hop was fetched)', no: 'No' }[d.toolExecuted]}</dd>
        <dt>Response inspection</dt><dd>${d.responseOutcome ? esc(d.responseOutcome) + (d.findings ? `: injection score ${d.findings.injectionScore}, ${d.findings.steering} tool reference(s), ${d.findings.secrets} secret(s), ${d.findings.pii} PII item(s)` : '') : 'Not performed: no response was received'}</dd>
        <dt>Processing time</dt><dd>${fmtMs(d.latency)} engine time</dd>
        <dt>Audit record</dt><dd class="mono">${d.auditSeq ? `#${d.auditSeq} <span class="dim">${esc((d.auditHash || '').slice(0, 24))}…</span> <button class="btn sm" id="dverify" style="margin-left:6px">Verify record</button> <span id="dverr"></span>` : '—'}</dd>
      </dl></div></div>
      ${d.decision === 'DENY' ? `<div class="panel"><div class="ph"><h3>Why this request was denied</h3></div><div class="pb"><dl class="kv">
        <dt>Stage that failed</dt><dd>${x.failedStage ? `${x.failedStage.n}. ${esc(x.failedStage.name)}` : '—'}</dd>
        <dt>Rule triggered</dt><dd class="mono">${esc(x.rule || '—')}</dd>
        <dt>Why</dt><dd>${esc(x.why || '—')}</dd>
        <dt>Connection attempted</dt><dd>${esc(x.connection)}</dd>
        <dt>Protected operation executed</dt><dd>${esc(x.executed)}</dd>
      </dl></div></div>` : ''}
      <div class="panel"><div class="ph"><h3>Evidence by check</h3><span class="sub">expand any check to see what was recorded</span></div><div class="pb" style="padding-top:2px">
        ${group('Passed', x.passed)}${group('Flagged', x.flagged, 'executed and raised a finding')}${group('Blocked', x.blocked)}${group('Not executed', x.skipped, 'these checks did not run and are not counted as passed')}
      </div></div>
      <div class="row wrap">${d.intentId ? `<a class="btn sm" href="#/intent/${d.intentId}">${ic('crosshair')}Intent evaluation</a>` : ''}${d.taskId ? `<a class="btn sm" href="#/chains/${d.taskId}">${ic('waypoints')}Attack chain</a>` : ''}${d.auditSeq ? `<button class="btn sm" id="daudit">${ic('scroll-text')}Open audit record</button>` : ''}${Warden.runs.has(d.requestId) ? `<button class="btn sm" id="dpipe">${ic('git-commit-vertical')}Replay in pipeline view</button>` : ''}</div>
    </div>`;
  },
  mount() {
    this.arg = null;
    const setF = (k, v) => { this.f = { ...(this.f || {}), [k]: v }; rerender(this); };
    $('#dv').onchange = e => setF('v', e.target.value); $('#dt2').onchange = e => setF('tool', e.target.value);
    $('#dq').oninput = e => { clearTimeout(this.t); this.t = setTimeout(() => { setF('q', e.target.value); const i = $('#dq'); i.focus(); i.setSelectionRange(i.value.length, i.value.length); }, 250); };
    $$('[data-d]').forEach(tr => tr.onclick = () => { UI.decSel = tr.dataset.d; $$('[data-d]').forEach(x => x.classList.toggle('sel', x === tr)); $('#dexp').innerHTML = this.detail(Decisions.get(UI.decSel)); this.bindD(); icons(); });
    this.bindD();
  },
  bindD() {
    const d = Decisions.get(UI.decSel); if (!d) return;
    const v = $('#dverify'); if (v) v.onclick = async () => {
      v.disabled = true; const res = await Audit.verify(); const e = Audit.list.find(a => a.seq === d.auditSeq);
      const ok = e && e.requestId === d.requestId && e.hash === d.auditHash && (res.ok || res.seq > d.auditSeq);
      $('#dverr').innerHTML = ok ? '<span class="badge allow">record intact and chained</span>' : `<span class="badge deny">${!e ? 'record missing' : e.hash !== d.auditHash ? 'hash differs from decision record' : 'chain broken at or before #' + res.seq}</span>`; v.disabled = false;
    };
    const a = $('#daudit'); if (a) a.onclick = () => { UI.auditOpen = d.auditSeq; location.hash = '#/audit'; };
    const p = $('#dpipe'); if (p) p.onclick = () => { UI.focusRun = d.requestId; UI.selStage = d.blockingStage; PAGES.pipeline.follow = false; location.hash = '#/pipeline'; };
  },
  on(e) { if (e.type === 'decision' && UI.page === this && !this.f?.q) rerender(this); }
};

// ---------------- Attack Chain Explorer ----------------
PAGES.chains = {
  title: 'Attack Chain Explorer', sub: 'Related events correlated into one incident, from recorded request, task and provenance IDs',
  render() {
    const all = Chains.list(); const f = this.f || { inc: true };
    const list = all.filter(c => (!f.inc || c.incident) && (f.impl || !c.implicit || c.calls > 1) && (!f.q || (c.text || '').toLowerCase().includes(f.q.toLowerCase())));
    if (this.arg) { UI.chainSel = this.arg; this.arg = null; }
    if (!UI.chainSel || !all.some(c => c.taskId === UI.chainSel)) UI.chainSel = list[0]?.taskId;
    const ch = UI.chainSel ? Chains.forTask(UI.chainSel) : null;
    return `<div class="split" style="grid-template-columns:minmax(0,.62fr) minmax(0,1.38fr)">
      <div class="stack">
        <input class="input" id="cq" placeholder="Search tasks" value="${esc(f.q || '')}">
        <div class="row wrap" style="font-size:12.5px;color:var(--muted)"><label class="row"><input type="checkbox" id="cinc" ${f.inc ? 'checked' : ''}> Incidents only</label><label class="row"><input type="checkbox" id="cimp" ${f.impl ? 'checked' : ''}> Include single direct calls</label></div>
        <div class="panel flush"><div class="pb" style="max-height:calc(100vh - 250px);overflow:auto">${list.length ? `<table class="t"><tbody>${list.slice(0, 120).map(c => `<tr class="click ${UI.chainSel === c.taskId ? 'sel' : ''}" data-c="${c.taskId}"><td><span class="dot ${c.worst === 'bad' ? 'r' : c.worst === 'warn' ? 'a' : 'g'}"></span></td><td style="font-size:12.5px">${esc(c.text)}<div class="dim mono" style="font-size:11px">${c.calls} call${c.calls > 1 ? 's' : ''}, ${fmtTime(c.ts)}</div></td></tr>`).join('')}</tbody></table>` : `<div class="pb"><div class="empty"><b>No chains match</b>Run "Page steers the agent" in the playground to create a multi-step incident.</div></div>`}</div></div>
      </div>
      <div class="stack" id="chainv">${ch ? this.view(ch) : '<div class="empty"><b>Select a task</b>Its calls, findings and decisions will be drawn as a chain.</div>'}</div></div>`;
  },
  view(ch) {
    const ebd = ch.executedBeforeDetection;
    return `<div class="panel"><div class="pb"><div class="row wrap between"><div><div style="font-weight:600;font-size:15px">${esc(ch.task?.text || 'Task')}</div><div class="dim mono" style="font-size:11.5px">${esc(UI.chainSel)}</div></div>${ch.incident ? '<span class="badge deny">INCIDENT</span>' : '<span class="badge allow">NO INCIDENT</span>'}</div>
      <div class="metrics" style="margin-top:12px"><div><div class="v">${ch.decisions.length}</div><div class="l">Tool calls</div></div><div><div class="v r">${ch.blocked.length}</div><div class="l">Blocked operations</div></div><div><div class="v ${ebd.length ? 'a' : ''}">${ebd.length}</div><div class="l">Executed before first detection</div></div><div><div class="v">${ch.edges.filter(e => e.basis === 'inferred').length}</div><div class="l">Inferred links</div></div></div>
      ${ebd.length ? `<div class="banner warn" style="margin-top:12px">${ic('history')}<div><b>Executed before detection:</b> ${ebd.map(d => `${esc(d.tool)} ${esc(d.destination || '')} (${d.connections} connection${d.connections === 1 ? '' : 's'})`).join('; ')}. Everything after the first finding is shown in the graph with its own decision.</div></div>` : ''}
    </div></div>
    <div class="panel"><div class="ph"><h3>Attack chain</h3><span class="grow"></span><div class="legend"><span><i style="background:var(--line3)"></i>Confirmed link (IDs recorded by MCPWarden)</span><span><i style="background:transparent;border:1px dashed var(--amber)"></i>Inferred link</span><span><i style="background:var(--red)"></i>Blocked</span></div></div><div class="pb scroll-x">${this.graph(ch)}</div></div>
    <div class="panel"><div class="ph"><h3>Evidence</h3><span class="sub">click a node</span></div><div class="pb" id="cev">${this.evidence(ch, this.node)}</div></div>`;
  },
  graph(ch) {
    const W = 220, H = 60, GX = 44, GY = 30, PAD = 16;
    const cols = Math.max(1, ...ch.nodes.filter(n => n.type !== 'task').map(n => n.col + 1));
    const width = Math.max(W + PAD * 2, cols * (W + GX) - GX + PAD * 2);
    const rows = Math.max(...ch.nodes.map(n => n.row)) + 1;
    const height = rows * (H + GY) + PAD * 2 - GY;
    const pos = {}; for (const n of ch.nodes) pos[n.id] = n.type === 'task' ? { x: (width - W) / 2, y: PAD } : { x: PAD + n.col * (W + GX), y: PAD + n.row * (H + GY) };
    const col = s => ({ ok: 'var(--green)', warn: 'var(--amber)', bad: 'var(--red)', info: 'var(--cyan)' }[s]);
    const edges = ch.edges.map(e => { const a = pos[e.from], b = pos[e.to]; if (!a || !b) return ''; const x1 = a.x + W / 2, y1 = a.y + H, x2 = b.x + W / 2, y2 = b.y; const tgt = ch.nodes.find(n => n.id === e.to); const stroke = e.basis === 'inferred' ? 'var(--amber)' : tgt?.status === 'bad' ? 'var(--red)' : 'var(--line3)';
      return `<path d="M${x1} ${y1} C${x1} ${y1 + GY * .8}, ${x2} ${y2 - GY * .8}, ${x2} ${y2 - 4}" fill="none" stroke="${stroke}" stroke-width="1.5" ${e.basis === 'inferred' ? 'stroke-dasharray="5 4"' : ''} marker-end="url(#cah)"><title>${esc(e.basis + ': ' + e.why)}</title></path>`; }).join('');
    const nodes = ch.nodes.map(n => { const p = pos[n.id]; const c = col(n.status); const sel = this.node === n.id;
      return `<g class="gnode" data-node="${esc(n.id)}" tabindex="0" style="cursor:pointer"><rect x="${p.x}" y="${p.y}" width="${W}" height="${H}" rx="9" fill="${n.status === 'bad' ? 'var(--red-a)' : 'var(--panel2)'}" stroke="${sel ? 'var(--cyan)' : c}" stroke-width="${sel ? 2 : n.status === 'bad' ? 1.6 : 1}"/>
        <rect x="${p.x}" y="${p.y + 10}" width="3" height="${H - 20}" rx="1.5" fill="${c}"/>
        <text x="${p.x + 14}" y="${p.y + 22}" fill="var(--text)" font-size="12.5" font-weight="600">${esc(n.title.slice(0, 30))}</text>
        <text x="${p.x + 14}" y="${p.y + 40}" fill="var(--muted)" font-size="11" font-family="var(--mono)">${esc((n.sub || '').slice(0, 32))}</text>
        ${n.ts ? `<text x="${p.x + W - 8}" y="${p.y + 22}" fill="var(--dim)" font-size="10" text-anchor="end" font-family="var(--mono)">${fmtTime(n.ts)}</text>` : ''}
        ${n.beforeDetection ? `<text x="${p.x + W - 8}" y="${p.y + 52}" fill="var(--amber)" font-size="10" text-anchor="end">executed</text>` : ''}</g>`; }).join('');
    return `<svg class="chart" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}" style="display:block;max-width:none"><defs><marker id="cah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0L10 5L0 10z" fill="var(--muted)"/></marker></defs>${edges}${nodes}</svg>`;
  },
  evidence(ch, id) {
    const n = ch.nodes.find(x => x.id === id);
    if (!n) return '<div class="dim" style="font-size:12.5px">Select a node to see the recorded evidence behind it.</div>';
    const inEdges = ch.edges.filter(e => e.to === n.id);
    return `<div class="stack"><div class="row"><b>${esc(n.title)}</b><span class="badge ${n.status === 'bad' ? 'deny' : n.status === 'warn' ? 'warn' : n.status === 'ok' ? 'allow' : 'info'}">${esc(n.type)}</span>${n.ts ? `<span class="mono dim" style="font-size:11.5px">${new Date(n.ts).toISOString()}</span>` : ''}</div>
      ${inEdges.map(e => `<div style="font-size:12.5px"><span class="badge ${e.basis === 'confirmed' ? 'allow' : 'warn'}">${e.basis}</span> <span class="muted">${esc(e.why)}</span></div>`).join('')}
      ${n.evidence ? `<pre class="code">${esc(safeText(JSON.stringify(n.evidence, null, 2)))}</pre>` : ''}
      ${n.ref ? `<div class="row"><a class="btn sm" href="#/decisions/${n.ref}">${ic('file-search')}Explain this decision</a></div>` : ''}</div>`;
  },
  mount() {
    const setF = (k, v) => { this.f = { ...(this.f || { inc: true }), [k]: v }; rerender(this); };
    $('#cinc').onchange = e => setF('inc', e.target.checked); $('#cimp').onchange = e => setF('impl', e.target.checked);
    $('#cq').oninput = e => { clearTimeout(this.t); this.t = setTimeout(() => { setF('q', e.target.value); const i = $('#cq'); i.focus(); i.setSelectionRange(i.value.length, i.value.length); }, 250); };
    $$('[data-c]').forEach(tr => tr.onclick = () => { UI.chainSel = tr.dataset.c; this.node = null; rerender(this); });
    this.bindG();
  },
  bindG() {
    $$('.gnode').forEach(g => { const h = () => { this.node = g.dataset.node; const ch = Chains.forTask(UI.chainSel); $('#chainv').innerHTML = this.view(ch); this.bindG(); icons(); }; g.onclick = h; g.onkeydown = e => { if (e.key === 'Enter') h(); }; });
  },
  on(e) { if (e.type === 'decision' && UI.page === this) { clearTimeout(this.rt); this.rt = setTimeout(() => rerender(this), 200); } }
};

// ---------------- Intent Firewall ----------------
PAGES.intent = {
  title: 'Intent Firewall', sub: 'Checks every tool action against the task the user actually asked for',
  render() {
    const I = Warden.policy.intent; const f = this.f || {};
    const list = Intent.list.filter(ev => !f.d || ev.decision === f.d || (f.d === 'followup' && ev.isFollowup));
    if (this.arg) { UI.intSel = this.arg; this.arg = null; }
    if (!UI.intSel || !Intent.list.some(x => x.id === UI.intSel)) UI.intSel = list[0]?.id;
    const ev = Intent.list.find(x => x.id === UI.intSel);
    const sel = (k, opts) => `<select class="input" data-ik="${k}">${opts.map(o => `<option ${I[k] === o ? 'selected' : ''}>${o}</option>`).join('')}</select>`;
    const counts = { allow: 0, review: 0, block: 0 }; Intent.list.forEach(x => counts[x.decision]++);
    return `<div class="stack">
    <div class="split" style="grid-template-columns:minmax(0,1.2fr) minmax(0,.8fr)">
      <div class="panel"><div class="ph"><h3>How it decides</h3></div><div class="pb" style="font-size:13px;line-height:1.6">
        <p style="margin-top:0">Each task gets a profile: its category, the tools it needs, and the destinations the user named. MCPWarden records every URL it returns to the agent, so it knows where a later destination came from without trusting the agent's word. Hard rules then apply policy; an advisory relevance classifier may raise a review but can never relax a rule.</p>
        <p style="margin-bottom:0">This stage runs after the mandatory URL, DNS and SSRF checks, so a follow-up to an internal address is still stopped by those checks first. The intent firewall catches what they cannot: a public destination the user never asked for.</p>
        <div class="row wrap" style="margin-top:14px"><button class="btn primary" id="idemo">${ic('play')}Run the steering demo</button><span class="dim" style="font-size:12px" id="idemomsg">Summarizes a page that tells the agent to visit two other URLs, with a manipulable agent.</span></div></div></div>
      <div class="panel"><div class="ph"><h3>Intent policy</h3><span class="sub">v${Warden.policy.version}</span></div><div class="pb stack">
        <div class="grid g2"><div><label class="f">Enforcement</label><select class="input" id="ien"><option value="true" ${I.enabled ? 'selected' : ''}>Enabled</option><option value="false" ${!I.enabled ? 'selected' : ''}>Disabled (record only)</option></select></div>
        <div><label class="f">Follow-ups suggested by page content</label>${sel('contentDerivedFollowups', ['block', 'review', 'allow'])}</div>
        <div><label class="f">Destinations with unknown origin</label>${sel('unknownProvenance', ['review', 'block', 'allow'])}</div>
        <div><label class="f">Tools outside the task's scope</label>${sel('outOfScopeTools', ['block', 'review', 'allow'])}</div>
        <div><label class="f">Exfiltration-shaped URLs</label>${sel('exfiltrationShape', ['block', 'review', 'allow'])}</div>
        <div><label class="f">Max tool calls per task</label><input class="input" type="number" min="1" max="20" id="imax" value="${I.maxCallsPerTask}"></div>
        <div><label class="f">Relevance classifier</label>${sel('classifier', ['advisory', 'off'])}</div></div>
        <div class="row"><button class="btn" id="isave">${ic('save')}Save intent policy</button><span id="imsg" style="font-size:12.5px"></span></div></div></div>
    </div>
    <div class="metrics"><div><div class="v">${Intent.list.length}</div><div class="l">Evaluations recorded</div></div><div><div class="v g">${counts.allow}</div><div class="l">Consistent with task</div></div><div><div class="v a">${counts.review}</div><div class="l">Held for review</div></div><div><div class="v r">${counts.block}</div><div class="l">Blocked</div></div><div><div class="v">${Intent.list.filter(x => x.isFollowup).length}</div><div class="l">Follow-up actions evaluated</div></div></div>
    <div class="split" style="grid-template-columns:minmax(0,.8fr) minmax(0,1.2fr)">
      <div class="stack"><div class="row wrap">${[['', 'All'], ['block', 'Blocked'], ['review', 'Review'], ['allow', 'Allowed'], ['followup', 'Follow-ups']].map(([k, l]) => `<button class="chip" data-if="${k}" style="${(f.d || '') === k ? 'border-color:var(--cyan);background:var(--cyan-a)' : ''}">${l}</button>`).join('')}</div>
      <div class="panel flush"><div class="pb" style="max-height:560px;overflow:auto">${list.length ? `<table class="t"><tbody>${list.slice(0, 150).map(x => `<tr class="click ${UI.intSel === x.id ? 'sel' : ''}" data-i="${x.id}"><td><span class="badge ${x.decision === 'allow' ? 'allow' : x.decision === 'review' ? 'warn' : 'deny'}">${x.decision}</span></td><td style="font-size:12px"><div class="mono">${esc(x.tool)} ${esc(x.destination ? hostOf(x.destination) || '' : '')}</div><div class="dim" style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(x.taskText)}</div></td><td class="dim" style="font-size:11.5px">${x.isFollowup ? 'follow-up' : 'first call'}</td></tr>`).join('')}</tbody></table>` : '<div class="pb"><div class="empty"><b>No evaluations yet</b>Every request that reaches the intent stage is evaluated here. Run the steering demo to see a block.</div></div>'}</div></div></div>
      <div id="idet">${this.detail(ev)}</div></div></div>`;
  },
  detail(ev) {
    if (!ev) return '<div class="empty"><b>Select an evaluation</b></div>';
    const I = Warden.policy.intent;
    return `<div class="stack">
      <div class="dc ${ev.decision === 'allow' ? 'allow' : ev.decision === 'review' ? 'warn' : 'deny'}"><div class="top"><div class="ic">${ic(ev.decision === 'allow' ? 'shield-check' : ev.decision === 'review' ? 'user-check' : 'shield-x')}</div><div class="grow"><div class="vd">${ev.decision.toUpperCase()}${ev.reviewOutcome ? ` <span style="font-size:14px">(${ev.reviewOutcome})</span>` : ''}</div><div class="why">${esc(ev.explanation)}</div></div>${ev.finalVerdict ? vbadge(ev.finalVerdict) : ''}</div></div>
      <div class="grid g2">
        <div class="panel"><div class="ph"><h3>Original user intent</h3></div><div class="pb"><dl class="kv"><dt>Task</dt><dd>${esc(ev.taskText)}</dd><dt>Category</dt><dd>${esc(ev.profile.category)}</dd><dt>Tools it needs</dt><dd class="mono">${esc(ev.profile.permittedTools.join(', '))}</dd><dt>Named destinations</dt><dd class="mono">${esc(ev.profile.hosts.join(', ') || 'none')}</dd></dl></div></div>
        <div class="panel"><div class="ph"><h3>Requested tool action</h3></div><div class="pb"><dl class="kv"><dt>Tool</dt><dd class="mono">${esc(ev.tool)}</dd><dt>Destination</dt><dd class="mono">${esc(ev.destination || 'none (search provider)')}</dd><dt>Position</dt><dd>${ev.isFollowup ? `Follow-up after ${ev.priorCalls} earlier call(s)` : 'First call of the task'}</dd><dt>Origin</dt><dd>${esc(ev.provenance.label)}${ev.provenance.excerpt ? `<div class="mono dim" style="font-size:11.5px;margin-top:4px">“${esc(ev.provenance.excerpt)}”</div>` : ''}</dd></dl></div></div>
      </div>
      <div class="panel flush"><div class="ph"><h3>Risk signals</h3><span class="sub">rules are deterministic; the advisory classifier can only escalate</span></div><div class="pb scroll-x"><table class="t"><thead><tr><th>Type</th><th>Signal</th><th>Policy</th><th>Action</th></tr></thead><tbody>${ev.signals.map(s => `<tr><td><span class="badge ${s.kind === 'rule' ? 'purple' : s.kind === 'advisory' ? 'info' : 'mute'}">${s.kind}</span></td><td style="font-size:12.5px">${esc(s.label)}${s.evidence ? `<div class="mono dim" style="font-size:11px">${esc(safeText(JSON.stringify(s.evidence)).slice(0, 180))}</div>` : ''}</td><td class="mono dim" style="font-size:11.5px">${esc(s.policy || '—')}</td><td><span class="badge ${s.action === 'block' ? 'deny' : s.action === 'review' ? 'warn' : 'allow'}">${s.action}</span></td></tr>`).join('') || '<tr><td colspan="4" class="dim">No signals</td></tr>'}</tbody></table></div></div>
      <div class="panel"><div class="ph"><h3>Relevant policy</h3></div><div class="pb"><dl class="kv"><dt>Decisive rule</dt><dd class="mono">${esc(ev.rule)}</dd><dt>Evaluated under</dt><dd>policy v${ev.policyVersion}${ev.policyVersion !== Warden.policy.version ? ` <span class="dim">(current is v${Warden.policy.version})</span>` : ''}${ev.enforced ? '' : ', enforcement disabled'}</dd><dt>Classifier relevance</dt><dd>${ev.relevance == null ? 'not computed' : ev.relevance}</dd><dt>Current settings</dt><dd class="mono" style="font-size:11.5px">${esc(JSON.stringify(I))}</dd></dl>
        <div class="row" style="margin-top:12px"><a class="btn sm" href="#/decisions/${ev.requestId}">${ic('file-search')}Explain full decision</a><a class="btn sm ghost" href="#/chains/${ev.taskId}">${ic('waypoints')}Attack chain</a></div></div></div>
    </div>`;
  },
  mount() {
    $('#idemo').onclick = async () => {
      const b = $('#idemo'); b.disabled = true; $('#idemomsg').textContent = 'Running…';
      const r = await Agent.runTask('Summarize https://blog.secure-ai.test/research-roundup', { mode: 'manipulable', source: 'playground' });
      const last = Intent.list.find(x => x.taskId === r.task?.id && x.isFollowup) || Intent.list[0];
      UI.intSel = last?.id; rerender(this); toast(`Demo finished: ${r.runs.map(x => x.verdict).join(', ')}`);
    };
    $('#isave').onclick = async () => {
      const p = JSON.parse(JSON.stringify(Warden.policy));
      $$('[data-ik]').forEach(s => p.intent[s.dataset.ik] = s.value); p.intent.enabled = $('#ien').value === 'true'; p.intent.maxCallsPerTask = +$('#imax').value;
      const r = await Warden.savePolicy(p, 'Intent policy edited in Intent Firewall');
      $('#imsg').innerHTML = r.ok ? `<span class="g">Saved as v${r.version}. Applies to the next call.</span>` : `<span class="r">${esc(r.errs.join(' '))}</span>`;
      PAGES.policy.draft = null;
    };
    $$('[data-if]').forEach(b => b.onclick = () => { this.f = { d: b.dataset.if }; rerender(this); });
    $$('[data-i]').forEach(tr => tr.onclick = () => { UI.intSel = tr.dataset.i; $$('[data-i]').forEach(x => x.classList.toggle('sel', x === tr)); $('#idet').innerHTML = this.detail(Intent.list.find(x => x.id === UI.intSel)); icons(); });
  },
  on(e) { if (e.type === 'intent' && UI.page === this) { clearTimeout(this.rt); this.rt = setTimeout(() => rerender(this), 150); } }
};

// ---------------- Tool Integrity Sentinel ----------------
function lcsDiff(a, b) {
  const n = a.length, m = b.length; const dp = Array.from({ length: n + 1 }, () => new Uint16Array(m + 1));
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
  const out = []; let i = 0, j = 0;
  while (i < n && j < m) { if (a[i] === b[j]) { out.push(['=', a[i]]); i++; j++; } else if (dp[i + 1][j] >= dp[i][j + 1]) out.push(['-', a[i++]]); else out.push(['+', b[j++]]); }
  while (i < n) out.push(['-', a[i++]]); while (j < m) out.push(['+', b[j++]]);
  return out;
}
function sideBySide(beforeTxt, afterTxt, splitter) {
  const A = splitter(beforeTxt || ''), B = splitter(afterTxt || ''); const d = lcsDiff(A, B);
  const L = d.filter(x => x[0] !== '+').map(([o, t]) => o === '-' ? `<del>${esc(t)}</del>` : esc(t)).join(splitter === words ? '' : '\n');
  const R = d.filter(x => x[0] !== '-').map(([o, t]) => o === '+' ? `<ins>${esc(t)}</ins>` : esc(t)).join(splitter === words ? '' : '\n');
  return `<div class="grid g2"><div><label class="f">Approved baseline</label><pre class="code diff">${L || '<span class="dim">(none: new tool)</span>'}</pre></div><div><label class="f">Live definition</label><pre class="code diff">${R || '<span class="dim">(removed)</span>'}</pre></div></div>`;
}
const words = s => s.split(/(\s+)/).filter(x => x !== '');
const lines = s => s.split('\n');
PAGES.sentinel = {
  title: 'Tool Integrity Sentinel', sub: 'Baselines every tool definition and holds changes until an operator reviews them',
  render() {
    const inv = []; Registry.entries.forEach(e => Object.entries(e.tools || {}).forEach(([n, t]) => inv.push({ e, n, t })));
    const by = s => inv.filter(x => x.t.status === s).length;
    const pending = Sentinel.pending(); const st = Sentinel.mirror() || {};
    const hf = this.hf || '';
    const hist = Sentinel.changes.filter(c => !hf || c.status === hf || c.classification === hf).slice(0, 60);
    const FIX = [['cosmetic', 'Reword description (punctuation only)'], ['optionalParam', 'Add optional timeout parameter'], ['confidential', 'Description asks for confidential data'], ['rugpull', 'Ask for cookies in a new headers field'], ['addTool', 'Add a new upload_page tool'], ['removeExtract', 'Remove extract_web_content']];
    return `<div class="stack">
    <div class="row wrap"><button class="btn primary" id="sscan">${ic('scan-search')}Scan all servers now</button><span class="muted" style="font-size:12.5px">Discovery also runs on every call, so a change is caught even between scans.</span></div>
    <div class="metrics"><div><div class="v g">${by('trusted')}</div><div class="l">Trusted tools</div></div><div><div class="v a">${by('pending-review')}</div><div class="l">Pending review</div></div><div><div class="v r">${by('quarantined')}</div><div class="l">Quarantined</div></div><div><div class="v r">${by('rejected')}</div><div class="l">Rejected</div></div><div><div class="v">${by('removed')}</div><div class="l">Removed upstream</div></div><div><div class="v">${Sentinel.changes.length}</div><div class="l">Changes recorded</div></div></div>
    <div class="banner">${ic('info')}<div>A tool is usable only in the <b>trusted</b> state with a live fingerprint equal to its approved baseline. New tools on an already trusted server start in <b>pending review</b>. Changes are classified as cosmetic, benign or suspicious; not every change is malicious, but every change waits for a decision unless policy auto-approves cosmetic edits (${Warden.policy.integrity.autoApproveCosmetic ? 'on' : 'off'}). Definitions with poisoning indicators are quarantined and cannot be approved.</div></div>
    <div class="panel"><div class="ph"><h3>Simulate an upstream change</h3><span class="sub">test fixture on web-tools-mirror; affects only this page's mock server</span></div><div class="pb"><div class="row wrap" style="gap:8px">${FIX.map(([k, l]) => `<label class="chip" style="${st[k] ? 'border-color:var(--amber);background:var(--amber-a)' : ''}"><input type="checkbox" data-fx="${k}" ${st[k] ? 'checked' : ''}> ${l}</label>`).join('')}<button class="btn sm" id="sreset">${ic('rotate-ccw')}Restore original definitions</button></div></div></div>
    <div class="panel"><div class="ph"><h3>Review queue</h3><span class="sub">${pending.length} pending</span></div><div class="pb">${pending.length ? pending.map(c => this.changeCard(c, true)).join('<div class="hr"></div>') : '<div class="dim" style="font-size:13px">Nothing is waiting. Toggle a simulated change above to see the sentinel catch it.</div>'}</div></div>
    <div class="panel flush"><div class="ph"><h3>Tool inventory</h3></div><div class="pb scroll-x"><table class="t"><thead><tr><th>Server</th><th>Tool</th><th>Trust state</th><th>Baseline fingerprint</th><th>Live (pending)</th><th>Origin</th></tr></thead><tbody>${inv.map(({ e, n, t }) => `<tr><td class="mono">${esc(e.id)}</td><td class="mono">${esc(n)}</td><td>${trustBadge(t.status)}</td><td class="mono dim" style="font-size:11.5px">${t.fp ? t.fp.slice(0, 20) + '…' : 'none'}</td><td class="mono" style="font-size:11.5px">${t.pendingFp ? `<span class="a">${t.pendingFp.slice(0, 20)}…</span>` : '<span class="dim">matches</span>'}</td><td class="dim" style="font-size:12px">${esc(t.origin || '')}</td></tr>`).join('')}</tbody></table></div></div>
    <div class="panel"><div class="ph"><h3>Change history</h3><span class="grow"></span><select class="input" id="shf" style="max-width:170px"><option value="">All changes</option>${['pending', 'approved', 'rejected', 'reverted', 'auto-approved', 'suspicious', 'benign', 'cosmetic', 'new-tool', 'removed'].map(x => `<option ${hf === x ? 'selected' : ''}>${x}</option>`).join('')}</select></div><div class="pb">${hist.length ? hist.map(c => `<details class="ev"><summary><span class="mono dim" style="font-size:11px;width:72px;display:inline-block">${fmtTime(c.ts)}</span><span class="badge ${c.classification === 'suspicious' ? 'deny' : c.classification === 'benign' || c.classification === 'new-tool' ? 'warn' : 'mute'}">${esc(c.classification)}</span><span class="mono">${esc(c.server)}/${esc(c.tool)}</span><span class="dim">${esc(c.kind)}</span><span class="grow"></span><span class="badge mute">${esc(c.status)}</span></summary>${this.changeCard(c, false)}</details>`).join('') : '<div class="dim" style="font-size:13px">No changes recorded.</div>'}</div></div>
    </div>`;
  },
  changeCard(c, actions) {
    const e = Registry.get(c.server); const t = e?.tools[c.tool];
    const canApprove = actions && c.kind !== 'removed' && !(t?.pending?.findings?.length);
    const desc = sideBySide(c.before?.description, c.after?.description, words);
    const schema = sideBySide(c.before ? JSON.stringify(c.before.inputSchema, null, 2) : '', c.after ? JSON.stringify(c.after.inputSchema, null, 2) : '', lines);
    return `<div class="stack" style="padding:6px 0">
      <div class="row wrap"><b class="mono">${esc(c.server)}/${esc(c.tool)}</b><span class="badge ${c.classification === 'suspicious' ? 'deny' : 'warn'}">${esc(c.classification)}</span><span class="dim" style="font-size:12px">${esc(c.kind)}, ${esc(c.cause || '')}, ${fmtTime(c.ts)}</span></div>
      <ul style="margin:0;padding-left:18px;font-size:13px">${(c.reasons || []).map(r => `<li>${esc(r)}</li>`).join('')}</ul>
      <div><label class="f">Description</label>${desc}</div><div><label class="f">Input schema</label>${schema}</div>
      <div class="mono dim" style="font-size:11.5px">baseline ${esc(c.beforeFp || 'none')}<br>live&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;${esc(c.afterFp || 'none')}</div>
      ${actions ? `<div class="row wrap">${canApprove ? `<button class="btn sm ok" data-sa="${c.id}">${ic('check')}Approve as new baseline</button>` : c.kind === 'removed' ? '' : '<span class="badge deny">cannot be approved: poisoning indicators present</span>'}<button class="btn sm danger" data-sr="${c.id}">${ic('x')}Reject</button><span class="dim" style="font-size:12px">The tool stays blocked until a decision is made.</span></div>` : ''}
    </div>`;
  },
  mount() {
    $('#sscan').onclick = async () => { $('#sscan').disabled = true; await Sentinel.scanAll(); toast('Scan complete'); rerender(this); };
    $$('[data-fx]').forEach(cb => cb.onchange = async () => { await Sentinel.simulate(cb.dataset.fx, cb.checked); rerender(this); });
    $('#sreset').onclick = async () => { await Sentinel.simulate('reset'); toast('Mirror definitions restored'); rerender(this); };
    $$('[data-sa]').forEach(b => b.onclick = async () => { if (!confirm('Approve this definition as the new trusted baseline?')) return; const r = await Sentinel.approve(b.dataset.sa); toast(r.ok ? 'Approved' : r.msg); rerender(this); });
    $$('[data-sr]').forEach(b => b.onclick = async () => { const r = await Sentinel.reject(b.dataset.sr); toast(r.ok ? 'Rejected' : r.msg); rerender(this); });
    $('#shf').onchange = e => { this.hf = e.target.value; rerender(this); };
  },
  on(e) { if ((e.type === 'integrity' || e.type === 'registry') && UI.page === this) { clearTimeout(this.rt); this.rt = setTimeout(() => rerender(this), 120); } }
};
