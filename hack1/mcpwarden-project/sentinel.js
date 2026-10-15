// ---------------- Tool Integrity Sentinel ----------------
// Baselines every tool definition per server, diffs each discovery against the baseline,
// classifies the change, and holds changed or new tools out of use until an operator decides.
const SENSITIVE_TERMS = /\b(confidential|credentials?|api keys?|passwords?|secrets?|tokens?|cookies?|ssh|private keys?|internal urls?|environment variables?|session)\b/gi;
const SENSITIVE_PROP = /header|cookie|token|secret|cred|auth|context|notes|session|password|key/i;
const TRUST_LABEL = { trusted: 'Trusted', 'pending-review': 'Pending review', quarantined: 'Quarantined', rejected: 'Rejected', removed: 'Removed' };

const Sentinel = {
  changes: Store.get('integrity', []),
  save() { this.changes = this.changes.slice(0, 300); Store.set('integrity', this.changes); Bus.emit({ type: 'integrity' }); },
  async fp(t) { return sha256(canon({ name: t.name, description: t.description, inputSchema: t.inputSchema })); },
  norm: d => String(d || '').toLowerCase().replace(/[^a-z0-9]/g, ''),
  diff(before, after) {
    const bp = before?.inputSchema?.properties || {}, ap = after?.inputSchema?.properties || {};
    const addedProps = Object.keys(ap).filter(k => !(k in bp)), removedProps = Object.keys(bp).filter(k => !(k in ap));
    const changedProps = Object.keys(ap).filter(k => k in bp && canon(ap[k]) !== canon(bp[k]));
    const br = before?.inputSchema?.required || [], ar = after?.inputSchema?.required || [];
    const descChanged = (before?.description || '') !== (after?.description || '');
    const termsB = new Set(((before?.description || '').match(SENSITIVE_TERMS) || []).map(x => x.toLowerCase()));
    const addedSensitiveTerms = [...new Set(((after?.description || '').match(SENSITIVE_TERMS) || []).map(x => x.toLowerCase()))].filter(t => !termsB.has(t));
    const schemaOther = canon({ ...(before?.inputSchema || {}), properties: undefined, required: undefined }) !== canon({ ...(after?.inputSchema || {}), properties: undefined, required: undefined });
    return {
      descChanged, cosmeticOnly: descChanged && this.norm(before?.description) === this.norm(after?.description) && !addedProps.length && !removedProps.length && !changedProps.length && canon(br) === canon(ar) && !schemaOther,
      addedProps, removedProps, changedProps, requiredAdded: ar.filter(x => !br.includes(x)), requiredRemoved: br.filter(x => !ar.includes(x)),
      addedSensitiveTerms, suspiciousProps: addedProps.filter(p => SENSITIVE_PROP.test(p)), schemaOther
    };
  },
  classify(d, findings) {
    const reasons = [];
    if (findings.length) reasons.push('Poisoning indicators: ' + findings.map(f => f.label.toLowerCase()).join(', '));
    if (d.addedSensitiveTerms.length) reasons.push('Description newly mentions ' + d.addedSensitiveTerms.join(', '));
    if (d.suspiciousProps.length) reasons.push('New parameter(s) that could carry sensitive data: ' + d.suspiciousProps.join(', '));
    if (reasons.length) return { classification: 'suspicious', reasons };
    if (d.cosmeticOnly) return { classification: 'cosmetic', reasons: ['Only punctuation, spacing or capitalisation in the description changed'] };
    const r = [];
    if (d.descChanged) r.push('Description reworded');
    if (d.addedProps.length) r.push('Added parameter(s): ' + d.addedProps.join(', '));
    if (d.removedProps.length) r.push('Removed parameter(s): ' + d.removedProps.join(', '));
    if (d.changedProps.length) r.push('Changed parameter(s): ' + d.changedProps.join(', '));
    if (d.requiredAdded.length) r.push('Newly required: ' + d.requiredAdded.join(', '));
    if (d.schemaOther) r.push('Other schema keywords changed');
    return { classification: 'benign', reasons: r.length ? r : ['Definition changed'] };
  },
  async record(e, rec) {
    const c = { id: rid('chg'), ts: now(), server: e.id, status: 'pending', ...rec };
    this.changes.unshift(c);
    e.events.unshift({ ts: c.ts, msg: `${c.kind === 'added' ? 'New tool' : c.kind === 'removed' ? 'Tool removed' : 'Definition changed'}: ${c.tool} (${c.classification})` });
    this.save();
    await Audit.append({ kind: 'integrity', requestId: c.id, ts: c.ts, source: 'sentinel', server: e.id, tool: c.tool, action: 'integrity.' + c.kind, target: `${e.id}/${c.tool}`, verdict: c.status === 'auto-approved' ? 'ADMIN' : 'FLAGGED', decision: c.status, policy: c.status === 'auto-approved' ? 'policy.integrity.autoApproveCosmetic' : 'mandatory.integrity.trust', category: 'integrity', reason: `${c.kind} ${c.tool}: ${c.classification}. ${(c.reasons || []).join('; ')}`.slice(0, 240), beforeFp: c.beforeFp || null, afterFp: c.afterFp || null });
    return c;
  },
  close(id, status) { const c = this.changes.find(x => x.id === id); if (c && c.status === 'pending') { c.status = status; c.closedAt = now(); } },
  async reconcile(e, live, cause) {
    const first = !e.baselineAt; const P = Warden.policy || DEFAULT_POLICY;
    for (const t of live) {
      const fp = await this.fp(t); const findings = Inspector.poisonDescription(t.description);
      const def = { description: t.description, inputSchema: t.inputSchema };
      const cur = e.tools[t.name];
      if (!cur) {
        if (first && e.baselineApproved) {
          e.tools[t.name] = { fp, ...def, findings, status: findings.length ? 'quarantined' : 'trusted', baseStatus: findings.length ? 'quarantined' : 'trusted', origin: 'shipped baseline', registeredAt: now(), approvedAt: now() };
          if (findings.length) { const c = await this.record(e, { kind: 'baseline', tool: t.name, classification: 'suspicious', reasons: ['Quarantined at baseline: ' + findings.map(f => f.label.toLowerCase()).join(', ')], after: def, afterFp: fp, cause, status: 'quarantined' }); e.tools[t.name].changeId = c.id; }
          continue;
        }
        const cls = findings.length ? { classification: 'suspicious', reasons: ['Poisoning indicators: ' + findings.map(f => f.label.toLowerCase()).join(', ')] } : { classification: 'new-tool', reasons: [first ? 'Discovered on a server with no approved baseline' : 'Tool appeared after the server baseline was approved'] };
        const c = await this.record(e, { kind: 'added', tool: t.name, ...cls, after: def, afterFp: fp, cause });
        e.tools[t.name] = { fp: null, description: null, inputSchema: null, findings: [], status: findings.length ? 'quarantined' : 'pending-review', origin: 'discovered', registeredAt: now(), pendingFp: fp, pending: { ...def, findings }, changeId: c.id };
        continue;
      }
      if (cur.fp && cur.fp === fp) {
        if (cur.pendingFp || cur.status === 'removed' || cur.status === 'rejected') {
          if (cur.changeId) this.close(cur.changeId, 'reverted');
          if (cur.status !== cur.baseStatus) e.events.unshift({ ts: now(), msg: `${t.name} returned to its approved definition` });
          cur.status = cur.baseStatus || 'trusted'; delete cur.pendingFp; delete cur.pending; this.save();
        }
        continue;
      }
      if (cur.pendingFp === fp) continue; // already awaiting a decision on exactly this definition
      if (!cur.fp) { // a never-approved tool changed again
        if (cur.changeId) this.close(cur.changeId, 'superseded');
        const cls = findings.length ? { classification: 'suspicious', reasons: ['Poisoning indicators: ' + findings.map(f => f.label.toLowerCase()).join(', ')] } : { classification: 'new-tool', reasons: ['Unapproved tool changed before review'] };
        const c = await this.record(e, { kind: 'added', tool: t.name, ...cls, after: def, afterFp: fp, cause });
        Object.assign(cur, { pendingFp: fp, pending: { ...def, findings }, changeId: c.id, status: findings.length ? 'quarantined' : 'pending-review' });
        continue;
      }
      const d = this.diff(cur, def); const cls = this.classify(d, findings);
      if (cur.changeId && cur.pendingFp) this.close(cur.changeId, 'superseded');
      if (cls.classification === 'cosmetic' && P.integrity?.autoApproveCosmetic && !findings.length) {
        await this.record(e, { kind: 'modified', tool: t.name, ...cls, diff: d, before: { description: cur.description, inputSchema: cur.inputSchema }, after: def, beforeFp: cur.fp, afterFp: fp, cause, status: 'auto-approved' });
        Object.assign(cur, { fp, ...def, findings, status: 'trusted', baseStatus: 'trusted', approvedAt: now() }); delete cur.pendingFp; delete cur.pending;
        continue;
      }
      const c = await this.record(e, { kind: 'modified', tool: t.name, ...cls, diff: d, before: { description: cur.description, inputSchema: cur.inputSchema }, after: def, beforeFp: cur.fp, afterFp: fp, cause });
      Object.assign(cur, { pendingFp: fp, pending: { ...def, findings }, changeId: c.id, status: findings.length ? 'quarantined' : 'pending-review' });
    }
    for (const [n, cur] of Object.entries(e.tools)) {
      if (live.some(t => t.name === n) || cur.status === 'removed') continue;
      if (!cur.fp) { if (cur.changeId) this.close(cur.changeId, 'withdrawn'); delete e.tools[n]; e.events.unshift({ ts: now(), msg: `Unapproved tool ${n} disappeared before review` }); this.save(); continue; }
      if (cur.changeId && cur.pendingFp) this.close(cur.changeId, 'superseded');
      delete cur.pendingFp; delete cur.pending;
      const c = await this.record(e, { kind: 'removed', tool: n, classification: 'removed', reasons: ['Tool no longer listed by the server'], before: { description: cur.description, inputSchema: cur.inputSchema }, beforeFp: cur.fp, cause, status: 'logged' });
      cur.status = 'removed'; cur.changeId = c.id;
    }
    e.baselineAt = e.baselineAt || now();
  },
  find(id) { return this.changes.find(c => c.id === id); },
  async approve(id) {
    const c = this.find(id); if (!c || c.status !== 'pending') return { ok: false, msg: 'This change is no longer pending.' };
    const e = Registry.get(c.server); const t = e?.tools[c.tool];
    if (!t || !t.pendingFp) return { ok: false, msg: 'The server no longer presents this definition. Refresh discovery.' };
    if (t.pending.findings.length) return { ok: false, msg: 'Definitions with poisoning indicators cannot be approved (mandatory). Reject it or ask the server owner to fix it.' };
    Object.assign(t, { fp: t.pendingFp, description: t.pending.description, inputSchema: t.pending.inputSchema, findings: [], status: 'trusted', baseStatus: 'trusted', approvedAt: now() });
    delete t.pendingFp; delete t.pending;
    c.status = 'approved'; c.closedAt = now(); e.events.unshift({ ts: now(), msg: `Operator approved ${c.tool}` });
    this.save(); Registry.save(); await Warden.adminEvent('integrity.approve', `${c.server}/${c.tool} ${c.afterFp ? c.afterFp.slice(0, 12) : ''}`);
    return { ok: true };
  },
  async reject(id) {
    const c = this.find(id); if (!c || c.status !== 'pending') return { ok: false, msg: 'This change is no longer pending.' };
    const e = Registry.get(c.server); const t = e?.tools[c.tool];
    if (t) t.status = 'rejected';
    c.status = 'rejected'; c.closedAt = now(); e?.events.unshift({ ts: now(), msg: `Operator rejected change to ${c.tool}` });
    this.save(); Registry.save(); await Warden.adminEvent('integrity.reject', `${c.server}/${c.tool}`);
    return { ok: true };
  },
  pending() { return this.changes.filter(c => c.status === 'pending'); },
  async scanAll() { for (const e of Registry.entries) await Registry.verify(e.id, { silent: true, cause: 'manual scan' }); Registry.save(); },
  mirror() { return Registry.live.get('web-tools-mirror')?.server.state; },
  async simulate(flag, on) {
    const st = this.mirror(); if (!st) return { ok: false, msg: 'web-tools-mirror is not connected' };
    if (flag === 'reset') { for (const k of ['cosmetic', 'optionalParam', 'confidential', 'rugpull', 'addTool', 'removeExtract']) st[k] = false; }
    else st[flag] = on;
    await Registry.verify('web-tools-mirror', { cause: flag === 'reset' ? 'fixture reset' : 'upstream change (test fixture)' });
    return { ok: true };
  }
};
