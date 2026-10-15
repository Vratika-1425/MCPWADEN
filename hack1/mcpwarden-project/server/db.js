'use strict';
// SQLite persistence (node:sqlite, built into Node 22). All statements are parameterized.
const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

function openDb(file) {
  if (file !== ':memory:') fs.mkdirSync(path.dirname(file), { recursive: true });
  const db = new DatabaseSync(file);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = FULL;
    CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL, updated_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS audit (
      seq INTEGER PRIMARY KEY,
      request_id TEXT, ts INTEGER NOT NULL, kind TEXT, source TEXT, server TEXT, tool TEXT,
      decision TEXT, verdict TEXT, policy TEXT,
      prev_hash TEXT NOT NULL, hash TEXT NOT NULL, entry_json TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS audit_request ON audit(request_id);
  `);
  const q = {
    kvGet: db.prepare('SELECT v FROM kv WHERE k = ?'),
    kvSet: db.prepare('INSERT INTO kv (k, v, updated_at) VALUES (?, ?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v, updated_at = excluded.updated_at'),
    kvDel: db.prepare('DELETE FROM kv WHERE k = ?'),
    kvKeys: db.prepare('SELECT k FROM kv ORDER BY k'),
    auditAll: db.prepare('SELECT entry_json FROM audit ORDER BY seq'),
    auditCount: db.prepare('SELECT COUNT(*) AS n FROM audit'),
    auditInsert: db.prepare('INSERT INTO audit (seq, request_id, ts, kind, source, server, tool, decision, verdict, policy, prev_hash, hash, entry_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'),
    auditUpdate: db.prepare('UPDATE audit SET decision = ?, verdict = ?, entry_json = ? WHERE seq = ?'),
    auditClear: db.prepare('DELETE FROM audit'),
    auditBySeq: db.prepare('SELECT entry_json FROM audit WHERE seq = ?'),
  };
  // Test hook: lets integration tests simulate a failing disk without touching the real file system.
  let failWrites = false;
  const guard = () => { if (failWrites) throw new Error('SQLITE_FULL: simulated write failure'); };

  const kv = {
    get: k => q.kvGet.get(k)?.v ?? null,
    set: (k, v) => { guard(); q.kvSet.run(k, v, Date.now()); },
    remove: k => { guard(); q.kvDel.run(k); },
    keys: () => q.kvKeys.all().map(r => r.k),
  };

  // Matches the engine's AuditStore interface. append() returns true only after the row is committed.
  const auditStore = {
    kind: 'sqlite',
    load: () => q.auditAll.all().map(r => JSON.parse(r.entry_json)),
    append: (list, e) => {
      guard();
      q.auditInsert.run(e.seq, e.requestId ?? null, e.ts, e.kind ?? null, e.source ?? null, e.server ?? null, e.tool ?? e.action ?? null,
        e.decision ?? null, e.verdict ?? null, e.policy ?? null, e.prevHash, e.hash, JSON.stringify(e));
      return true;
    },
    update: (list, e) => { guard(); q.auditUpdate.run(e.decision ?? null, e.verdict ?? null, JSON.stringify(e), e.seq); return true; },
    clear: () => { guard(); q.auditClear.run(); return true; },
    probe: () => {
      try { guard(); db.exec('BEGIN'); q.kvSet.run('__audit_probe', String(Date.now()), Date.now()); db.exec('ROLLBACK'); return true; }
      catch { try { db.exec('ROLLBACK'); } catch { } return false; }
    },
    count: () => q.auditCount.get().n,
    bySeq: seq => { const r = q.auditBySeq.get(seq); return r ? JSON.parse(r.entry_json) : null; },
  };
  return { db, kv, auditStore, setFailWrites: v => { failWrites = !!v; }, close: () => db.close() };
}

module.exports = { openDb };
