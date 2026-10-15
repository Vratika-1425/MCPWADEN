'use strict';
// Shared helpers for integration tests: a throwaway live backend, a real MCP client, and the
// unmodified dashboard (index.html) loaded in jsdom, talking to that backend over real HTTP.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const ROOT = path.join(__dirname, '..', '..');
const { start } = require(path.join(ROOT, 'server', 'index.js'));
const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { StreamableHTTPClientTransport } = require('@modelcontextprotocol/sdk/client/streamableHttp.js');

const TOKENS = { MCPWARDEN_AGENT_TOKEN: 'it-agent-token', MCPWARDEN_ADMIN_TOKEN: 'it-admin-token' };
const tmpDb = () => path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'mcpw-it-')), 'mcpwarden.db');
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function startBackend(db = tmpDb(), extra = {}) {
  const app = await start({ MCPWARDEN_PORT: '0', MCPWARDEN_DB: db, MCPWARDEN_QUIET: 'true', ...TOKENS, ...extra });
  app.db = db; return app;
}
async function mcpClient(app, token = TOKENS.MCPWARDEN_AGENT_TOKEN) {
  const c = new Client({ name: 'integration-test-agent', version: '1.0.0' });
  await c.connect(new StreamableHTTPClientTransport(new URL(app.url + '/mcp'), { requestInit: { headers: { authorization: `Bearer ${token}` } } }));
  return c;
}

// Minimal EventSource for jsdom (it has none), reading the backend's real SSE stream.
function makeEventSource(base, cookie, open) {
  return class EventSource {
    constructor(p) {
      open.add(this);
      const u = new URL(p, base); this.onopen = null; this.onmessage = null; this.onerror = null;
      this.req = http.get(u, { headers: { cookie, accept: 'text/event-stream' } }, res => {
        if (res.statusCode !== 200) { this.onerror?.({}); return; }
        this.onopen?.({}); let buf = '';
        res.setEncoding('utf8');
        res.on('data', d => { buf += d; let i; while ((i = buf.indexOf('\n\n')) >= 0) { const block = buf.slice(0, i); buf = buf.slice(i + 2);
          const data = block.split('\n').filter(l => l.startsWith('data: ')).map(l => l.slice(6)).join('\n'); if (data) this.onmessage?.({ data }); } });
        res.on('end', () => this.onerror?.({}));
      });
      this.req.on('error', () => this.onerror?.({}));
    }
    close() { this.closed = true; this.onerror = this.onmessage = this.onopen = null; this.req.destroy(); }
  };
}

// Loads the built dashboard exactly as the backend serves it, with fetch and EventSource wired to the backend.
async function openDashboard(app, { JSDOM, VirtualConsole } = require('jsdom')) {
  const cookie = `mcpw_admin=${encodeURIComponent(TOKENS.MCPWARDEN_ADMIN_TOKEN)}`;
  const page = await fetch(app.url + '/', { headers: { cookie } });
  if (page.status !== 200) throw new Error('dashboard not served: HTTP ' + page.status);
  const html = await page.text();
  const errors = []; const vc = new VirtualConsole(); const streams = new Set();
  vc.on('jsdomError', e => errors.push(e.message + (e.detail && e.detail.stack ? ' @ ' + e.detail.stack.split('\n').slice(1, 4).join(' | ') : ''))); vc.on('error', e => errors.push(String(e)));
  const dom = new JSDOM(html, { url: app.url + '/', runScripts: 'dangerously', pretendToBeVisual: true, virtualConsole: vc, beforeParse(w) {
    Object.defineProperty(w, 'crypto', { value: globalThis.crypto }); w.TextEncoder = TextEncoder; w.confirm = () => true;
    w.fetch = (p, o = {}) => fetch(new URL(p, app.url), { ...o, signal: undefined, headers: { ...(o.headers || {}), cookie } });
    w.EventSource = makeEventSource(app.url, cookie, streams);
  } });
  const w = dom.window;
  const $ = s => w.document.querySelector(s), $$ = s => [...w.document.querySelectorAll(s)];
  const go = async h => { w.location.hash = h; await sleep(150); };
  const waitFor = async (fn, ms = 15000) => { const t0 = Date.now(); while (Date.now() - t0 < ms) { const v = fn(); if (v) return v; await sleep(100); } return null; };
  // Close event streams before the window, so no handler runs against a destroyed document.
  return { dom, w, $, $$, go, waitFor, errors, close: () => { for (const es of streams) es.close(); w.close(); } };
}

module.exports = { ROOT, startBackend, mcpClient, openDashboard, tmpDb, sleep, TOKENS };
