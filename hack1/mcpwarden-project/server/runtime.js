'use strict';
// Loads the existing MCPWarden engine files (the same ones the dashboard uses) into a Node VM context.
// Nothing is reimplemented: the backend runs the identical 18-stage engine, Sentinel, Intent Firewall and Threat Sandbox code.
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const { DOMParser } = require('linkedom');

const ROOT = path.join(__dirname, '..');
const ENGINE_FILES = ['engine.js', 'sentinel.js', 'intent.js', 'lab.js'];

// A synchronous localStorage over any get/set/remove backend (SQLite in the server, a Map in the child process).
function makeLocalStorage(backend) {
  return {
    getItem: k => backend.get(k),
    setItem: (k, v) => backend.set(k, String(v)), // throws on failure; the engine's Store.set reports it
    removeItem: k => backend.remove(k),
    key: i => backend.keys()[i] ?? null,
    get length() { return backend.keys().length; },
    clear: () => backend.keys().forEach(k => backend.remove(k)),
  };
}

function memoryBackend() {
  const m = new Map();
  return { get: k => (m.has(k) ? m.get(k) : null), set: (k, v) => m.set(k, v), remove: k => m.delete(k), keys: () => [...m.keys()] };
}

// files: which engine files to load. The child Web MCP server only needs engine.js (tool implementations).
function loadEngine({ storage = memoryBackend(), files = ENGINE_FILES } = {}) {
  const context = {
    console, setTimeout, clearTimeout, setInterval, clearInterval, queueMicrotask, structuredClone,
    URL, URLSearchParams, TextEncoder, TextDecoder, performance, crypto: globalThis.crypto,
    DOMParser, localStorage: makeLocalStorage(storage),
  };
  vm.createContext(context);
  const code = files.map(f => fs.readFileSync(path.join(ROOT, f), 'utf8')).join('\n;\n');
  vm.runInContext(code, context, { filename: 'mcpwarden-engine.js' });
  const names = ['Warden', 'Registry', 'Audit', 'AuditStore', 'Store', 'Bus', 'Settings', 'STAGES', 'STAGE_IDX', 'MockNet', 'IP', 'Inspector',
    'Sentinel', 'Tasks', 'Intent', 'Decisions', 'Chains', 'Lab', 'LAB', 'Agent', 'Rate', 'ENDPOINTS', 'TOOL_DEFS', 'DEFAULT_POLICY',
    'MANDATORY_CONTROLS', 'EgressError', 'makeWebServer', 'htmlToText', 'validatePolicy', 'sanitizeUrl', 'safeText', 'sha256', 'canon', 'rid', 'hostOf'];
  const api = {};
  for (const n of names) { try { api[n] = vm.runInContext(`typeof ${n} === 'undefined' ? undefined : ${n}`, context); } catch { api[n] = undefined; } }
  // The engine declares `let Net = MockNet`; the backend swaps in a real network layer through this setter.
  api.setNet = net => { context.__net = net; vm.runInContext('Net = __net;', context); };
  api.getNet = () => vm.runInContext('Net', context);
  api.context = context;
  return api;
}

module.exports = { loadEngine, memoryBackend, ROOT };
