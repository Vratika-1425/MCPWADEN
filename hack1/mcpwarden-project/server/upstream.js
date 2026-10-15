'use strict';
// MCPWarden's MCP client to a protected Web MCP server, using the official SDK over stdio.
// Exposes request(msg) — the same contract the engine already uses — so Registry, Sentinel and the
// 18-stage pipeline run unchanged while every message really travels over MCP.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { StdioClientTransport } = require('@modelcontextprotocol/sdk/client/stdio.js');
const { McpError } = require('@modelcontextprotocol/sdk/types.js');

const SERVER_SCRIPT = path.join(__dirname, 'web-mcp-server.js');
// Registry endpoint ids (unchanged from the dashboard) mapped to the controlled server they launch.
const LIVE_ENDPOINTS = {
  'local://warden-web-demo': { variant: 'demo', label: 'Controlled Web MCP server (stdio child process)' },
  'local://web-tools-mirror': { variant: 'mirror', label: 'Third-party mirror (stdio child process; drift and poisoning tests)' },
  'local://community-web-tools': { variant: 'community', label: 'Community server, unreviewed (stdio child process)' },
};

class McpUpstream {
  constructor({ entryId, endpoint, egressUrl, egressToken, stateDir, onUnauthorized, onExit }) {
    const ep = LIVE_ENDPOINTS[endpoint]; if (!ep) throw new Error(`Endpoint ${endpoint} is not available in live mode`);
    this.entryId = entryId; this.ep = ep; this.onUnauthorized = onUnauthorized; this.onExit = onExit;
    this.token = crypto.randomBytes(16).toString('hex'); // held only by MCPWarden and the child it launched
    this.stateFile = path.join(stateDir, `${entryId}.fixture-state.json`);
    this.stderr = [];
    this.env = { MCPWARDEN_SERVER_TOKEN: this.token, MCPWARDEN_EGRESS_URL: egressUrl, MCPWARDEN_EGRESS_TOKEN: egressToken };
    // Simulated upstream changes (Sentinel / Threat Sandbox test fixture). Writes go to a file the child reads.
    const self = this; let st = {}; try { st = JSON.parse(fs.readFileSync(this.stateFile, 'utf8')); } catch { }
    this.state = new Proxy(st, { set(t, k, v) { t[k] = v; fs.writeFileSync(self.stateFile, JSON.stringify(t)); return true; } });
    this.sent = 0;
  }
  async start() {
    this.transport = new StdioClientTransport({
      command: process.execPath,
      args: ['--disable-warning=ExperimentalWarning', SERVER_SCRIPT, '--variant', this.ep.variant, '--state-file', this.stateFile],
      env: this.env, stderr: 'pipe',
    });
    this.client = new Client({ name: 'mcpwarden', version: '1.0.0' }, { capabilities: {} });
    this.transport.onclose = () => { this.closed = true; this.onExit?.(this.entryId); };
    await this.client.connect(this.transport, { timeout: 15000 });
    this.transport.stderr?.on('data', d => { this.stderr.push(String(d)); this.stderr = this.stderr.slice(-20); });
    this.pid = this.transport.pid;
    return this;
  }
  identity() {
    const m = /mcpwarden-identity:\s*(\S+)/.exec(this.client.getInstructions() || '');
    return m ? m[1] : '';
  }
  async request(msg) {
    this.sent++;
    if (this.closed) return { jsonrpc: '2.0', id: msg.id, error: { code: -32000, message: 'Upstream MCP server process is not running' } };
    try {
      if (msg.method === 'initialize') {
        // The SDK performed the real initialize handshake in start(); report what it negotiated.
        return { jsonrpc: '2.0', id: msg.id, result: { protocolVersion: this.transport.protocolVersion || this.client._negotiatedProtocolVersion || 'negotiated', serverInfo: this.client.getServerVersion(), capabilities: this.client.getServerCapabilities(), _meta: { 'mcpwarden/identity': this.identity() } } };
      }
      if (msg.method === 'tools/list') {
        const tools = []; let cursor;
        do { const r = await this.client.listTools(cursor ? { cursor } : undefined, { timeout: 15000 }); tools.push(...r.tools); cursor = r.nextCursor; } while (cursor);
        return { jsonrpc: '2.0', id: msg.id, result: { tools } };
      }
      if (msg.method === 'tools/call') {
        const r = await this.client.callTool(msg.params, undefined, { timeout: 30000 });
        return { jsonrpc: '2.0', id: msg.id, result: r };
      }
      return { jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: 'Method not supported by MCPWarden upstream adapter' } };
    } catch (e) {
      const code = e instanceof McpError ? e.code : -32000;
      if (code === -32001) this.onUnauthorized?.(this.entryId, msg);
      return { jsonrpc: '2.0', id: msg.id, error: { code, message: String(e.message || e).replace(/^MCP error -?\d+:\s*/, '') } };
    }
  }
  async close() { try { await this.client?.close(); } catch { } }
}

module.exports = { McpUpstream, LIVE_ENDPOINTS };
