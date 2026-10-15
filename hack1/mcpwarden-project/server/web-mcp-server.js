#!/usr/bin/env node
'use strict';
// Controlled Web MCP server, spoken to over stdio with the official MCP SDK.
// MCPWarden spawns it as a child process, so it has no network listener an agent could reach.
// Tool definitions and implementations are the existing ones (makeWebServer in engine.js), so the
// fingerprints MCPWarden approved are exactly the definitions this process serves.
//
//   --variant demo|mirror|community   which server persona to serve
//   --state-file <path>               mirror only: JSON file with simulated upstream changes (test fixture)
//
// Environment (set by MCPWarden, never by the agent):
//   MCPWARDEN_SERVER_TOKEN  calls must carry this in _meta['mcpwarden/token']
//   MCPWARDEN_EGRESS_URL    the only route to the web: MCPWarden's guarded egress endpoint
//   MCPWARDEN_EGRESS_TOKEN  bearer token for that endpoint
const fs = require('node:fs');
const { Server } = require('@modelcontextprotocol/sdk/server/index.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
const { ListToolsRequestSchema, CallToolRequestSchema, McpError } = require('@modelcontextprotocol/sdk/types.js');
const { loadEngine } = require('./runtime');

const arg = n => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1] : null; };
const variant = arg('--variant') || 'demo';
const stateFile = arg('--state-file');
const { SERVER_TOKEN, EGRESS_URL, EGRESS_TOKEN } = { SERVER_TOKEN: process.env.MCPWARDEN_SERVER_TOKEN, EGRESS_URL: process.env.MCPWARDEN_EGRESS_URL, EGRESS_TOKEN: process.env.MCPWARDEN_EGRESS_TOKEN };
if (!SERVER_TOKEN || !EGRESS_URL || !EGRESS_TOKEN) { process.stderr.write('web-mcp-server: missing MCPWarden environment; refusing to start\n'); process.exit(2); }

const E = loadEngine({ files: ['engine.js'] });
const web = E.makeWebServer(variant);

web.bind({
  token: SERVER_TOKEN,
  // Every fetch goes to MCPWarden's egress, which validates destination, pins DNS and revalidates redirects.
  egress: async (url, ctx) => {
    const r = await fetch(EGRESS_URL, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${EGRESS_TOKEN}` }, body: JSON.stringify({ url, ctx }) });
    const j = await r.json().catch(() => ({ error: { message: `egress returned HTTP ${r.status}` } }));
    if (j.error) {
      if (j.error.rule) throw new E.EgressError(j.error.message, j.error.rule, j.error.hop, j.error.cat);
      throw Object.assign(new Error(j.error.message), { code: j.error.code || 'EGRESS' });
    }
    return j.result;
  },
  onUnauthorized: () => process.stderr.write('web-mcp-server: rejected tools/call without a valid MCPWarden token\n'),
});

const loadState = () => {
  if (!stateFile) return;
  try { Object.assign(web.state, JSON.parse(fs.readFileSync(stateFile, 'utf8'))); } catch { /* no simulated changes */ }
};

const server = new Server(
  { name: web.identity.name, version: web.identity.version },
  // MCP has no standard server-identity field. The identity key is presented in `instructions`, and
  // MCPWarden compares its SHA-256 with the fingerprint an operator pinned.
  { capabilities: { tools: { listChanged: true } }, instructions: `mcpwarden-identity: ${web.identity.publicKey}` }
);

server.setRequestHandler(ListToolsRequestSchema, async () => {
  loadState();
  const r = await web.handle({ jsonrpc: '2.0', id: 'list', method: 'tools/list' });
  return { tools: r.result.tools };
});

server.setRequestHandler(CallToolRequestSchema, async req => {
  loadState();
  const r = await web.handle({ jsonrpc: '2.0', id: 'call', method: 'tools/call', params: req.params });
  if (r.error) throw new McpError(r.error.code, r.error.message);
  return r.result;
});

server.connect(new StdioServerTransport()).catch(e => { process.stderr.write('web-mcp-server: ' + e.message + '\n'); process.exit(1); });
