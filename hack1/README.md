# MCPWarden

Runtime security proxy for web-connected MCP tools. Every tool call an agent makes passes through an 18-stage pipeline before it executes, and every web response is inspected before the agent sees it. Every decision is recorded, explained and hash-chained.

This release adds five features on top of the existing product: the Agent Intent Firewall, the Attack Chain Explorer, the Tool Integrity Sentinel, the Threat Sandbox, and the Decision Explorer.

## Two modes

| | Demo mode | Live mode |
|---|---|---|
| How you get it | Open `index.html` directly, or the published claude.ai link | `npm start`, then open the console URL it prints |
| Where the engine runs | In the browser | On the Node backend; the browser only displays and sends commands |
| MCP | In-memory JSON-RPC between in-page functions | Official MCP SDK: agents connect over Streamable HTTP, protected servers over stdio |
| Network | In-page mock with fixtures | Real sockets, to either a local fixture web server (`fixture`) or the public web (`real`) |
| Audit storage | Browser storage | SQLite (`audit` table, append-only, hash-chained) |
| Top-bar pill | "Demo mode: in-browser simulation" | "Live mode: MCP backend, …", or "disconnected" if the backend is lost |

Both modes run the same engine files. The published link can never be live: the claude.ai artifact sandbox blocks requests to other servers.

## Architecture

```
User task ──► Demo agent (rule-based, labelled) ──► Warden.call()  ← the only handle the agent holds
                                                     │
            1  Request intercepted                   │  request phase
            2  MCP server verified (pinned identity, operator trust, policy)
            3  Tool and schema validated ◄── Tool Integrity Sentinel (trust state + fingerprint)
            4  URL normalized
            5  Destination safety (DNS, every record classified)   ┐ mandatory,
            6  SSRF policy (per-tool reach, pinning)               ┘ never overridable
            7  Agent intent evaluated ◄── task profile + recorded URL provenance
            8  Rate limit
            9  Human approval (cannot override 1–7)
           10  Access decision
           11  Forwarded (proxy-bound token, pinned egress, per-hop redirect checks)
                                                     │  response phase
           12  Response received   13 Injection   14 Tool steering/poisoning
           15  Secrets and PII     16 Response policy   17 Sanitize/block   18 Return
                                                     │
            Audit (SHA-256 chain) · Decision record · Intent evaluation · Task provenance
```

The engine is split into modules: `engine.js` holds the proxy, the mock network, the MCP servers and the audit log. `sentinel.js` holds the tool integrity code. `intent.js` holds task tracking, the intent firewall, decision records and attack-chain correlation. `lab.js` holds the threat sandbox, and `ui.js` and `ui2.js` hold the interface.

### What each new feature does

**Agent Intent Firewall (stage 7).**
- Each task gets a deterministic profile: its category, the tools it needs, and the hosts the user named.
- MCPWarden records every URL it returns to the agent. When a later call arrives, it looks up where the destination came from without relying on anything the agent says. The possible origins are: named by the user, taken from a search result, taken from page content, or unknown.
- Rules cover out-of-scope tools, follow-ups suggested by page content, unknown origin, exfiltration-shaped URLs and a per-task call budget. Each rule can be set to `allow`, `review` or `block`.
- An optional lexical relevance classifier can raise a decision to review. It cannot relax a rule or block on its own.
- This stage runs after the mandatory URL, DNS and SSRF checks. It adds task context on top of them; it never replaces them.

**Tool Integrity Sentinel.**
- Every tool gets a baseline and a SHA-256 fingerprint of its name, description and input schema.
- Each discovery, including the one done at call time, compares the live definitions with the baselines. It detects tools that were added, removed or modified.
- Changes are classified as `cosmetic`, `benign` or `suspicious`. A change is suspicious if it shows poisoning indicators, newly mentions sensitive terms, or adds parameters that could carry sensitive data.
- Tool trust states are `trusted`, `pending-review`, `quarantined`, `rejected` and `removed`. Only `trusted` tools whose live fingerprint matches the baseline can be used.
- New tools on an already trusted server start in pending review. Definitions with poisoning indicators cannot be approved.
- Every change, approval, rejection and revert goes into the audit log. A side-by-side word and line diff is shown for review.

**Decision Explorer.**
- Each proxied request produces a persisted decision record. It holds every stage's status, result, rule, timing and sanitized evidence, plus the task, the destination's origin, connections, redirect hops, whether the tool executed, the response outcome, and the audit sequence number and hash.
- Explanations are built only from these records.
- Checks that never ran are listed as "not executed". They are never counted as passed.
- The "Verify record" button checks the record against the audit chain.

**Attack Chain Explorer.**
- Decision records from one task are correlated into a single graph: task, calls, retrieved pages, suspicious content, follow-up actions, triggered policy and the final decision.
- Edges are "confirmed" when they rest on IDs MCPWarden recorded itself: task ID, request ID, provenance source, or a change-record ID.
- Edges are "inferred", and drawn dashed, when they rest only on a parent the agent declared.
- Calls that executed before the first detection are flagged.
- Unrelated tasks are never merged.

**Threat Sandbox.** This replaces the Web Attack Lab and keeps all 22 original scenarios.
- It adds 6 new ones: two unauthorized follow-ups, a benign research follow-up, a tool description that starts asking for confidential data, a new tool appearing on a trusted server, and a harmless schema change.
- The "Run Security Test Suite" button runs all of them against the engine. There are now 31, including 3 campus scenarios (L29–L31).
- Results show the policy version they ran under. A banner warns when the current policy differs from the defaults, so results that change after a policy edit are explained rather than hidden.

## Live mode architecture

```
Agent (any MCP client) ──Streamable HTTP + bearer token──► MCPWarden /mcp
                                                              │ Warden.call: the 18 stages above (unchanged engine)
                                         MCP over stdio (SDK) ▼
                         protected Web MCP server (child process, no listening port,
                         rejects tools/call without the token only MCPWarden holds)
                                                              │ every fetch
                                                              ▼
                         127.0.0.1 egress endpoint (separate token) ─► Warden.egress
                         (normalize, DNS check, pin, per-hop redirect revalidation, rebinding check)
                                                              ▼
                         RealNet / FixtureNet: real socket to the validated IP only;
                         the socket's remote address is checked again on connect
Dashboard (index.html, unchanged) ◄── /api/* + /api/events (SSE) ── same backend
```

| File | Role |
|---|---|
| `server/index.js` | Backend entry: hosts the engine, agent MCP endpoint, egress endpoint, dashboard API, SSE, auth |
| `server/runtime.js` | Loads the existing engine files unchanged into a Node VM context |
| `server/upstream.js` | Official SDK MCP client to the protected servers (stdio) |
| `server/web-mcp-server.js` | Controlled Web MCP server (official SDK), reusing the existing tool implementations |
| `server/net.js` | Real network layer, fixture network layer, and the local fixture web server |
| `server/db.js` | SQLite (`node:sqlite`); parameterized statements only |
| `live-client.js` | Browser mirror for live mode; inert in demo mode |

## Setup

Requires Node 22.9 or newer, for built-in `node:sqlite` and `--env-file-if-exists`.

```
npm install
npm run build          # builds index.html (used by both modes)
cp .env.example .env   # optional: set tokens, port, network mode
npm start              # prints the console URL and the agent MCP endpoint
```

- **Dashboard:** open the printed `http://127.0.0.1:8787/?token=…` once. It sets an HttpOnly, SameSite=Strict cookie.
- **Agents:** connect any MCP client to `http://127.0.0.1:8787/mcp` with `Authorization: Bearer $MCPWARDEN_AGENT_TOKEN`.
  - Tools from the default server keep their names; other trusted servers' tools are exposed as `<server>__<tool>`.
  - Optional `_meta` keys: `mcpwarden/task` (task text, which enables the intent firewall's task context), `mcpwarden/taskId` and `mcpwarden/parent`.
- **Network:**
  - `MCPWARDEN_NETWORK=fixture` (the default) uses real sockets to a local fixture web server with fixture DNS, and works offline. The Threat Sandbox needs this mode because its scenarios use fixture hostnames.
  - `MCPWARDEN_NETWORK=real` uses real DNS and the public web.
- **Secrets:** all tokens stay on the server. None are sent to the dashboard.

## Tests

`npm test` builds the page, then runs:
1. the 6 original demo-mode suites, unchanged (`tests/run-demo-suites.js` checks their output);
2. 62 integration tests (`tests/integration/`, Node test runner) against a real backend on a throwaway database.

The integration tests cover:
- **Real MCP:** SDK client → MCPWarden → stdio server, with tool discovery and agent authentication.
- **Allowed call over a real socket:** exactly one web request and one upstream `tools/call` are made.
- **Six prohibited destinations:** each is denied before execution, with zero upstream calls, zero sockets and zero web-server hits.
- **Real-network mode:** a canary server on loopback receives nothing, even though real DNS resolves `localhost`.
- **Redirects and rebinding:** each redirect hop is revalidated, and DNS rebinding is refused.
- **Audit:** SQLite rows match the engine's decisions, survive a restart, and still verify the hash chain. Simulated disk failures cause content to be withheld and new calls to be refused.
- **Threat Sandbox:** all 31 scenarios pass through the live backend.
- **Campus scenario:** an external MCP client walks through the timetable and notice flows. Its manipulated follow-ups are denied with zero upstream calls and zero web hits. The audit rows and confirmed attack-chain links are also checked.
- **Event stream:** stage events arrive in execution order, and the streamed verdict equals the one the agent received.
- **Errors and timeouts:** a slow upstream hits the 3-second policy timeout and is reported as FAILED; a crashed protected server is denied at server verification and recovers when re-verified; malformed and oversized MCP input is rejected.
- **The dashboard cannot override the backend:** policy edits that weaken mandatory controls are rejected; no API executes a tool or sets a verdict; browser-side tool calls are disabled; tampering with browser objects doesn't change backend decisions.
- **Dashboard:** the unmodified dashboard shows the exact backend decision, and shows when the backend disconnects.
- **Bypass routes:** all are refused.

**Results for this build:** `npm test` exited 0. Demo suites: 6 of 6 passed. Integration tests: 62 of 62 passed.

**Visual check:** your original page and this build were rendered side by side in Chromium (demo mode, frozen clock).
- The landing page is pixel-identical.
- Each of the 14 app pages differs only in the second top-bar pill: about 2,190 pixels, where the text changed from "Deterministic demo agent" to the mode label.
- The only other differences are counts the pages compute from data: 31 scenarios instead of 28, 18 fixture hostnames instead of 15, and the 3 new campus rows in the Threat Sandbox table.

**Mutation checks:** I deliberately broke the code in a scratch copy, to confirm the tests can fail:
- **Metadata-address rule removed:** 2 tests failed. The request was still blocked by the general link-local rule (defence in depth), but the tests flagged that the wrong rule fired.
- **Whole destination check made to always pass:** 4 tests failed and 1 timed out.

## Campus demonstration

This is a fictional, controlled scenario: an AI campus assistant helping a student. All pages are local fixtures on `campus-demo.test` hostnames, and no real student record or university system is involved. It shows how a deployment could work; it is not evidence that any institution has authorised one.

```
npm run demo:campus -- --sandbox        # starts a private backend and prints the evidence
npm start   +   npm run demo:campus -- --live   # runs against your backend; watch the dashboard
```

`--live` needs `MCPWARDEN_AGENT_TOKEN` and `MCPWARDEN_ADMIN_TOKEN` set in `.env`.

What it shows, with request IDs and audit sequence numbers:

1. **"Find the examination timetable":** `search_web`, then `fetch_url` on the top result. Both are allowed, and MCPWarden records that the URL came from its own search result.
2. **"Summarize the latest examination notice":** the notice hides an obvious injection, which the inspector removes. The response is sanitized, and the legitimate content is kept.
3. **The manipulated follow-ups:** the notice also carries a subtle instruction to open two links, which the detector doesn't flag. Detection is best-effort. A manipulated assistant tries both:
   - the data-sink link is denied by the intent firewall, because it came from page content;
   - the internal address `10.10.0.5` is denied by the mandatory destination check.

   Neither executes, no connection is opened, and the fixture web server receives zero requests for them.
4. **Audit and attack chain:** the SQLite audit chain verifies. The attack chain links both follow-ups to the notice with confirmed edges. In the dashboard, see Attack Chain Explorer and Decision Explorer.
5. **Destination protection:** a request to the cloud metadata address is denied before any connection.
6. **Threat Sandbox (optional):** runs all 31 scenarios.

In the dashboard you can also type the two tasks into the Web Agent Playground. Use "Manipulable" agent behaviour for the notice.

## What persists, and what does not (live mode)

| Data | Where | After a restart |
|---|---|---|
| Audit log | SQLite `audit` table, one row per record, committed before the call returns | Kept; the hash chain verifies |
| Decision records, intent evaluations, tasks and provenance | SQLite | Kept (most recent 250, 300 and 200) |
| Policy and version history | SQLite | Kept |
| Server registry, tool baselines and trust states, integrity changes | SQLite | Kept; servers are relaunched and re-verified |
| Threat Sandbox results | SQLite | Kept |
| Pending approvals | Memory | Lost. The waiting call is dropped with the process, so nothing runs unapproved; the agent must retry |
| Rate-limit windows | Memory | Reset |
| Live pipeline view of recent runs | Memory | Cleared; the evidence stays in Decision Explorer |

**What the audit hash chain guarantees:** any change, deletion or reordering of a stored record is detected by verification. It does not stop someone with full control of the server and database from rewriting the whole chain. Copying the chain head to external storage would close that gap; this build doesn't do it.

## Repository layout

The engine files stay at the repository root, used by both modes:
- `engine.js`, `sentinel.js`, `intent.js` and `lab.js` hold the security logic;
- `ui.js`, `ui2.js`, `live-client.js`, `boot.js` and `head.html` hold the interface.

The backend loads the same engine files through `server/runtime.js`, so no security logic exists twice. I didn't move them into `frontend/` and `core/` folders, because that would risk the build and the published demo for no functional gain.

## Security assumptions

- **Enforcement location.** In live mode, all enforcement happens on the backend. The browser holds no tokens and cannot run tools.
- **Mandatory controls.** These run before the intent firewall and before human approval, and neither can override them:
  - destination classification;
  - DNS pinning;
  - redirect revalidation;
  - rebinding detection;
  - the scheme allow-list;
  - tool trust states;
  - the proxy token.
- **Fail closed.** Any exception in a security stage fails closed.
  - **Audit write failure:** the result is withheld from the agent and new calls are refused until storage recovers.
  - **What it can't undo:** the tool has already executed by the time its audit record is written.
- **Protected servers.** They are spawned by MCPWarden with a per-process token and have no network listener. Their only intended route to the web is the egress endpoint, which accepts only contexts belonging to an active proxied call.
- **Console protection.** The console binds to 127.0.0.1, requires the admin cookie, checks the Host header, and requires a CSRF header on writes.

## Limitations

- **Public web untested.** Real public websites were not tested. The build sandbox can only reach package registries, so all fetches in the tests went to the local fixture web server over real sockets. Real-network mode is covered only by the loopback canary test.
- **No OS-level isolation.** Nothing at the operating-system level stops protected servers from opening their own connections. Production use should add container or firewall egress rules, so MCPWarden's egress is the only way out.
- **Plain HTTP in fixture mode.** The fixture web server is plain HTTP, even for `https://` fixture URLs. TLS is used only in real mode.
- **Server identity.** MCP has no standard server-identity field, so the identity key is presented in the `instructions` field of the MCP handshake.
- **Single operator.** There is one admin token and no multi-user accounts.
- **Live dashboard window.** The live dashboard loads the most recent 3,000 audit entries. Verification always covers the full log on the server.
- **Detection.** Prompt-injection, poisoning and relevance detection are pattern-based and best-effort.
- **SQLite.** `node:sqlite` still prints an "experimental" warning in Node 22; the npm scripts suppress it.
