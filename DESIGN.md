# Federated Agent Messaging (FAM) — Design Document

## Overview

FAM is an agent-framework-agnostic messaging system for agent-to-agent and agent-to-human communication. It uses a three-layer authentication model (OAuth 2.0 + passkey + key pair) to ensure entity identity is cryptographically bound to specific instances.

**Key principles:**
- Account-based identity (email as ID)
- Entity instances are authenticated separately from accounts
- Framework-agnostic (MCP is one transport, not the only one)
- Federation-ready but local-only for v1
- TPM-backed auto-unlock for v2

---

## Account/Entity Data Model

### Account

The root identity. A human or organization that owns entities.

```
Account ID:    Email address (ciresnave@gmail.com)
Display Name:  Human-readable name
Created At:    Timestamp
```

**Purpose:** Global identity, verified by OAuth 2.0 provider. Account owns all entities and message history.

### Entity

An authorized instance under an account. The entity is what connects, sends messages, and interacts with other entities.

```
Entity ID:     name@account (FAM-Architect@ciresnave@gmail.com)
Account ID:    FK → accounts
Type:          agent | human | tool
Display Name:  Human-readable name
Capabilities:  JSON (can_send, can_join_channel, can_create_entities, etc.)
Location:      Current server (for federation)
Public Key:    Base64-encoded public key
Created At:    Timestamp
Last Seen:     Timestamp
```

### Entity Types

| Type | Description | Example |
|------|-------------|---------|
| agent | AI agent that sends/receives messages | FAM-Worker-1@ciresnave@gmail.com |
| human | Human participant | john@company.com |
| tool | Local resource exposed via FAM | CommandPrompt@ciresnave@gmail.com |

### Channel

A named group for broadcast messaging.

```
Channel ID:    UUID
Name:          Human-readable name
Created By:    FK → entities
Is Public:     Boolean
Created At:    Timestamp
```

### Channel Members

```
Channel ID:    FK → channels
Entity ID:     FK → entities
Role:          owner | admin | member
Joined At:     Timestamp
```

### Messages

```
Message ID:    Auto-increment
Channel ID:    FK → channels (NULL for DMs)
From Entity:   FK → entities
To Entity:     FK → entities (NULL for channel messages)
Text:          String
Sent At:       Timestamp
Delivered:     Boolean
```

---

## Database Schema (SQLite)

```sql
CREATE TABLE accounts (
  id TEXT PRIMARY KEY,           -- email address
  display_name TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE authorizations (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id),
  server_id TEXT NOT NULL,       -- which FAM server is authorized
  token_hash TEXT NOT NULL,
  granted_at TEXT DEFAULT (datetime('now')),
  expires_at TEXT,
  revoked_at TEXT
);

CREATE TABLE entities (
  id TEXT PRIMARY KEY,           -- name@account
  account_id TEXT NOT NULL REFERENCES accounts(id),
  type TEXT NOT NULL CHECK(type IN ('agent', 'human', 'tool')),
  display_name TEXT,
  capabilities JSON DEFAULT '{}',
  location_server TEXT,          -- which FAM server it's currently on
  public_key TEXT NOT NULL,      -- base64-encoded public key
  created_at TEXT DEFAULT (datetime('now')),
  last_seen TEXT
);

CREATE TABLE channels (
  id TEXT PRIMARY KEY,           -- UUID
  name TEXT NOT NULL,
  created_by_entity TEXT REFERENCES entities(id),
  is_public INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE channel_members (
  channel_id TEXT REFERENCES channels(id),
  entity_id TEXT REFERENCES entities(id),
  role TEXT DEFAULT 'member' CHECK(role IN ('owner', 'admin', 'member')),
  joined_at TEXT DEFAULT (datetime('now')),
  PRIMARY KEY (channel_id, entity_id)
);

CREATE TABLE messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  channel_id TEXT REFERENCES channels(id),
  from_entity TEXT NOT NULL REFERENCES entities(id),
  to_entity TEXT REFERENCES entities(id),
  text TEXT NOT NULL,
  sent_at TEXT DEFAULT (datetime('now')),
  delivered INTEGER DEFAULT 0
);

-- Indexes for common queries
CREATE INDEX idx_entities_account ON entities(account_id);
CREATE INDEX idx_messages_channel ON messages(channel_id);
CREATE INDEX idx_messages_to ON messages(to_entity, delivered);
CREATE INDEX idx_messages_from ON messages(from_entity);
```

---

## Authentication Flows

### Three-Layer Security Model

```
Layer 1: Account token (OAuth 2.0)     — proves identity
Layer 2: Passkey (decrypts file)       — proves intent (physical presence)
Layer 3: Private key (signs challenge) — proves entity identity
```

**To impersonate an entity, you need all three layers.**

### Account Authentication (OAuth 2.0)

```
1. Account clicks "Authorize" on FAM server
2. Server redirects to identity provider (Google, GitHub, etc.)
3. Account authenticates with provider
4. Provider issues authorization code
5. Server exchanges code for access token
6. Server now has proof that the account authorized it
```

**Key insight:** FAM server never sees the account's password. Only gets a token from the identity provider.

### Entity Creation

```
1. Account authenticates → account_token
2. Account creates entity:
   POST /entities/create { account_token, name, type, capabilities }
3. Server generates key pair (Ed25519 or similar)
4. Server encrypts private key with derived key (from passkey)
5. Server returns:
   {
     entity_id: "FAM-Architect@ciresnave@gmail.com",
     public_key: "base64...",
     encrypted_private_key: "base64...",
     kdf_params: { ... }
   }
6. Account stores encrypted_private_key locally
```

### Entity Connection

```
1. Entity loads encrypted_private_key from local storage
2. Entity prompts for passkey (password, Windows Hello, PIN, hardware key)
3. Passkey derives key via KDF (argon2id)
4. Derived key decrypts private key
5. Entity connects to server:
   POST /entities/connect { entity_id, public_key_signature }
6. Server sends nonce challenge
7. Entity signs nonce with private key
8. Server verifies signature
9. Entity is now authenticated and authorized
```

### Encrypted File Format

```json
{
  "entity_id": "FAM-Architect@ciresnave@gmail.com",
  "public_key": "base64...",
  "encrypted_private_key": "base64...",
  "kdf": "argon2id",
  "kdf_params": {
    "memory": 65536,
    "iterations": 3,
    "parallelism": 4
  },
  "encryption": "aes-256-gcm"
}
```

---

## Messaging API Surface

### Push-First Architecture

Messages are pushed to entities, not polled. Entities receive messages in real-time when online, or have them queued for delivery when they come back online.

### Push Strategies by Framework

| Framework | Push Mechanism | Implementation |
|-----------|---------------|----------------|
| Claude Code | MCP channel notifications | `notifications/claude/channel` (existing code) |
| OpenCode | Message queue + prompt injection | Queue messages, append to LLM context with next user prompt |
| LangChain/CrewAI | WebSocket callback | Real-time WebSocket push to agent's message handler |
| AutoGen | Event system | Hook into agent's event/message queue |
| Custom agents | WebSocket or HTTP webhook | Standard push interface |

### Account Endpoints

```
POST /accounts/authorize          — OAuth callback, grants server access
POST /accounts/create-entity      — create entity under this account
POST /accounts/list-entities      — list my entities
POST /accounts/revoke-entity      — revoke entity token
```

### Entity Endpoints

```
POST /entities/connect            — authenticate and go online
POST /entities/disconnect         — go offline
POST /entities/status             — set status (optional)
POST /entities/list               — list online entities (with filters)
POST /entities/subscribe          — register push endpoint (WebSocket URL, webhook, etc.)
POST /entities/unsubscribe        — remove push endpoint
```

### Channel Endpoints

```
POST /channels/create             — create channel
POST /channels/join               — join channel
POST /channels/leave              — leave channel
POST /channels/list               — list available channels
POST /channels/list-members       — who's in this channel
```

### Message Endpoints

```
POST /messages/send               — send to entity or channel
WebSocket: { type: "send" }       — send message (real-time)
WebSocket: { type: "message" }    — receive message (real-time)
```

### Health

```
GET /health                       — server status
```

### WebSocket Message Format

```json
// Server → Entity (push)
{
  "type": "message",
  "from": "FAM-Architect@ciresnave@gmail.com",
  "channel": "project-x",
  "text": "Please review the latest changes",
  "timestamp": "2026-08-15T10:30:00Z"
}

// Entity → Server (send)
{
  "type": "send",
  "to": "FAM-Worker-1@ciresnave@gmail.com",
  "text": "On it, reviewing now"
}
```

---

## Transport Adapters

### MCP Server (for Claude Code)

- Translates FAM API to MCP tools
- Uses `notifications/claude/channel` for push notifications
- One instance per Claude Code session
- Reuses existing claude-peers-mcp channel push code

### WebSocket Client (for generic agents)

- Standard WebSocket connection
- JSON message format
- Heartbeat/ping-pong for keepalive
- Real-time push to agent's message handler

### CLI (for humans)

- Interactive terminal interface
- Manual passkey entry
- Channel management, message sending
- Online/offline status display

### HTTP API (for web UIs)

- RESTful endpoints
- OAuth 2.0 integration
- WebSocket upgrade for real-time
- CORS support for browser clients

---

## Security Tiers

### Tier 1: Manual Authentication

- Passkey required at launch
- No auto-unlock
- Highest security
- Use case: Sensitive tool entities, one-off operations

### Tier 2: OS Keychain Auto-unlock (v1)

- Passkey entered once, derived key cached in OS keychain
- Auto-unlock on subsequent launches
- Medium security
- Use case: Background agents, production servers

### Tier 3: TPM-backed Auto-unlock (v2)

- Derived key stored in TPM
- Hardware-backed protection
- Platform-specific implementation
- Use case: High-security production environments

### Platform Support (v2)

| Platform | Method | Status |
|----------|--------|--------|
| Windows | Windows Hello / DPAPI + TPM | Supported |
| macOS | Secure Enclave + TPM | Supported |
| Linux | tpm2-tools + systemd | Supported (major distros) |
| Other | Fallback to Tier 2 | Manual support |

---

## Federation Protocol (v2)

### Design Principles

- Account IDs are emails → naturally encode home server
- Entity IDs are local to a server, referenced globally as `entity@server`
- Federation adds server-to-server forwarding
- No changes to agent-facing APIs

### Server-to-Server Protocol

```
1. Server A receives message for entity on Server B
2. Server A looks up entity's location (Server B)
3. Server A forwards message to Server B
4. Server B delivers to entity
```

### Account Verification

- Server A can verify Server B is authorized for an account
- Uses OAuth 2.0 tokens or signed assertions
- No need to contact the identity provider for every message

### Entity Transfer

- Account initiates transfer to Server B
- Account shares entity's public key with Server B
- Entity connects to Server B with its private key
- Server B verifies the key pair → entity is authenticated
- Server A releases the entity

---

## Reusable Components from claude-peers-mcp

| Component | Reuse? | Notes |
|-----------|--------|-------|
| `broker.ts` HTTP server | Partial | Reuse HTTP server setup, replace API endpoints |
| `broker.ts` SQLite setup | Partial | Reuse WAL mode, busy timeout, replace schema |
| `server.ts` MCP server | Partial | Reuse MCP setup, replace tools |
| `server.ts` channel push | Yes | Core mechanism for Claude Code integration |
| `shared/types.ts` | Replace | New type definitions for accounts/entities |
| `shared/summarize.ts` | Replace | Remove OpenAI dependency, make pluggable |
| `cli.ts` | Replace | New CLI for FAM commands |
| `package.json` | Partial | Keep bun, replace dependencies |

---

## Implementation Phases

### Phase 1: Core Account/Entity System

- [ ] Account authentication (OAuth 2.0)
- [ ] Entity creation with key pair generation
- [ ] Encrypted private key storage
- [ ] Entity connection and challenge-response auth
- [ ] Online/offline status tracking

### Phase 2: Messaging

- [ ] Point-to-point messaging
- [ ] Channel creation and management
- [ ] Message storage and delivery
- [ ] Online/offline message handling

### Phase 3: Transport Adapters

- [ ] MCP server (Claude Code integration)
- [ ] WebSocket client (generic agents)
- [ ] CLI (human interface)
- [ ] HTTP API (web UIs)

### Phase 4: Security

- [ ] OS keychain integration (Windows, macOS, Linux)
- [ ] TPM-backed auto-unlock (Windows)
- [ ] TPM-backed auto-unlock (macOS)
- [ ] TPM-backed auto-unlock (Linux major distros)

### Phase 5: Federation

- [ ] Server-to-server protocol
- [ ] Cross-server message routing
- [ ] Account verification
- [ ] Entity transfer protocol

---

## Open Questions

**Five of the six below were answered by the code and never struck from this
list. Corrected 2026-09-05, each verified against `origin/main` rather than
inherited** — a question listed as open invites someone to re-decide something
already decided, and to build a second answer beside the first.

1. ~~**OAuth 2.0 providers**~~ — **ANSWERED: both.** Google and GitHub are
   implemented in `src/auth/oauth.ts`.
2. ~~**Key pair algorithm**~~ — **ANSWERED: Ed25519 for identity, X25519 for
   encryption.** Two keypairs, not one. ⚠️ `src/crypto/keys.ts` warns at length
   against merging them: an Ed25519 public key *imports* as X25519 and derives
   32 plausible bytes, so the shortcut produces ciphertext the recipient can
   never open and every check short of testing agreement passes.
3. **Channel permissions**: should channels have fine-grained permissions beyond
   owner/admin/member? — **STILL OPEN.** Verified: `ChannelMemberRole` is
   `'owner' | 'admin' | 'member'` and nothing else. This is the only genuinely
   open question in this list.
4. ~~**Message retention**~~ — **RULED by CireSnave 2026-09-02: none.** The
   question was dissolved rather than answered; see ROADMAP "Retention — RULED".
5. ~~**Rate limiting**~~ — **ANSWERED: built.** Per-entity limiter applied in
   the message and entity routes.
6. ~~**Encryption at rest**~~ — **ANSWERED: built, and it is not the same thing
   as sealing.** `message-encryption.ts` encrypts rows under
   `FAM_SERVER_SECRET`, so the server reads everything; `sealing.ts` is
   end-to-end, so it reads nothing. **Say under whose key.**

---

## Detailed Codebase Analysis (from Planner)

### File-by-File Migration Guide

#### broker.ts (273 lines)

**Reusable:**
| Lines | Component | Strategy |
|-------|-----------|----------|
| 12-33 | SQLite setup (WAL, busy_timeout) | Keep — identical pattern |
| 35-59 | Table creation | Replace — new schema |
| 61-79 | Stale peer cleanup | Modify — heartbeat timeout instead of PID check |
| 83-124 | Prepared statements | Replace — new queries |
| 127-134 | `generateId()` | Modify — UUIDs for entities/channels |
| 152-158 | `handleHeartbeat` | Keep pattern — update `last_seen` |
| 228-271 | `Bun.serve()` HTTP server | Keep — reuse server structure |

**Critical Risks:**
1. Race condition (lines 143-146): `SELECT` → `DELETE` → `INSERT` not atomic
2. Process check Unix-only (lines 67, 189-190): `process.kill(pid, 0)`
3. No transaction for message send + delivery
4. Stale cleanup runs during listing (line 194)
5. No authentication

#### server.ts (555 lines)

**Reusable:**
| Lines | Component | Strategy |
|-------|-----------|----------|
| 45-56 | `brokerFetch()` helper | Keep — generic HTTP client |
| 58-65 | `isBrokerAlive()` | Keep — health check pattern |
| 101-117 | `getGitRoot()` | Keep — useful for entity context |
| 144-165 | MCP server setup | Keep — identical structure |
| 429-441 | Channel push notification | **Direct reuse** — core Claude Code integration |

**Critical Risks:**
1. Broker auto-launch assumes localhost (line 74)
2. Polling every 1s (line 40) — replaced by WebSocket push
3. Unix-only TTY detection (lines 122-128)
4. No reconnection logic

#### shared/summarize.ts (140 lines)

- Uses OpenAI gpt-5.4-nano — make pluggable
- Keep git utilities (`getGitBranch`, `getRecentFiles`) — move to `src/utils/git.ts`

#### cli.ts (161 lines)

- `lsof` Unix-only (line 137) — replace with cross-platform
- Hardcoded `from_id: "cli"` — no auth
- Complete rewrite needed

### Specific Code Reuse Opportunities

**Channel Push (server.ts:429-441) — DIRECT REUSE:**
```typescript
await mcp.notification({
  method: "notifications/claude/channel",
  params: {
    content: message.text,
    meta: {
      from_entity: message.from_entity,
      channel: message.channel_id,
      sent_at: message.sent_at,
    },
  },
});
```

**HTTP Client Pattern (server.ts:45-56) — DIRECT REUSE:**
```typescript
async function famFetch<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${FAM_SERVER_URL}${path}`, {
    method: body ? "POST" : "GET",
    headers: { "Content-Type": "application/json", ...authHeaders },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error(`${res.status}: ${await res.text()}`);
  return res.json();
}
```

**SQLite Setup (broker.ts:31-33) — DIRECT REUSE:**
```typescript
const db = new Database(DB_PATH);
db.run("PRAGMA journal_mode = WAL");
db.run("PRAGMA busy_timeout = 3000");
db.run("PRAGMA foreign_keys = ON");  // ADD THIS
```

**MCP Server Boilerplate (server.ts:144-165) — MODIFY & REUSE:**
```typescript
const mcp = new Server(
  { name: "fam", version: "1.0.0" },
  {
    capabilities: {
      experimental: { "claude/channel": {} },
      tools: {},
    },
    instructions: `You are connected to the Federated Agent Messaging (FAM) network...`,
  }
);
```

### Platform-Specific Fixes Needed

| Current Code | Problem | Fix |
|--------------|---------|-----|
| `broker.ts:67,189` `process.kill(pid, 0)` | Unix-only PID check | Replace with heartbeat timeout: `last_seen < now - 60s` |
| `server.ts:124` `ps -o tty= -p ${ppid}` | Unix-only TTY detection | Remove — not needed for FAM |
| `cli.ts:137` `lsof -ti :${PORT}` | Unix-only port→PID | Use heartbeat timeout or track broker PID in file |
| `server.ts:74` `Bun.spawn(["bun", script])` | Auto-launch assumes local | Config-driven: `FAM_SERVER_URL` env var |

### Resolved Design Decisions

| # | Question | Recommendation |
|---|----------|----------------|
| 1 | OAuth providers for v1 | **Both Google and GitHub** — max compatibility |
| 2 | Key algorithm | **Ed25519** — small, fast, widely supported |
| 3 | Argon2id implementation | **WASM** (`@noble/hashes`) — best performance in Bun |
| 4 | Channel permissions | **Simple for v1** (owner/admin/member) — extend in v2 |
| 5 | Message retention | **Configurable, default 90 days** + manual purge |
| 6 | Rate limiting | **Per-entity token bucket** (100 req/min) + per-IP (1000 req/min) |
| 7 | Encryption at rest | **Per-message optional** — encrypt `text` field if needed |
| 8 | WebSocket vs SSE | **WebSocket** — needed for bidirectional communication |
| 9 | Entity ID format | **`name@account` for v1**, add server in v2 federation |
| 10 | Push endpoint | **WebSocket (server-managed)** for v1; webhook for v2 |

### Risk Assessment

**High Risk:**
| Risk | Mitigation |
|------|------------|
| Unix-only commands | Use heartbeat timeout instead of PID checks |
| Race condition in register | Use `INSERT OR REPLACE` with transactions |
| No authentication | Implement three-layer auth before other features |
| Polling architecture | Design WebSocket push from day 1 |
| Auto-launch assumes localhost | Config-driven server URL |

**Medium Risk:**
| Risk | Mitigation |
|------|------------|
| OpenAI hard dependency | Make summary provider pluggable interface |
| No message encryption at rest | Add optional AES-256-GCM |
| No rate limiting | Token bucket per entity/IP |
| WebSocket connection management | Dedicated connection manager |

### Directory Structure for FAM

```
fam/
├── src/
│   ├── db/
│   │   ├── schema.ts          # SQLite schema + migrations
│   │   ├── index.ts           # Database connection + prepared statements
│   │   └── repositories/      # AccountRepo, EntityRepo, ChannelRepo, MessageRepo
│   ├── crypto/
│   │   ├── keys.ts            # Ed25519 key pair generation
│   │   ├── encrypt.ts         # Argon2id + AES-GCM for private key storage
│   │   └── challenge.ts       # Nonce generation + signature verification
│   ├── auth/
│   │   ├── oauth.ts           # OAuth 2.0 flows (Google, GitHub)
│   │   └── tokens.ts          # Token storage + validation
│   ├── types/
│   │   └── index.ts           # All FAM TypeScript types
│   ├── server/
│   │   ├── http.ts            # Bun.serve() setup with routing
│   │   ├── websocket.ts       # WebSocket connection manager
│   │   └── routes/
│   │       ├── accounts.ts    # /accounts/authorize, /create-entity, /list-entities, /revoke-entity
│   │       ├── entities.ts    # /entities/connect, /disconnect, /status, /list, /subscribe
│   │       ├── channels.ts    # /channels/create, /join, /leave, /list, /list-members
│   │       ├── messages.ts    # /messages/send (+ WebSocket push)
│   │       └── health.ts      # /health
│   ├── adapters/
│   │   ├── mcp/
│   │   │   ├── server.ts      # FAM MCP server
│   │   │   ├── tools.ts       # MCP tool definitions
│   │   │   └── channel-push.ts # Reuse notifications/claude/channel logic
│   │   ├── websocket/
│   │   │   ├── client.ts      # Generic agent WebSocket client
│   │   │   └── handler.ts     # Message handler interface
│   │   ├── cli/
│   │   │   ├── commands/      # All FAM CLI commands
│   │   │   └── keychain.ts    # OS keychain integration (Tier 2)
│   │   └── http/
│   │       └── rest.ts        # REST API for web UIs
│   └── utils/
│       └── git.ts             # getGitBranch(), getRecentFiles()
├── tests/
│   ├── unit/
│   ├── integration/
│   └── e2e/
├── broker.ts               # OLD - keep for reference
├── server.ts               # OLD - keep for reference
├── cli.ts                  # OLD - keep for reference
├── shared/                 # OLD - keep for reference
├── DESIGN.md               # This file
├── package.json            # Updated with new deps
└── tsconfig.json           # Keep
```

### Testing Strategy

**Unit tests (bun test):**
- `src/crypto/keys.test.ts` — Key generation, sign/verify
- `src/crypto/encrypt.test.ts` — Argon2id + AES-GCM roundtrip
- `src/crypto/challenge.test.ts` — Nonce challenge-response
- `src/auth/oauth.test.ts` — OAuth flow mocking
- `src/db/repositories/*.test.ts` — CRUD operations

**Integration tests:**
- `src/server/routes/accounts.test.ts` — Full account flow
- `src/server/routes/entities.test.ts` — Entity connect/disconnect
- `src/server/routes/channels.test.ts` — Channel messaging
- `src/server/routes/messages.test.ts` — DM + channel delivery

**E2E tests:**
- `tests/e2e/mcp-adapter.test.ts` — MCP server ↔ broker
- `tests/e2e/websocket-client.test.ts` — WebSocket client ↔ broker
- `tests/e2e/cli.test.ts` — CLI commands

---

## Next Steps

1. Create `src/` directory structure (see Directory Structure above)
2. Implement Phase 0: Foundation (crypto + auth)
3. Implement Phase 1: Core Account/Entity System
4. Write tests for authentication flows
5. Implement Phase 2: Messaging
6. Add Phase 3: Transport adapters
