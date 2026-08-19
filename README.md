# FAM — Federated Agent Messaging

Agent-framework-agnostic messaging for agents, humans, and tools. Durable
identity, cross-account authorization, and a push-first delivery model — so
agents built on different frameworks, and the people supervising them, can talk
to each other.

> ### ⚠️ Status: pre-alpha. Not production ready. Do not deploy.
>
> FAM is under active development and **cannot currently be run end to end**.
> Known gaps, documented in full in [`ROADMAP.md`](ROADMAP.md):
>
> - **Authentication is built but not enforced.** `/messages/*`, `/channels/*`,
>   `/entities/list` and `/entities/status` read `entity_id` from the request
>   body and treat it as identity. Forging a message or reading another
>   entity's history requires no token, session, or key.
> - **Cross-provider account takeover.** The OAuth callback matches accounts on
>   an email that GitHub does not verify, so a GitHub profile email can claim a
>   Google-created account.
> - **No local bootstrap.** The OAuth callback is the only path that creates an
>   account, so a fresh clone cannot create one without registering an OAuth app.
> - **Port 7899 collides** with the claude-peers broker; they cannot both run.
>
> If you are looking for something that works today, use the predecessor —
> see [Relationship to claude-peers](#relationship-to-claude-peers).

---

## Why

Existing agent-messaging systems tend to assume every participant is the same
kind of agent on the same trusted machine, and identify participants by
whatever handle the transport happens to mint. That breaks in three ways once
real work runs on it:

- **Identity is ephemeral.** Restart a session and its address changes. Peers
  cache the old one, and messages go nowhere.
- **Failure is silent.** A send to a stale address produces no error, so
  delivery failure is indistinguishable from someone choosing not to reply.
- **Everything is trusted.** Fine on one machine owned by one person; not fine
  the moment agents span people, hosts, or organizations.

FAM addresses each directly: identity is a durable `name@account` that survives
restarts, delivery outcomes are meant to be legible to the sender, and
cross-account messaging is default-deny with explicit grants.

## Model

| Concept | Description |
| --- | --- |
| **Account** | Root identity, keyed by email, verified via OAuth 2.0. Owns entities. |
| **Entity** | An authenticated instance — `name@account`. Type `agent`, `human`, or `tool`. Stable across restarts. |
| **Session** | An ephemeral connection, established by Ed25519 challenge-response. Deliberately separate from identity. |
| **Channel** | Named group for broadcast, with owner/admin/member roles. |
| **Grant** | Cross-account permission. Absent a grant, cross-account messaging is denied. |

Authentication is three-layer: an OAuth account token proves who you are, a
passkey decrypts the local key file, and an Ed25519 private key signs a server
nonce to prove the entity is really that entity.

`availability` (declared user intent) is modelled separately from `status`
(derived from whether a connection exists) — so "I am not going to answer" is
something an agent can state rather than something a sender has to infer.

## Architecture

```
src/
  db/           SQLite schema, versioned migrations, repositories
  crypto/       Ed25519 keys, Argon2id + AES-256-GCM key files,
                challenge-response, optional encryption at rest
  auth/         OAuth 2.0 (Google, GitHub), HMAC token hashing
  server/       Bun.serve HTTP + WebSocket, rate limiting, permission
                matrix, cross-account grants
  adapters/
    mcp/        MCP stdio server — Claude Code integration via
                notifications/claude/channel
    cli/        Command-line client
```

MCP is one transport adapter, not the interface. The HTTP and WebSocket APIs
are the contract; anything that speaks them participates.

## Development

Requires [Bun](https://bun.sh).

```bash
bun install
bun run typecheck        # tsc --noEmit
bun run test             # NOT `bun test` — see below
bun run dev              # starts the server (needs FAM_SERVER_SECRET)
```

**Use `bun run test`, not `bun test`.** Bun does not honour the `[test] timeout`
key in `bunfig.toml`, so three integration tests exceed the 5-second default and
fail. The `test` script passes `--timeout 60000` explicitly.

Copy [`.env.example`](.env.example) to `.env` and set at minimum
`FAM_SERVER_SECRET`. OAuth credentials are required for account creation.

## Relationship to claude-peers

**FAM is a fork of [`claude-peers-mcp`](https://github.com/louislva/claude-peers-mcp)
by Louis Arge**, and is a substantial rewrite rather than an incremental change.
The original code is retained in this tree and still works:

| File | Purpose |
| --- | --- |
| `broker.ts` | claude-peers broker daemon — localhost:7899 + SQLite |
| `server.ts` | claude-peers MCP stdio server |
| `cli.ts` | claude-peers CLI |
| `shared/` | claude-peers shared types and summary generation |

Those files are the working predecessor. `src/` is FAM. They are kept side by
side deliberately during the transition — FAM is not yet a replacement, and
until it is, claude-peers is the system that actually carries traffic.

What FAM adds over claude-peers is identity: durable entity IDs that survive
restarts, authenticated sessions, cross-account authorization, and a federation
model. What claude-peers gives you today is zero-setup peer messaging between
Claude Code sessions on one machine. If everything talking to each other is
already inside one trust boundary, the predecessor is the better tool.

## License

MIT. See [`LICENSE`](LICENSE).

Copyright © 2026 Louis Arge — original `claude-peers-mcp`
Copyright © 2026 Eric Evans — FAM

The original copyright notice is retained as MIT requires. It applies to this
work regardless of how much of the original source remains.
