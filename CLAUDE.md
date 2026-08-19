---
description: Use Bun instead of Node.js, npm, pnpm, or vite.
globs: "*.ts, *.tsx, *.html, *.css, *.js, *.jsx, package.json"
alwaysApply: false
---

# FAM — Federated Agent Messaging

Agent-framework-agnostic messaging for agents, humans, and tools. A fork of
`claude-peers-mcp` by Louis Arge, substantially rewritten. See `DESIGN.md` for
architecture and `ROADMAP.md` for phased status — ROADMAP.md is the source of
truth for what is done and what is not.

**Pre-alpha. Not deployable.** Authentication is implemented but NOT enforced on
`/messages/*`, `/channels/*`, `/entities/list` or `/entities/status` — those
routes trust a body-supplied `entity_id`. There is also a cross-provider account
takeover path in the OAuth callback, and no local bootstrap (OAuth is the only
way to create an account). Do not describe FAM as working end to end.

## Architecture — FAM (`src/`)

- `src/db/` — SQLite schema, versioned migrations, repositories. `SCHEMA_SQL` is
  the frozen v1 baseline; post-v1 changes go in the `MIGRATIONS` registry, never
  by editing the baseline.
- `src/crypto/` — Ed25519 keys, Argon2id + AES-256-GCM key files, nonce
  challenge-response, optional message encryption at rest.
- `src/auth/` — OAuth 2.0 (Google, GitHub), HMAC token hashing.
- `src/server/` — `Bun.serve()` HTTP + WebSocket, rate limiting, permission
  matrix, cross-account grants. `MessageSendService` is the single authoritative
  send path — HTTP and WebSocket both delegate to it, so put enforcement there
  rather than in a route.
- `src/adapters/mcp/` — MCP stdio server, pushes via `notifications/claude/channel`.
- `src/adapters/cli/` — CLI client.

Identity is `name@account` and durable across restarts; sessions are ephemeral
and separate. `availability` (declared intent) is distinct from `status`
(connection-derived). Preserve that separation.

## Architecture — claude-peers (legacy, still working)

Retained side by side during the transition. This is what currently carries
real traffic; do not delete it.

- `broker.ts` — Singleton HTTP daemon on localhost:7899 + SQLite.
- `server.ts` — MCP stdio server, one per Claude Code instance.
- `shared/` — Shared types and auto-summary generation.
- `cli.ts` — CLI for inspecting broker state.

Note FAM also defaults to port 7899, so the two cannot run simultaneously.

## Running

```bash
# FAM server (needs FAM_SERVER_SECRET; see .env.example):
bun run dev

# FAM MCP adapter:
# { "fam": { "command": "bun", "args": ["./src/adapters/mcp/server.ts"] } }

# Legacy claude-peers CLI:
bun cli.ts status
bun cli.ts peers
bun cli.ts send <peer-id> <message>
bun cli.ts kill-broker
```

## Bun

Default to using Bun instead of Node.js.

- Use `bun <file>` instead of `node <file>` or `ts-node <file>`
- Use `bun test` instead of `jest` or `vitest`
- Use `bun build <file.html|file.ts|file.css>` instead of `webpack` or `esbuild`
- Use `bun install` instead of `npm install` or `yarn install` or `pnpm install`
- Use `bun run <script>` instead of `npm run <script>` or `yarn run <script>` or `pnpm run <script>`
- Use `bunx <package> <command>` instead of `npx <package> <command>`
- Bun automatically loads .env, so don't use dotenv.

## APIs

- `Bun.serve()` supports WebSockets, HTTPS, and routes. Don't use `express`.
- `bun:sqlite` for SQLite. Don't use `better-sqlite3`.
- `Bun.redis` for Redis. Don't use `ioredis`.
- `Bun.sql` for Postgres. Don't use `pg` or `postgres.js`.
- `WebSocket` is built-in. Don't use `ws`.
- Prefer `Bun.file` over `node:fs`'s readFile/writeFile
- Bun.$`ls` instead of execa.

## Testing

Run tests with `bun run test`, **not** `bun test`.

Bun does not honour the `[test] timeout` key in `bunfig.toml`, so three
integration tests exceed the 5-second default and fail under bare `bun test`.
The `test` script passes `--timeout 60000` explicitly. A bare `bun test` will
show 3 spurious failures; that is the harness, not a regression.

```ts#index.test.ts
import { test, expect } from "bun:test";

test("hello world", () => {
  expect(1).toBe(1);
});
```

## Frontend

Use HTML imports with `Bun.serve()`. Don't use `vite`. HTML imports fully support React, CSS, Tailwind.

Server:

```ts#index.ts
import index from "./index.html"

Bun.serve({
  routes: {
    "/": index,
    "/api/users/:id": {
      GET: (req) => {
        return new Response(JSON.stringify({ id: req.params.id }));
      },
    },
  },
  // optional websocket support
  websocket: {
    open: (ws) => {
      ws.send("Hello, world!");
    },
    message: (ws, message) => {
      ws.send(message);
    },
    close: (ws) => {
      // handle close
    }
  },
  development: {
    hmr: true,
    console: true,
  }
})
```

HTML files can import .tsx, .jsx or .js files directly and Bun's bundler will transpile & bundle automatically. `<link>` tags can point to stylesheets and Bun's CSS bundler will bundle.

```html#index.html
<html>
  <body>
    <h1>Hello, world!</h1>
    <script type="module" src="./frontend.tsx"></script>
  </body>
</html>
```

With the following `frontend.tsx`:

```tsx#frontend.tsx
import React from "react";
import { createRoot } from "react-dom/client";

// import .css files directly and it works
import './index.css';

const root = createRoot(document.body);

export default function Frontend() {
  return <h1>Hello, world!</h1>;
}

root.render(<Frontend />);
```

Then, run index.ts

```sh
bun --hot ./index.ts
```

For more information, read the Bun API docs in `node_modules/bun-types/docs/**.mdx`.
