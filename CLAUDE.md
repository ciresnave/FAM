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

**Pre-alpha.** Runs end to end locally via `bun run bootstrap <email>`, but is
not ready to deploy. **Federation is unbuilt** — see `DESIGN-FEDERATION.md` for
the scope and `ROADMAP.md` Phase 5 for the position.

This line previously also named key rotation and per-recipient channel delivery
as unbuilt. Both shipped and ROADMAP has carried them as LOCKED for some time
(`src/scripts/rotate-key.ts` and the keyring in `src/crypto/message-encryption.ts`;
`message_deliveries` and migration 7). A stale "not built yet" is worse than a
stale "done": it invites someone to build a second one.

⚠️ **And a third item in the same sentence survived that edit.** It read *"see
DESIGN.md Phase 5, **which is the one phase with no ROADMAP section**"* — while
`ROADMAP.md:1185` carries a Phase 5 section and says, in its own text, *"for a
long time never given a ROADMAP section … **that is no longer true and this
heading has been corrected rather than left to age**."* Measured 2026-09-06 at
`58ce6196`: **all five of `DESIGN.md`'s phases now have a `### Phase N` section
in ROADMAP** (control: 9 phase sections in total). **ROADMAP corrected itself and
nothing carried the correction back up here** — four lines under the sentence
naming ROADMAP as the source of truth. The pointer now names the two documents
that hold the answer instead of asserting a fact about one of them. *Correcting
something makes its neighbour less likely to be checked, because the line reads
as handled; here the neighbour was in the same sentence.* Found by the Claim
Auditor.

`bun run bootstrap` writes to the database directly and is deliberately NOT an
HTTP route — an endpoint that mints account credentials is an authentication
bypass by construction. Do not "helpfully" expose it as one.

Auth IS now enforced: entity-scoped routes call `requireEntitySession` and take
identity from the session, never from a body-supplied `entity_id`. When adding
a route that acts on behalf of an entity, use that helper — do not read
`entity_id` from the body. `/entities/connect` and `/entities/authenticate` are
the only exceptions, because they establish the session.

Do not add a session-authentication implementation — an inline check that
happens to agree today is a second answer waiting to drift.

⚠️ **This paragraph said "There is exactly ONE session-authentication
implementation" and that was FALSE. There are two, and the second is an inline
check, and it had already drifted.** `requireEntitySession`
(`src/server/middleware/auth.ts`) serves every entity-scoped HTTP route. The
**WebSocket upgrade** in `src/server/http.ts` reads the session table itself and
decides independently. Measured 2026-09-09 at `66892b59`: the HTTP path
distinguishes a **superseded** session from an invalid one and says so; the
upgrade path answered `Invalid session` to both — *the exact defect #53 was
written to fix, alive one path over, in the branch this sentence said did not
exist.* Fixed at the site; **the two implementations remain two**, and unifying
them behind a shared classifier is tracked separately.

*The comment at the upgrade site read "uses the shared server context — single
source of truth". True of the DATA, and read for weeks as a statement about the
LOGIC. Sharing a table is not sharing a decision.*

⚠️ **And the enumerator's domain does not cover it.**
`src/server/__tests__/integration.test.ts` enumerates every registered route and
fails if an entity-scoped one answers anything but 401 to an unauthenticated
call, so **a new ROUTE cannot default into being untested.** A WebSocket upgrade
is not a registered route. `src/server/__tests__/websocketUpgradeAuth.test.ts`
covers that path instead, and it exists because deleting the upgrade's
entity-ownership check once left 787 tests passing. **When you add an
authenticated path that is not a route, the enumerator will not notice; say
where its guard lives.**

## Repositories and remotes — READ BEFORE PUSHING

Two checkouts on this machine share ancestry, and their remote naming differs.
`origin` does NOT mean the same thing in both. This has caused two near-misses;
check `git remote -v` before any push you have not made before.

**`C:\Projects\fam` — this repo, FAM.**

| Remote | Target | Notes |
| --- | --- | --- |
| `origin` | `ciresnave/FAM` | Canonical. Push here. |

**`~/claude-peers-mcp` — the claude-peers broker checkout (separate clone).**

| Remote | Target | Notes |
| --- | --- | --- |
| `origin` | `louislva/claude-peers-mcp` | **UPSTREAM — a third party's repository. Never push here.** |
| `fam` | `ciresnave/FAM` | Where broker work is archived. Push here. |

This is the one asymmetry to hold in mind: `origin` is *ours* in `C:\Projects\fam`
and *someone else's* in `~/claude-peers-mcp`. Both are conventional in isolation —
`origin` pointing upstream is normal for a fork — but a bare `git push` in the
broker checkout targets Louis Arge's project. Push explicitly by remote name
there.

`ciresnave/claude-peers-mcp` (the pre-rename fork) was **deleted 2026-08-20**.
Before deletion, the broker branches `fix/preserve-undelivered-messages` (the
code currently running), `fix/cross-platform-support` (its rollback target) and
`fix/retention-and-indexes` were archived to `ciresnave/FAM`, since none was
reachable from FAM's `main`. All three are verified present there.

**These three branches are RETAINED ON PURPOSE and are not debris. Do not
delete them, and do not merge them.** All three fork from `640183f` (pre-rename)
and every one is strictly superseded — measured 2026-08-27 at `c5e1436` by
`git diff origin/main origin/<branch> -- broker.ts server.ts cli.ts shared/`.
The only lines they hold that `main` lacks are the *originals* of code `main`
has since replaced, which is what being superseded looks like from a diff. In
`fix/cross-platform-support` that includes
`DELETE FROM messages WHERE to_id = ? AND delivered = 0` on peer eviction — the
destroys-undelivered-mail bug itself, kept because that branch is the rollback
target for the broker that is actually running.

They exist because the repository holding them was deleted, so they have no
other home. A sweep that subtracts merged-PR heads will surface all three every
time: they were never PRs, and a tree diff cannot tell "main moved on" from
"never merged". That is a true observation with a settled answer, recorded here
so the answer does not have to be re-derived.

⚠️ **And it is now re-derivable by a PROGRAM, not only by whoever read this
paragraph.** `.github/retained-branches.json` carries the same three branches in
machine-readable form, and `src/__tests__/retainedBranches.test.ts` fails if the
two disagree in either direction. **The category a sweep matches on is "merged,
no open PR"; the property that matters is "has no other home"; and those come
apart on exactly these three.** A sweep that reads the datafile can tell them
apart. **One that does not, cannot — and the file protects nothing by itself.**
An exception documented on the protected side and enforced on the acting side is
a hope with a filename, so the second half belongs to whoever owns the sweep.

Dead remotes pointing at the deleted repo have
been removed from both checkouts — every configured remote now resolves.

## Architecture — FAM (`src/`)

- `src/db/` — SQLite schema, versioned migrations, repositories. `SCHEMA_SQL` is
  the frozen v1 baseline; post-v1 changes go in the `MIGRATIONS` registry, never
  by editing the baseline.
- `src/crypto/` — Ed25519 identity keys, X25519 encryption keys, Argon2id +
  AES-256-GCM (Advanced Encryption Standard, 256-bit key, Galois/Counter Mode)
  key files, nonce challenge-response.

  **Two different message encryptions live here and they are not substitutes.
  Always say under whose key.** `message-encryption.ts` encrypts rows at rest
  under a key derived from `FAM_SERVER_SECRET`, so **the server reads every
  message** — it defends a stolen disk. `sealing.ts` is end-to-end under the
  recipient's X25519 key, so **the server reads nothing** — it defends against
  the relay. A claim that "messages are encrypted" is ambiguous between a
  property FAM has and one it did not have until `33dd549`.

  *The word "always" is deliberate, and a hedged version would reintroduce the
  defect the rule was written for.* `message-encryption.ts` was read as providing
  confidentiality from the relay for as long as it existed, because its *file
  name* matches that requirement and nothing forced the question. "Usually say
  under whose key" leaves exactly the gap the omission already walked through
  once.

  **Both key custodies are now client-side, so confidentiality AND authenticity
  are unconditional.** `POST /entities/encryption-key` accepts a PUBLIC key
  only, so FAM never holds an X25519 private half. And
  `POST /accounts/create-entity` **refuses** a request without a client-supplied
  `public_key` — *"the entity generates its own Ed25519 key pair and sends the
  public half. The server no longer mints identity keys"*
  (`src/server/routes/accounts.ts:231`). `src/adapters/cli/provision.ts:56`
  generates both pairs locally and transmits neither private half.

  ⚠️ **THIS PARAGRAPH SAID THE OPPOSITE, AND SAID THE FIX WAS "NOT YET BUILT".**
  It read: *"`POST /accounts/create-entity` GENERATES the Ed25519 identity pair
  server-side, so the server held that private key once … authenticity assumes
  the server was honest when the entity was created. The fix is client-generated
  identity keys at creation; it is recorded in `DESIGN-FEDERATION.md` and not yet
  built."* **It is built.** Found 2026-09-09 by standing FAM up for the first
  time: the route rejected an entity-creation request, and the rejection was the
  correction.

  ⚠️ **A stale "not yet built" is the expensive direction, and this file says so
  four paragraphs above about a different claim.** It invites the next person to
  build a second implementation of something that already exists — and with FAM
  being rewritten into Synapse, the next person is a rewrite. **A stale
  "done" costs a wasted check; a stale "not built" costs the work.**

  *And note the shape of the refusal, which is the part worth keeping:* the route
  does not fall back to minting a key when none is supplied. Its own comment
  rejects that — *"client key if supplied, server key otherwise"* is the
  disjunction shape, and it would have **silently restored the property being
  removed** for exactly the callers who had not been updated, which are the ones
  who would not notice.

  **Entity identity keys are Ed25519 and cannot encrypt**, which is why the
  X25519 key exists rather than being reused. Do not reach for the Ed25519→
  X25519 conversion to avoid the second key: measured on Bun 1.3.14, an Ed25519
  public key *imports* as X25519 and *derives 32 plausible bytes*, while its own
  private half is refused — so you get ciphertext the recipient can never open,
  and every check short of testing agreement passes.

  *Also absolute on purpose.* The conversion is not wrong-in-most-cases, it is
  wrong-with-a-passing-smoke-test: the failure appears only when the recipient
  tries to read, which is after the message is gone. A rule with an escape
  hatch here is a rule that will be escaped by whoever is trying to avoid a
  migration, which is the exact person it is addressed to.
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

FAM defaults to port 7900 and the broker to 7899, so both can run at once —
that is what makes a migration reversible rather than a single attempt.

Endpoint defaults live in `src/config.ts`; do not restate them as literals.
They were previously hand-written in fourteen places, which is how the two
projects came to share a port. `src/__tests__/config.test.ts` fails if 7899
reappears anywhere under `src/` outside that one file.

## Toolchain

Bun's version is not pinned anywhere. `bun test` and `bun run test` are NOT
the same instrument on this machine: Bun ignores bunfig's `[test] timeout`, so
bare `bun test` shows three spurious failures. Two commands that look
interchangeable and are not — worth remembering before CI exists to disagree
with you.

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

**Before you push, run `bun run gates`.** It reads
`.github/workflows/test.yml`, extracts the commands CI runs, and runs those —
so it has no list of its own to drift. Adding a step to CI adds it locally with
no second edit.

This exists because of a specific failure. Commit `d0819a9` was pushed with a
green test suite and a broken typecheck, and CI caught it in twelve seconds. The
suite had been run; `tsc` had not. **Local verification was a strict subset of
the gate, and the gap was invisible because everything that was run passed.**
That is the second instance of one shape here — the first is `bun test` below —
and in both a hand-invoked command answered a narrower question than CI's while
looking like success.

`bun run gates` refuses rather than guesses: a step it cannot parse aborts the
run, because a local gate that silently skips what it cannot read is worse than
none.

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
