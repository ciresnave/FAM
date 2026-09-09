# FAM → Synapse: what the rewrite must carry, and what it must not inherit

**Status:** handover note. **FAM is being retired and rewritten as part of Synapse** — ruled by
CireSnave 2026-09-09, verbatim: *"FAM is going away and will need to be rewritten as part of
Synapse. The fact that FAM has an MCP server means \*nothing\* in the long run."*

This file exists because **the code is being discarded and the measurements are not.** Everything
below was measured on 2026-09-09 against `origin/main` `7978588`, with a live server on port 7910
driven by non-Claude MCP clients — the first time FAM had been stood up and talked to by something
that was not Claude Code.

**A finding recorded is cheap; a finding re-discovered is not.** Four of the five items here are
traps the rewrite can inherit for free if nobody writes them down.

---

## 1. The injection layer is the thing FAM has that nothing else does

**The question that started this:** how does FAM get an incoming message into a *running* agent's
context? Not "move bytes between processes" — that is a transport, and Synapse already has one.

**The mechanism, in full:**

    FAM server
      -> WebSocket                 src/adapters/mcp/client.ts        holds the socket
      -> push handler              src/adapters/mcp/channel-push.ts  opens, verifies, renders
      -> MCP notification          method: notifications/claude/channel
      -> stdio                     src/adapters/mcp/server.ts        StdioServerTransport
      -> the agent's MCP client

Measured absent, so nobody re-searches: no file watching (`watchFile` 0, `fs.watch` 0,
`chokidar` 0), no hooks, no writing to the agent's stdin. Control: `StdioServerTransport` 2 sites.

⚠️ **The delivery half is not the hard half. The hard half is that something on the other end has
to splice the payload into a running loop, and that is not in this repository.** FAM's injection
works because Claude Code subscribes to that notification and renders it. Any runtime can receive
it; whether it *does anything* with it is the runtime's problem.

---

## 2. ⚠️ THE CAPABILITY IS NEGOTIATED, NOT A PRIVATE METHOD NAME — reproduce this

`notifications/claude/channel` appears **0 times** in `@modelcontextprotocol/sdk` (controls:
`notifications/message` 8, `notifications/tools/list_changed` 10). It is an extension.

**But it is declared at handshake.** The `initialize` result carries:

    "capabilities": { "experimental": { "claude/channel": {} }, "tools": {} }

**Confirmed independently by two clients in two languages** — a raw stdio JSON-RPC client and a
stock Python `mcp` 2.2.0 client, which now derives its binding as `"notifications/" + key` instead
of hardcoding the method name.

> **Requirement on the rewrite:** a push channel must be a **declared capability, discoverable at
> handshake**, not a method name a client has to be told about out of band. The difference is
> whether a foreign client can *negotiate* with the transport or must *special-case* it.

⚠️ **One measured constraint on that pattern:** the Python MCP SDK fixes `notification_bindings`
at `ClientSession` **construction**, before the handshake. So discovery cannot drive registration
inside one session — it needs a reconnect. **A capability that can only be acted on after
reconnecting is weaker than it looks, and a rewrite can do better by advertising out of band as
well.**

⚠️ **And the two SDKs disagree about unknown notifications, which is a delivery hazard in itself.**
The TypeScript SDK has a catch-all `fallbackNotificationHandler`; the Python SDK has none — an
unbound method reaches `logger.debug("dropped %r")` at `client/session.py:1452-1462` and returns.
**At DEBUG level, so the drop is silent on the client too, not only to the peer.**

---

## 3. The seam — read this as a SPECIFICATION, not as an argument

Measured. The injection layer's entire dependency on the transport is **three subscriptions**:

    channel-push.ts:118   client.onMessage(…)
    channel-push.ts:119   client.onUndeliveredMessages(…)
    channel-push.ts:120   client.onInvitation(…)

plus one **payload** type — `{type, from, channel, to, text, sealed, timestamp, message_id, refs}`
— which describes a *message*, not a socket. `channel-push.ts` imports nothing from `ws`, opens no
connection, and names no URL.

**So: those three callbacks and that payload are the interface the rewrite must provide.**

⚠️ **AND THE VALUE SITS ABOVE THE SEAM, NOT AT IT. This is the list a rewrite loses for free:**

| above the seam | what it does | where |
| --- | --- | --- |
| sealing | end-to-end under the recipient's X25519 key; the relay reads nothing | `crypto/sealing.ts` |
| identity resolution | the directory key is the relay's WORD; a vouched chain that disagrees **refuses** | `messaging/senderIdentity.ts` |
| replay suppression | a windowed seen-store, recorded only after a message OPENS | `adapters/cli/seenMessages.ts` |
| the vouched-key chain | account-signed vouchers, so `sender_vouched` is a fact and not a hope | `crypto/voucher.ts` |

⚠️ **Synapse provides none of these.** A transport swap is cheap; **re-earning this layer is not,
and it will not announce itself as missing** — messages will flow, and `sender_vouched` will simply
never be false.

⚠️ **One caveat on the seam itself:** the payload type is *named* for the transport
(`WebSocketMessagePush`) and **has drifted from the wire before** — `types/index.ts:388` records the
server sending `sealed` while the type denied it, and a reader of the type concluded the signal did
not exist. **Name the rewrite's payload for the message, not the pipe.**

---

## 4. ⚠️ TWO DESIGN TRAPS, MEASURED HERE, INHERITABLE FOR FREE

### 4a. THE ACK MUST BELONG TO THE RECEIVER

FAM acknowledges delivery **on the pushing side**. `channel-push.ts` called `markDelivered`
immediately after emitting an MCP notification.

⚠️ **An MCP notification carries no acknowledgement by protocol — no id, no response. So a
resolved `notification()` means "written to the pipe".** The adapter can detect a **dead** pipe (it
raises `EPIPE`) but **not a live pipe that nobody is reading.**

**Measured consequence:** a client that authenticated, completed `initialize`, and registered no
handler **consumed and permanently destroyed its own backlog.** Controlled pair, same clock, one
variable: a listener *with* a prior capability-probe connection never received message 3; *without*
one, message 5 arrived intact. **Silent on both sides** — the SDK dropped it at `logger.debug`, and
FAM had already acked.

**FAM's own server states the correct contract in prose** and the client half implemented the
opposite (`server/routes/entities.ts:153`): *"the client must acknowledge via `/messages/delivered`
after processing."*

> **Requirement on the rewrite:** the receiver acknowledges, and the transport must give it
> something to acknowledge WITH. FAM acked on the sender's side because the transport gave it
> nothing better. **Synapse is being written from scratch and can simply not make that choice.**

*Partially mitigated in FAM (`#66`): an UNREADABLE message is no longer acked, so a sealed message
whose key arrives later survives. The measured case — a live pipe nobody reads — is unfixable
inside the adapter and remains open.*

### 4b. A GUARD WRITTEN ON ONE BRANCH AND NOT ITS SIBLING

**Four instances measured in this repository in a single day:**

| the guarded branch | the unguarded sibling |
| --- | --- |
| `requireEntitySession` distinguishes a superseded session | the WebSocket upgrade said `Invalid session` (`#64`) |
| `handleMessage` opens the sealed envelope | `handleUndelivered` pushed it raw (`#66`) |
| `WebSocketMessagePush` declares `sealed` | `undelivered_messages` did not (`#66`) |
| `config.test.ts`'s sweep had no vacuity floor | every guard written after it had one (`#59`) |

⚠️ **All four were invisible for the same reason: nothing had ever connected to FAM that was not
Claude Code.** A second client is not a nice-to-have — **it is the instrument that makes
sibling-branch divergence observable at all.**

> **Requirement on the rewrite:** where one decision has two call paths, **leave one branch to
> guard.** `#66` does this — the open-and-verify logic became a single method both paths call,
> rather than a guard copied into the second one. And **test with a foreign client from the start**,
> because the native client's habits hide the divergence.

---

## 5. ⚠️ A NAMING TRAP THAT FOOLED THREE PARTIES INDEPENDENTLY

    ~/.fam        the credentials DIRECTORY
    ~/.fam.db     the DATABASE, and the default FAM_DB_PATH

**Three separate agents measured `~/.fam`, found it empty, and stated the conclusion "FAM has never
been run on this box."** Measured: `~/.fam.db` dated 2026-08-17 holds **12 tables, 14 accounts, 13
entities, 2 channels, 4 messages** — at `schema_version` **1 of 21**.

⚠️ **Three independent parties making the same error is a property of the names, not three lapses of
attention.** And it had a hazard attached: **`~/.fam.db` is the default, so "just start it" would
have run 20 migrations over somebody's live messages.**

> **Requirement on the rewrite:** do not let the config directory and the data store differ by a
> suffix. And do not migrate a database found at a default path without saying what was found.

---

## 6. First-run steps that are in no document

Recorded because whoever writes FAM into Synapse will hit them. **Not being fixed** — polish on a
retiring system.

- **`fam auth` cannot complete (`#44`), and it is the ONLY supported path to a first entity.**
  `bootstrap` mints an account token and *nothing consumes it*: `fam entity create` →
  `getAccountToken()` → `loadCredentials()` throws *"No credentials found. Run `fam auth` first"*.
  **Standing FAM up required hand-writing `~/.fam/credentials.json` with
  `{account_token, active_entity_id:"", entities:[]}`.**
- **The MCP adapter's fatal message routes the reader to OAuth** when the offline `bootstrap` path
  exists in the same repository. That is the step where someone concludes FAM needs a hosted
  account and stops.
- **`FAM_CLI_SERVER_URL` is documented in `.env.example` and read by nothing** (0 sites; the CLI
  reads `FAM_SERVER_URL`, 8 sites). A newcomer following the example file gets the 7900 default and
  a cold port.
- **`fam send <target> <message>` cannot work as documented.** `parseArgs` returns
  `positional.slice(2)`, so the target is consumed as `subcommand` before the handler reads
  `positional[0]`. **The usage string printed on failure is itself the failing form.**

---

## 7. What was demonstrated, and what was not

**Demonstrated, against a live server:** a stock Python MCP client with no Anthropic dependency
called `fam_send_message` and the message was accepted, sealed. **The same message arrived in a
second non-Claude process** as `notifications/claude/channel`, **opened** — `sealed: true` with the
plaintext in `content`. Challenge-response, session, WebSocket, the real queue, and sealed
decryption were all exercised.

⚠️ **NOT demonstrated: an agent.** There is **no LLM behind any of those clients.** Five non-Claude
MCP *clients*, zero non-Claude *agents*. **This is the pipe, not the capacity plan**, and the
distinction is the difference between "the transport works" and "the work can move off Claude".
