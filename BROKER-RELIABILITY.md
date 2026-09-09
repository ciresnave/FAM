# claude-peers broker — measured reliability

**Status:** measurement, no repairs. Taken 2026-09-09 against `origin/main`
`e658e792`, on an **isolated** broker (`CLAUDE_PEERS_PORT=7951`, its own
database). The fleet's broker on 7899 was never touched — verified before and
after: `{"status":"ok","peers":17}` both times.

**Why this exists.** Five distinct peer-link failures were reported on this
machine in one day, each by a lane doing something else at the time. **None was
found by measuring the broker, because the broker had never been the subject of
a measurement — only the object of designs.** This is the measurement.

⚠️ **Every axis states what healthy looks like BEFORE it runs.** A reliability
sweep with no stated expectation returns clean by default — the same defect as
*"no twins detected"* being indistinguishable from *"nobody populated the
detector"*.

---

## The mechanism, from the source

Three facts govern everything below, all in `broker.ts`:

```ts
// registration is de-duplicated by PID, and mints a NEW id every time
const existing = db.query("SELECT id FROM peers WHERE pid = ?").get(body.pid);
if (existing) deletePeer.run(existing.id);

// eviction requires POSITIVE PROOF OF DEATH — only ESRCH counts
function isProcessAlive(pid) { try { process.kill(pid, 0); return true }
                               catch (e) { return e.code !== "ESRCH" } }

// sending validates the RECIPIENT and not the SENDER
const target = db.query("SELECT id FROM peers WHERE id = ?").get(body.to_id);
if (!target) return { ok: false, error: `Peer ${body.to_id} not found` };
```

**The `peers` table knows a `pid` and a `cwd`. It has no concept of a logical
lane.** That is the root of most of what follows.

---

## Axis 0 — compatibility of the two `server.ts` implementations

**Expected (healthy):** if two programs answer to one MCP server name, they
speak the same broker protocol, or the difference is documented.

**Measured.** Endpoints called by FAM's `server.ts` versus endpoints implemented
by each broker:

```
FAM server.ts calls   heartbeat list-peers poll-messages register
                      send-message set-summary unregister          (7)
July broker has       ...the same 7, plus /shutdown                (8)
FAM broker has        ...the same 8                                (8)
```

**Verdict: compatible. FAM's `server.ts` is a drop-in against either broker** —
every endpoint it calls exists in both, and it calls no endpoint unique to FAM's.

⚠️ **And `whoami` requires no broker change at all.** It is implemented
client-side over `/list-peers` with `exclude_id` omitted, which both brokers
already support. `server.ts` says so at the call site and gives the reason: the
broker is a shared singleton daemon, so changing it would need a fleet-wide
restart, while this needs only a per-lane MCP restart.

**Consequence: distributing `whoami` is a config path plus a per-lane restart.**
Not a design question, and not a daemon restart. **This was assumed to be the
expensive option and is the cheap one.**

---

## Axis 1 — RESTART: a lane dies and returns

**Expected (healthy):** the dead lane's row is evicted within one sweep (30s),
its undelivered messages are retained rather than destroyed, and the returning
lane gets a new id.

**Measured.** Registered a real spawned process, killed it, waited 32s:

```
row for the dead lane still present?   false          evicted, as designed
poll(dead id) ->  {"messages":[{... "text":"before the death" ...}]}
lane returns:     new pid, new id (afx7e8xr vs vdc1m4o5)
send to old id -> {"ok":false,"error":"Peer vdc1m4o5 not found"}
```

**Verdict: as expected. This axis is healthy** and the reported failures are not
here.

⚠️ **One clause worth keeping: the retained message is still POLLABLE by the
dead id, and nobody will ever poll it.** `poll-messages` does not check that the
peer exists, so the row survives and is reachable in principle — but the
returning lane comes back under a different id and never asks. **The retention is
evidence, not delivery**, which is exactly what `broker.ts`'s own comment claims
for it. Nothing here is broken; the message is simply unreachable by design until
durable identity exists.

---

## Axis 2 — DIRECTIONALITY ⚠️ **DEVIATION**

**Expected (healthy):** inbound and outbound fail *together*. A peer that cannot
be reached should not be able to send either — otherwise it is *"responsive to
itself and dead to everyone"*, which no party can see from one side.

**Measured.** Took a live process whose row had been superseded (same pid
re-registered, so the old id is gone while the process lives):

```
INBOUND   observer -> the OLD id   ->  {"ok":false,"error":"Peer 1zxujd7e not found"}
OUTBOUND  the OLD id -> observer   ->  {"ok":true}
observer's inbox                   ->  [["1zxujd7e","outbound from the old id"]]
```

⚠️ **Outbound succeeds AND IS DELIVERED, from an id that does not exist.** The
recipient reads a live message stamped with a dead address — **and a reply to it
gets `Peer not found`.**

**Cause: `handleSendMessage` validates `to_id` and not `from_id`.** One
unvalidated field.

**This reproduces the reported one-way break from first principles**, on an
isolated broker, with no reference to the original incident. It is not a race, a
timing window, or a platform quirk: **it is the specified behaviour of the
code.**

⚠️ **And the asymmetry is invisible from both ends by construction.** The sender
holds `{"ok":true}` — positive evidence of success. The recipient holds a real
message. Neither is told that the return path is gone. **The only party who could
notice is someone comparing the `from_id` against the peer list, which nothing
does.**

**Not repaired here.** Validating `from_id` is a one-line change to a shared
singleton daemon, so it needs a restart of every lane's link and is therefore a
decision rather than a patch.

---

## Axis 3 — STALENESS: a cached id after rotation

**Expected (healthy):** sending to a rotated id fails loudly, and never delivers
to whoever now holds the successor identity.

**Measured:**

```
send to rotated id            ->  {"ok":false,"error":"Peer vdc1m4o5 not found"}
successor's inbox afterwards  ->  {"messages":[]}       nothing leaked
```

**Verdict: as expected, and loud.** The reported *silence* around stale ids is
therefore **not** in the send path. It is in **not sending** — a lane that
believes a peer is gone and stays quiet produces no error, no row, and no
artifact. **A decision not to send has no failure mode to observe**, which is why
that report was right and this axis is still healthy.

---

## Axis 4 — THE TWIN ⚠️ **DEVIATION, and not the one I expected**

**Expected (healthy):** two rows claiming one lane are impossible; or if
possible, `last_seen` distinguishes the live one.

**Measured.** Two live processes, different pids, same `cwd`, both heartbeating:

```
id=xx96mj6n pid=22244 registered_at=05:02:40.447Z last_seen=05:02:42.691Z
id=6zhfzv5p pid=48144 registered_at=05:02:41.567Z last_seen=05:02:42.693Z
```

**Both rows persist and both advance `last_seen`.** So:

- ⚠️ **`last_seen` cannot rank them.** Both are fresh, because both processes are
  alive. **"Recently seen" does not mean "the one you want".**
- **`registered_at` can** — it differs, and the later registration is the
  successor.

⚠️ **But the sharper finding is that my own expectation was malformed.** Two rows
with one `cwd` is *also* the entirely legitimate multi-lane case — `C:\Projects\fuel`
carries four rows and `C:\Projects\KISS` three, all distinct agents doing
different work. **So "two rows, one directory" is not evidence of a twin.**

**The broker cannot tell a twin from a second legitimate lane, because it has no
identity above the process.** `pid` and `cwd` are all it knows, and neither
identifies a *role*. A twin and a colleague are byte-identical in this schema.

**That is not a bug in the broker. It is the boundary of what a registry keyed on
processes can answer** — and it is the same finding as
`DESIGN-INSTANCE-IDENTITY.md` reaches from the other direction: **a correct
registry cannot repair a false belief about which row is yours.**

---

## Summary

| axis | verdict |
| --- | --- |
| 0 · compatibility | **healthy** — drop-in; `whoami` needs no broker change |
| 1 · restart | **healthy** — evicted in 30s, messages retained-but-unreachable |
| 2 · directionality | ⚠️ **DEVIATION** — outbound succeeds from a dead id, delivered, unrepliable |
| 3 · staleness | **healthy** — loud refusal, nothing leaks to the successor |
| 4 · the twin | ⚠️ **DEVIATION** — `last_seen` cannot rank; and the schema cannot tell a twin from a colleague |

**Two of five reported failure modes reproduce as specified behaviour. Two axes
are healthy and the reports about them were about something adjacent — a decision
not to send, which leaves no artifact. One is a boundary rather than a defect.**

⚠️ **Nothing in this document is a repair, and one thing in it is a correction to
its own author: the twin expectation was wrong before it was measured.**
