# FAM — Instance identity and duplicate resolution

**Status:** design, nothing built. Ruled by CireSnave 2026-09-08, after two
duplications of a running agent on the claude-peers network.

**Positions are attributed where the design changed hands.** Two of the three
policy calls here are his, one proposal of his is deliberately *not* being
built, and the record should say which is which rather than flattening the
conversation into a single voice.

All code references measured at `origin/main` `43e2498f`.

---

## ⚠️ The one sentence this document exists for

**A duplicated agent holds a copy of the key, so every cryptographic check
answers "same identity" — correctly, and uselessly.**

FAM already separates identity from connection, and does it properly: identity
is `name@account` plus an Ed25519 keypair, `/entities/connect` issues a
server-chosen nonce, `/entities/authenticate` requires a signature over it, and
`challenges` rows expire after five minutes. That is a real challenge-response
and it is the right primitive for *"are you 1234?"*.

**It cannot answer *"are you the only 1234?"*, and no amount of strengthening it
will.** A clone and its original are identical in everything a key can attest.
The question is not about identity at all — it is about **how many running
processes believe they hold one identity**, and that is a fact about processes,
which no key knows.

---

## What FAM does today

| | measured |
| --- | --- |
| `sessions.entity_id` | **no uniqueness constraint** (`schema.ts:90`) — N sessions per entity |
| `websocket.ts:41` | `entityConnections: Map<EntityId, Set<sessionId>>` — **multi-connection is designed**, and pushes fan out to all of them |
| `challenges.entity_id` | `PRIMARY KEY` (`schema.ts:100`), written `INSERT OR REPLACE` (`crypto/challenge.ts:52`) |
| generation / lease / claim | **does not exist** |
| a way to tell a client "you are a duplicate" | **does not exist** |

### ⚠️ Row three is a live availability bug, and it is worse than "flaky login"

Exactly one challenge may be outstanding per entity; a second `connect`
overwrites the first's nonce; and `/entities/authenticate` **consumes** the row.
**Measured, not reasoned** — two sequential `connect` calls for one entity, then
each authenticating with the nonce it was given:

    connect A                        200, nonce A
    connect B                        200, nonce B   (replaces A's row)
    authenticate A (correct sig)     401  "Invalid signature"      SIGNATURE_INVALID
    authenticate B (correct sig)     401  "Challenge has expired"  CHALLENGE_EXPIRED

    CONTROL: one connect, one authenticate, same key   ->   200

⚠️ **BOTH FAIL, AND BOTH ARE TOLD SOMETHING FALSE.** A's signature was valid
over the nonce A was given; B's challenge was seconds old and never expired — A
consumed it. **Neither error names the actual cause, and *"Invalid signature"* is
precisely the message that sends an operator to check their key file**, which is
the one thing that was never wrong.

**It is not a narrow race.** The two connects above were *sequential*. **Any two
overlapping `connect` → `authenticate` exchanges collide**, so the window is the
whole exchange, not an instant. An agent that restarts while a previous instance
is still holding a session can lock itself out this way.

**This is a bug independent of the rest of this document and worth fixing on its
own.** The fix is to key `challenges` by the nonce with `entity_id` as an
ordinary column, so two outstanding challenges coexist and each is consumed by
the party that was issued it. The five-minute sweep already bounds the table.

⚠️ **AND FIXING IT REMOVES THE ACCIDENTAL DETECTOR.** Today's collision is the
only thing in FAM that reacts to duplication at all. After the fix, two
instances both authenticate cleanly and nothing notices — **which is correct
behaviour and exactly why the deliberate mechanism below has to exist.** Landing
the fix without it would trade a misleading signal for no signal.

⚠️ **UPDATE — THE FIX LANDED FIRST, AND THE WARNING WENT WITH IT.** #50 merged
migration 20, and issue 48 went with it — which is where this consequence was
recorded. *(Written without a closing keyword next to the number on purpose: a
commit message quoting this line would otherwise act on it.)*
**The repair closed the issue that carried the warning about the repair**, and
what survived was a comment inside a migration nobody greps plus this document,
which is still an open PR. The gap is now tracked as **#52**, filed after the
fact.

**The general rule, which is what this instance is worth:** *a repair that
removes an accidental detector must not land before its deliberate replacement,
or it silently reduces coverage while reading as a fix.* **And an issue is not a
durable home for a warning about the fix that closes it.**

**Row two is the constraint everything else must respect.** Multiple concurrent
connections per entity is a *feature* — a CLI and an MCP adapter attached at
once is the normal case. **Any mechanism here that reduces to "one session per
entity" breaks a working feature to fix a different problem.**

---

## Why the obvious answers do not work

### A shared secret, or a code the peer knows

Both clones know it. This is the key problem restated.

### A fresh random value, requested per connection

⚠️ **A random differs on every connection even from ONE process**, so two sockets
of a single agent look like two agents. The rule inverts: "different values ⇒
two peers" would fire constantly on the supported case.

This was CireSnave's first framing — *"a random code chosen by you in some way
linked to your most recent thoughts"* — and **the second half is the working
half.**

### A digest of the peer's own recent state

This does what the random cannot: two connections of one process read the same
memory and report the same digest; two diverged processes report different ones.
**The rule holds exactly as originally written, provided the value is *derived*
rather than *random*.**

⚠️ **But it fails at t=0, which is the moment you most want it.** Two clones that
have not yet diverged produce **identical** digests. A snapshot restored twice,
compared in the first second, is indistinguishable from one process — and that
is precisely the window in which the duplication is created.

It also requires the server to challenge both parties **simultaneously with one
nonce**, and to compare answers before either is revealed to the other.
**So it is a *confirmation* test, usable only once you already suspect a
duplicate. It cannot find one.**

---

## The mechanism

Two pieces, neither of which is a secret.

### 1. An instance id, minted at process start and never persisted

A random value the client generates when it starts and holds only in memory.

- Two connections of one process present **the same** instance id.
- A restored or relaunched process **re-runs startup and mints a new one.**

That is the whole discriminator, and it is strictly better than a state digest
because **it differs immediately, before any divergence has occurred.**

⚠️ **It does not detect a `fork()` that inherits memory.** Stated rather than
papered over: a forked child shares the parent's instance id and will look like
a second connection of one process. The duplications actually observed were
separate Claude Code processes started from the same credentials, which mint
different ids; a fork is a different failure with a different fix, and pretending
this covers it would be the more dangerous outcome.

### ⚠️ 1a. And "never persisted" is the load-bearing half, because this machine
has already produced identity-by-inheritance

A third duplication mechanism exists that **neither the instance id nor the
generation counter can detect**, and it is worth naming because the obvious
implementation walks straight into it.

**Verified locally at `43e2498f`:** `.remember/` is listed in `.gitignore`
(line 49), so it is **per-checkout, not per-session** — one directory shared by
every session whose working directory is that checkout, read into context by the
resume hook. FAM's copy holds lines like *"## 05:53 | test/channel-authorization
— Channel auth: member-kick priv-esc found via mutation"*: state written in a
voice that reads as **the current session's own**.

**FAM has one lane, so nothing collides here. That is the only reason.**

*Two lanes on this machine have reported the collision itself — a resume hook
telling two different sessions, in the first person, that each was the same named
role. Those are peer reports and are recorded as such; the mechanism they
describe is the one verified above.*

⚠️ **THE GENERATION COUNTER IS BLIND TO THIS, AND NOT BY OVERSIGHT.** Both
parties hold **legitimate, distinct** registry identities. There is no contested
claim, no second holder, nothing to fence. **The registry is right and the
BELIEF is wrong** — so a mechanism that arbitrates claims has nothing to
arbitrate.

**Which is exactly why the instance id must be minted in memory and written
nowhere.** An id persisted to a project-scoped file is inherited by the next
sibling that reads it, and **an inherited instance id is worse than none: it
makes two processes indistinguishable BY THE MECHANISM BUILT TO DISTINGUISH
THEM.** The requirement is not "avoid the disk" as hygiene — it is that the
storage must be **structurally exclusive to one session**, so a sibling *cannot*
read it rather than merely *does not*.

### 2. A generation counter on the entity — a fencing token

A new migration (the next is **20**; `CURRENT_SCHEMA_VERSION` is 19) adds a
monotonic `generation` and the instance id that currently holds it.

- `/entities/authenticate` accepts `instance_id` alongside the signature.
- **Same instance id as the current holder ⇒ no bump, no eviction.** This is what
  keeps multi-connection working: a second socket from one process is not a
  claim, it is a connection.
- **Different instance id ⇒ generation bumps, the newcomer becomes the holder,
  and the previous holder is superseded.**

**This detects rather than confirms.** It needs no simultaneity, no comparison of
thoughts, and no suspicion in advance.

---

## The three rulings

**Evict-old is the default.** CireSnave's words. The common cause is a resumed or
restarted session, where the old process is usually already dead or useless.

**The evicted process is notified, and may request a new identity — it is not
auto-renamed and not silently killed.** His call, chosen over both alternatives.

- Auto-renaming mints an identity on every duplication event, so a reconnect
  loop sprays the directory with agents nobody created deliberately, silently.
- Silent termination throws away whatever work the old process was holding.

So: **eviction carries an explicit reason, and claiming a fresh identity is a
separate action the superseded process takes if it decides it still has work.**

**Build it properly in FAM; detection-only in claude-peers.** He took the
recommendation over building an eviction mechanism into the broker that is being
replaced. The broker learns to *say* a duplicate occurred; it does not learn to
resolve one.

---

## The broker side: detection without eviction

The ruling gives claude-peers detection only, and there is a mechanism for it
that needs no server change at all — **an instance can detect its own twin using
its own successful write as the probe:**

    1. write something only this instance would write   (e.g. set_summary
       with a value containing a freshly minted instance id)
    2. the write returns success AND echoes the new value
    3. read the directory back
    4. if the row for this identity does not carry the value just written,
       the write landed on a DIFFERENT row -> a twin exists

⚠️ **Step 4 is what makes this stronger than a staleness check.** A directory
entry that is merely lagging catches up; **an entry that does not move after a
write you were told succeeded is not lag, it is a different entity.** The probe
distinguishes "stale" from "someone else" using nothing but the writer's own
acknowledged write — no nonce, no simultaneity, and **no cooperation from the
twin, which is essential because a twin that could be asked would answer
honestly and identically.**

*This shape was reported by another lane on this machine, who used it to
diagnose a stale duplicate registration that was still heartbeating — so
"last seen is recent" had established nothing.* It is recorded here because it
is the detection half of this design and it works against a broker that will
never grow a generation counter.

⚠️ **It has one hard prerequisite — an instance must be able to read its own
identity — AND THAT PREREQUISITE IS BUILT BUT NOT DISTRIBUTED.** A peer that cannot ask *"which
row is mine?"* cannot compare the row to what it wrote, so it cannot run step 4
at all.

**Corrected twice, 2026-09-09, before this document was merged.**

**First correction:** an earlier draft said a peer could not read its own id and
that diagnosis fell back to process-tree forensics. **`whoami` exists** — it
returns this instance's own `id`, `pid`, `cwd`, `git_root`, `summary`,
`registered_at` and `last_seen`. A stale *"not built"* is worse than a stale
*"done"*, since it invites somebody to build a second one, so the sentence was
replaced rather than annotated.

⚠️ **SECOND CORRECTION, AND THE FIRST ONE WAS OVER-GENERAL IN THE SAME WAY IT
CRITICISED.** I wrote *"`whoami` EXISTS on claude-peers"* — a claim about the
network. **It is a claim about MY SESSION.** Two other lanes measured it ABSENT
from their tool lists, one of them after I had reported it as a portfolio fact.

**Traced to the cause rather than left as "per-session":**

    ~/.claude.json  mcpServers.claude-peers  ->  bun ~/claude-peers-mcp/server.ts
        that file is dated 2026-07-19, and `whoami` appears NOWHERE in that
        repository's history (`git log --all -S whoami` -> empty)

    C:/Projects/fam/.mcp.json  claude-peers   ->  bun ./server.ts
        i.e. FAM's OWN copy of the broker, where `whoami` landed in FAM #35
        (`9482aad`), present on `origin/main` (5 hits; control: `set_summary`
        also 5)

⚠️ **SO ONE MCP SERVER NAME RESOLVES TO TWO DIFFERENT IMPLEMENTATIONS, chosen
by whether the working directory carries a project-level `.mcp.json`.** FAM does,
because FAM *is* the fork. Every other lane gets the July file.

**It is not version skew and it is not a per-session capability. It is two
programs with one name** — the same shape `CLAUDE.md` already documents for
`origin` meaning two different repositories in two checkouts, **and the tell was
identical both times: a missing entry in a tool list.**

**What this means for the ruling.** CireSnave's *"detection-only in
claude-peers"* is, for this piece, **already built and simply not distributed**:
the tool exists in FAM's copy. Giving it to every lane is a configuration or a
port, not a design. **That is worth knowing before anyone writes it again.**

⚠️ **AND IT SHIPS WITH A CHEAPER DETECTOR THAN THE PROBE ABOVE, which this
document should prefer.** Two refinements, both from the tool's own contract:

**1 — A SELF-IDENTIFYING SUMMARY.** `list_peers` excludes the caller, so a
summary cannot name its own address unless the instance asks. Put the id INTO
the summary and a twin becomes visible **to every other peer at a glance,
without anybody running a probe**: *the stale row's summary names an id that is
not that row's id.* No write, no read-back, no comparison — the inconsistency is
on the face of the record.

**2 — `registered_at`, NOT `last_seen`.** ⚠️ **A superseded registration keeps
heartbeating**, so *"recently seen"* does not mean *"live"*. When two rows claim
one identity, the older `registered_at` is the stale one. **This is the same
insight as the write-then-read-back probe reduced to a FIELD CHOICE** — and a
field choice is available to a reader who is not the affected instance, which the
probe is not.

So the ordering this document should recommend is: **a self-identifying summary
first** (passive, visible to others, zero cost), **`registered_at` when comparing
two rows**, and **the write-then-read-back probe only when an instance must
settle the question about itself** — which remains the one case the other two
cannot serve, because a lone instance sees no second row to compare.

⚠️ **AND THE ORDERING IS A RECOMMENDATION, NOT A DESCRIPTION OF PRACTICE.**
Measured `list_peers scope=machine`, 2026-09-09 05:4xZ:

    rows returned .................................. 17
    rows whose summary names a DIFFERENT id as own ..  0
    rows whose summary names THEIR OWN id at all ....  1   (this lane's)

**"No twins detected" and "nobody has populated the detector" are the same
reading.** The first line is what a reader takes away; the third is why they
should not. **A detector that requires voluntary adoption reports clean until it
is adopted, and the clean reading is what stops anyone adopting it** — so the
count belongs beside the recommendation, or the recommendation reads as a
convention already in use.

---

## Delivery of the notice

⚠️ **Do not invent a second notification path.** The MCP client already
classifies failures as transient or permanent and already has
`onTerminalFailure` (`adapters/mcp/client.ts:847`, consumed at
`adapters/mcp/server.ts:334`), added because *"between retries" and "finished
forever" were indistinguishable from outside* (ROADMAP, connection-retry
section).

**Supersession is a permanent classification, and that is the existing seam for
one.** A superseded client must **not** retry — an evicted process that reconnects
in a backoff loop is the ping-pong failure, where two instances evict each other
forever.

---

## What this deliberately does not do

- **It does not make multi-connection illegal.** That is a supported feature and
  the design is shaped around preserving it.
- **It does not distinguish "two paths" from "two processes" for its own sake.**
  Two paths to one peer are harmless. **The thing that hurts is two *actors*
  draining one work queue**, so the claim is attached to *authentication*, not to
  *connection*.
- **It does not detect forks.** See above.
- **It does not decide anything about federation.** A generation is local to a
  home server. What a peer server should believe about another server's
  generation is a federation question and is out of scope here.

---

## Open questions

### Flap protection — build it, and measure the floor

Two processes that both keep reconnecting will evict each other in turn.
**Ping-pong eviction is worse than the duplication it resolves**, because it
converts an invisible problem into a loud one that also destroys both parties'
sessions. A minimum hold time before a fresh claim may supersede is the remedy.

⚠️ **THE VALUE MUST BE MEASURED, NOT PICKED.** Measure the observed
restart-to-reconnect interval and set the floor above it, **stating the
measurement in the code beside the constant.** An arbitrary constant here is a
literal carrying an unstated relationship to reality — it will look principled,
it will be wrong under a workload nobody tested, and nothing will say which.

### Human-owned entities — CireSnave's call, and the code must not pre-empt it

A person's entity legitimately runs on a phone and a laptop. Under this design
those are two instances and the second evicts the first. **The likely answer is
that eviction applies to `type = 'agent'` and not to `type = 'human'` — but that
is a product call, not a mechanical one**, and it is not decided here.

⚠️ **BUILD THE POLICY AS A LOOKUP, NOT A HARDCODE.** Whatever he rules should be
a one-line change, and neither branch should be implemented in advance —
including the one that looks obviously right. **A mechanism that ships with the
likely answer baked in has answered the question while appearing to defer it.**

### In-flight work — answered, because deferring it loses the argument

Earlier drafts said messages addressed to a superseded identity *"should not"*
follow it and left the reasoning for later. **That is the deferral this project
keeps finding: the next reader reopens the question with no record of why, and
re-derives it from scratch or decides differently.** So:

**Messages follow the IDENTITY, not the process.** A message addressed to `X`
was addressed to *whoever holds* `X`. After supersession the newcomer holds it,
so undelivered messages are the newcomer's to poll — they are not forwarded to
the superseded process and they are not destroyed.

Three reasons, in order of weight:

1. ⚠️ **Forwarding would make eviction cosmetic.** The evicted process keeps
   receiving, which is precisely the state eviction exists to end.
2. ⚠️ **A superseded process is often superseded BECAUSE it is stale.**
   Forwarding hands fresh instructions to the actor least qualified to act on
   them — the failure is not that work is lost, it is that work is done twice
   by two parties with divergent state.
3. **Destroying them would be worse than either.** `/send-message` returns
   success as soon as the row exists, so the sender already holds positive
   evidence of delivery. **An ack that does not mean delivery is the worst shape
   a messaging failure can take, and it is invisible precisely because nothing
   bounces.** Retain, do not forward, do not delete.

**What IS lost: work the superseded process was holding in memory.** That is
real and it is the cost of evict-old. The ruling's mitigation is that the
process is *told*, and may claim a fresh identity if it decides the work is
worth continuing — which is a decision only that process can make.
