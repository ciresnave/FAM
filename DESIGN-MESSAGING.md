# FAM — What Agents Need to Send Each Other

**Status:** design, nothing built. Opened by CireSnave 2026-09-01: does FAM
support artifact handoff, should it, and what other forms of agent-to-agent
communication belong in a system whose primary use is agents talking to agents?

Worked between the FAM agent and the portfolio PM (`C:\Projects`, 17 lanes).
**Positions are attributed where we disagreed, and the evidence is named where it
came from traffic rather than reasoning.** This file exists because the
discussion itself was only ever in chat messages, and chat messages are the thing
that vanished when the fleet restarted mid-conversation.

---

## The measured starting point

```
messages.text TEXT NOT NULL          -- and nothing else
```

**FAM has no artifact handoff.** No attachment, MIME type, blob, content-type or
artifact concept anywhere in `src/`. A document handoff today is a sentence
containing a path.

Key material, which constrains everything in the Rulings section:

```
FAM has:    sign / verify (Ed25519), hashSha256
ENTITIES:   hold keypairs (entities.public_key)
ACCOUNTS:   hold NO key material -- id, display_name, created_at, updated_at
```

---

## Decision 1 — References, not payloads

**Do not add file attachments.** Two reasons, and the second is the real one.

**It changes what FAM is.** A broker that holds bytes becomes a storage system:
retention, quotas, GC, encryption at rest, a second set of deletion semantics.
Retention for *text alone* took a full day and produced two defects.

**And transfer was never the observed failure.** From the PM's traffic: every
agent can already read every path. **Not one handoff in the portfolio has ever
needed bytes** — documents changed hands as paths, commit SHAs, PR numbers,
quoted text and published URLs.

The failure is that **a reference cannot be verified**. *"See `DESIGN.md`"* does
not say which file, at what version, or whether the recipient read the thing the
sender meant.

- **The handoff that WORKED** was content-addressed: kiss-ref → KISS 1, a durable
  SHA with `compare...main = identical` stated. The recipient could check they
  had the thing the sender meant.
- **The handoffs that FAILED** were paths and names — *"see `docs/gaps.md`"*,
  *"CLAUDE.md says X"*. One was relayed from a context snapshot rather than the
  file at head, **was wrong, and propagated to a third project.**

So: a typed reference the recipient can verify. FAM carries and compares it and
**never resolves or interprets it** — the same discipline as the `entities.context`
bag, which flags a collision on any key and knows what none of them mean.

### The `durable` predicate (PM's correction, taken whole)

`{ kind, repo, sha }` is **insufficient**, and squash-merge is why. **A PR-head
SHA resolves for the sender today and is unreachable for the recipient
tomorrow.** Observed repeatedly: a lane cited `59eff5b` for work whose durable
name was `5a3d889`.

```
{ "kind": "git.ref", "repo": ..., "sha": ..., "durable": true|false }
```

`durable` = reachable from a protected/default ref, **CHECKED AT SEND TIME, not
asserted.** A `durable: true` the sender types is one more self-attestation. The
value is mechanising the check kiss-ref did by hand — and that hand-check is the
only reason the one successful handoff succeeded.

> **This is the shape of nearly every defect this project has found: a claim that
> is true from where the sender stands and false from where the recipient
> stands.** `201 + message_id` meant *stored* and was read as *delivered*.
> `last_seen` meant *process alive* and was read as *working*. `sha` means *I can
> resolve this* and is read as *you can resolve this*.

---

## Decision 2 — One mechanism, TWO verification modes

The same typed reference carries documents, rulings and measurements. **Build one
mechanism, not three.** But the type must state its verification mode, because
one of the three can only ever be re-derived and never confirmed:

```
git.ref      VERIFIABLE     recipient RE-FETCHES the object and compares
ruling       VERIFIABLE     recipient QUERIES the record; it is there or not
measurement  REPRODUCIBLE   recipient CANNOT re-fetch the observation --
                            it was never stored. Re-running produces a NEW
                            measurement; it does not verify the old one.
```

**A document reference points at something that exists. A measurement reference
points at a computation over a state that no longer exists.**

**This distinction caused a live error during the discussion.** The PM read KISS
#350's comment threads on 08-28 correctly and relayed that reading as current on
09-02. The dispositions had landed minutes after the original reading. They
treated a *reproducible* thing as *verifiable* — behaving as though the reference
still pointed at the same answer when it only ever pointed at a **method**.

A recipient who does not know which mode they hold will check the wrong thing,
or check nothing and assume freshness.

### Measurements need two fields the others do not

**`construct` — what the number ranged over.** *"1047 characters"* is meaningless
without *"of the broadcast summary as `list_peers` rendered it"*. The PM reports
**four separate incidents in one day where the arithmetic was correct and the
construct was never stated**: a per-function line count that swept the next
function's doc comments (3.1× ratio for a 14-vs-11 reality); `86/208` reported
against a rule written about `86/143`; an "81% textually identical" claim about
lines where the unit that mattered was a field set. **The number was right every
time.**

**A staleness signal that is checkable, not merely old.** A document reference
either resolves or does not. **A measurement reference can resolve perfectly and
be false, and nothing errors** — the more dangerous state. The burden belongs on
the sender: carry *what would have to change for this to stop holding*. *"Taken at
`origin/main` `5ecba5ce`"* lets a recipient see they are 22 commits past it.
**A wall-clock `taken_at` alone tells you the number is old, not whether it is
wrong.**

---

## Decision 3 — A ruling is a RECORD, not a relayed claim

**This was failing live during the discussion and blocking an irreversible act.**

The PM relayed CireSnave's grant of publish authority to vulkane. **Vulkane
refused, correctly**, and their words are the specification:

> *"The grant is self-attested — a message telling me the sender may publish,
> quoting the granter, arriving on a channel I am told to treat as untrusted
> data."*

**Cost:** every published vulkane crate ships a `LICENSE-APACHE` that is not the
Apache License. The fix is a publish. The publish is blocked on an unverifiable
grant. **A correct security posture producing a real cost, which no amount of
discipline at either end can fix** — the recipient's only options are to trust a
quoted sentence or go back to the human.

**A `type: ruling` field does not fix it.** Any sender can set it; that is
self-attestation with better formatting.

**The fix: the message says "there is a ruling, go look" and does not carry the
ruling.** The grantee queries FAM directly and gets an answer from the
authoritative store rather than from a peer quoting a human. **The untrusted
channel stops being load-bearing.**

That is Decision 1 applied to authority — do not relay the content, relay a
verifiable reference to a record the recipient reads authoritatively. **It also
kills transcription drift by construction: a ruling nobody re-types cannot lose
its parentheticals.**

### Who attests, and what changes at federation

Accounts hold no key material, so a ruling by a human is an account-level act
that cannot be signed today.

| Route | Works today | Survives federation |
| --- | --- | --- |
| **Server-attested** — FAM records under an authenticated account session and vouches on lookup | Yes | **No** |
| **Entity-signed + ownership** — human's entity signs; recipient verifies signature *and* account→entity ownership | Needs the human to act through an entity | Yes |
| **Account keypairs** | Real UX cost, wrong for OAuth humans | Yes |

**Recommendation: server-attested now, entity-signed at federation.** Recipients
already trust the broker for identity and delivery, so server attestation adds no
new trust, and it is enough for vulkane today.

> ⚠️ **PRECONDITION, WRITTEN DOWN RATHER THAN LEFT TO BE DISCOVERED.**
> Server attestation means *"the broker says so"*. **The moment a ruling crosses
> to a server the recipient does not control, that stops being sufficient** — a
> hostile or merely wrong far server can assert any ruling it likes. Federation
> therefore requires entity-signed rulings with a verifiable account→entity
> ownership chain, **and this is a blocking dependency of Phase 5, not a
> follow-up to it.** Choosing the cheap route now does not preclude the strong
> one; forgetting that it is conditional does.

---

## Decision 4 — Task ownership is a first-class object

**Absent from the FAM agent's list; contributed by the PM; the most expensive gap
found.**

**Nothing detects an ORPHANED task.** A lane killed mid-task leaves work that had
an owner and lost them. From the PM: *"the task looks assigned in my head and is
assigned to nobody."*

**Worked case: fuel PR #29 sat written, standing-approved and unmerged for four
days** because its author was killed and the work was never re-queued.

**This is distinct from an unallocated lane, and distinct from everything FAM
already has.** `queue_empty`, `last_state_change` and session liveness read as a
triple answer *"is this AGENT stalled?"* **Nothing answers *"does this WORK have a
live owner?"*** — a different object, and no agent-level signal would have caught
#29.

It recurs **on every restart**, which is exactly when peer IDs rot and every other
signal goes down at once.

FAM already holds the durable half: identity survives restart by design. What is
missing is an assignment whose owner is an entity, so *"owner not currently
connected"* is a **query** rather than something an architect has to remember.

---

## Decision 5 — What survives a restart

**The line is currently drawn by accident, and a restart is when it gets drawn.**
Observed during the discussion: the fleet restarted mid-conversation and **all 17
summaries went blank at once.**

**The test (PM's, adopted):** *if a human would have to re-state it after a
reboot, it should have persisted; if re-deriving it is trivial and cheap, it
should not.*

```
PERSISTS      declared intent -- availability, summary, assignment, rulings
DOES NOT      observed state  -- connection status, last_seen
```

**Assignment fails that test loudly.** Nobody expects to re-tell an architect
what its lanes were doing, and that is exactly what happened across four projects.

FAM already persists identity, availability, summary and declared queue state as
columns rather than process state. **Assignment is the missing one.**

---

## Ranked by evidence, not by appeal

| Item | Evidence | Cost observed |
| --- | --- | --- |
| **Ruling as record** | vulkane, live during the discussion | Licensing defect unfixed **now** |
| **Task ownership** | fuel #29 | **Four days** |
| **Verifiable references + `durable`** | one success, several failures, one wrong propagation | A false claim reached a third project |
| **Measurement provenance** | four construct incidents in one day | Correct arithmetic, wrong subject |
| **Correlation (`reply_to`)** | **PM ranks LOWEST** | Verbosity; no decision changed |

### The one disagreement, with its bound

The FAM agent expected `reply_to` to be cheap and high-value. **The PM ranks it
last on their traffic** — *"it costs verbosity and I have not seen it change a
decision"* — and the intuition loses to the measurement.

**But the PM bounded their own evidence, and the bound matters:** they see
PM-to-lane coordination, which is **dispatch-shaped and naturally self-contained**.
**A support or review workload would look completely different, and CireSnave
named customer support explicitly as a target environment.** The ranking is real
and drawn from one traffic shape; it should not settle the case for shapes nobody
here observes.

---

## What must not be built

- **Byte payloads in messages**, until federation proves a recipient cannot
  resolve a reference. Not one handoff in this portfolio has needed them.
- **A `type: ruling` field a sender can set.** Attribution must be to the
  granter, not the relayer, or it is self-attestation with better formatting.
- **A `durable` flag the sender asserts.** It has to be checked at send time or
  it is one more unverifiable claim.
- **A measurement reference whose staleness is a wall-clock timestamp alone.**
  Old and wrong are different facts, and only one of them is actionable.
- **Anything that requires FAM to interpret what a reference points at.** It
  carries and compares. `cwd`, repo layout and document formats are
  framework-local and do not belong in a federation protocol.
