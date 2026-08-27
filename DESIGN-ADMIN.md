# FAM Admin Console — Access Model

**Status:** browser-auth layer built (migration v9). **Both decisions below are
RULED** — see each section. Migration v10 has landed for decision 2; decision 1
turned out not to need a migration at all. The console screens are unblocked.

**Scope (from CireSnave):** a website for account holders to administer access
to their agents.

---

## The constraint that shapes everything

**The console needs no cross-account read.**

This is not a rule imposed on the design — it falls out of the data model:

- You grant **your** entity to **their** account, naming an email you already
  know. `grants(grantor_account_id, grantee_account_id, entity_id)` — the entity
  is always yours.
- A permission rule protects **your** entity from a named source. The target is
  always yours; the source is an identifier you learned because they contacted
  you.
- The directory (`scope: 'directory'`) already returns your own entities plus
  entities explicitly granted to you.

So nothing in the interface needs to **list, search, or autocomplete** anything
outside your account. That matters because those three are where cross-account
enumeration comes back: a dropdown of accounts, a type-ahead over entities, a
"did you mean…" suggestion.

A constraint that must be enforced is one someone routes around under deadline.
A constraint with nothing to route around is structural. This one is structural
— with one current exception, decision 2 below.

## Surfaces

| Surface | Reads | Writes |
| --- | --- | --- |
| My agents | own entities | create, revoke |
| Access I've given | grants where I am grantor | grant, revoke |
| Access I've received | grants where I am grantee | — |
| Rules | permission rules on my account | create, delete |
| Availability | own entities | set available/unavailable |

Every read is scoped to the account. **Verified, not assumed:** grant listing
shows only grants you are party to — a grant between two other accounts appears
in neither direction. There is a test for the third-party case specifically,
because that is the one a scoping bug would expose.

### Revocation is symmetric with granting

Granting is safe by construction — you supply the identifiers. Revoking operates
on a **list**, and a list is a read, so it could have reintroduced what the grant
path avoids. It does not: every row in either direction contains only what the
viewer either supplied themselves (`given`) or was deliberately handed
(`received`). No new information enters the account through the revocation
surface.

---

## Decision 1 — Is retention server-wide or per-account? — **DISSOLVED**

> **Ruled 2026-08-19.** Neither. CireSnave asked whether retention should exist
> at all: *"What if we notify the sender that the destination is unreachable and
> let them figure it out?"* If nothing is deleted by default there is nothing to
> configure per account, so the column on `accounts` is never needed. **A
> question answered "no" at the product level deleted schema work that both
> candidate answers would have required.**
>
> Shape proposed back to him, not yet ruled: retention OFF by default for
> DELIVERED messages; UNDELIVERED past a threshold notifies the sender and then
> discards; permanently-unreachable (entity deleted) notifies immediately.
> Delivered messages are the gap in the idea as stated — they generate no
> unreachability event, so nothing would ever trigger and they accumulate.
>
> Chasing this question found a live bug: the sweep was deleting UNDELIVERED
> mail, on by default at 30 days. Fixed separately — it is wrong under any
> retention policy.

### Original framing, kept for the record

The retention **number** needs no decision: `deleteOlderThan(days)` is one
statement bounded by a date, so 30 / 90 / 365 is an environment variable,
changeable any time, no migration.

**Per-account retention is a different question** and needs a column on
`accounts` plus a UI surface. If the answer is "server-wide forever", the
console never shows retention at all. If it is "per-account", it belongs beside
the account settings and needs the migration before build.

**Recommendation (superseded by the ruling above):** server-wide for now.
Nothing about the current product suggests one account holder needs a different
message lifetime from another.

Worth noting what this recommendation missed: it answered the question as posed
and never asked whether the feature should exist. Both options carried a cost
neither needed to carry.

---

## Decision 2 — May a grant or rule name a subject that does not exist? — **RULED: YES**

> **Ruled 2026-08-19.** Option B, and for a reason this document did not have.
> It argued from the enumeration oracle. He argued from workflow:
>
> > *"account A should be able to set up grants and rules for agents that account
> > B hasn't gotten around to creating yet. One shouldn't be forced to wait on
> > the other."*
>
> Same decision, different product. The oracle argument makes pending grants a
> security concession to be apologised for; the workflow argument makes them an
> INVITE, which is a feature. **The justification shapes the artifact even when
> the ruling is identical** — so the pending state gets designed as "access
> recorded, waiting for them", not as a degraded mode.
>
> Shipped as migration v10.

### Original framing, kept for the record

This is the one place the no-cross-account-read constraint is currently
violated, and it is a **product** question, not a schema detail:

> **May one account holder learn whether an email has a FAM account?**

Today: yes, by accident. Creating a grant answers `201` if the grantee account
exists and `404` if it does not. `grantee_account_id`, `source_entity_id` and
`source_account_id` all carry foreign keys, so the database enforces existence
regardless of route-level checks — closing this requires **dropping those three
FKs**, which is a migration.

### Option A — Reject (today's behaviour, made deliberate)

Granting to an unknown email fails and says so.

```
  Share "planner@me.example.com" with:
  ┌────────────────────────────────────────────┐
  │ alice@example.com                          │
  └────────────────────────────────────────────┘
  ✗  No FAM account for alice@example.com.
     They need an account before you can share with them.

                                    [ Cancel ]  [ Share ]
```

- **For:** honest, immediate, no dangling state. The grantor learns their typo.
- **Against:** it is an account-existence oracle. Anyone with an account can
  test any email address, one at a time, and get a definitive answer.

### Option B — Pending invite (requires dropping the FKs)

The grant is recorded and becomes live if and when that account appears.

```
  Share "planner@me.example.com" with:
  ┌────────────────────────────────────────────┐
  │ alice@example.com                          │
  └────────────────────────────────────────────┘
  ✓  Access recorded for alice@example.com.
     It becomes active when they sign in. You can revoke it any time.

                                    [ Done ]
```

- **For:** closes the oracle completely — the response is identical whether or
  not the account exists. Also better behaviour: you can set up access before
  someone joins, which is what an invite is.
- **Against:** dangling grants that may never activate; needs a "pending" state
  in the list and a rule for expiry. Typos become invisible — you get no signal
  that `alice@exmaple.com` will never activate.

**Recommendation:** Option B, with pending grants shown distinctly in "Access
I've given" and a visible expiry. The oracle is real and the invite behaviour is
independently better; the cost is one migration and one extra state in one list.

The mitigation for the typo problem is display, not validation: show pending
grants separately and stamp them with age, so `alice@exmaple.com` sits visibly
un-activated rather than silently.

---

## What is already true

Verified by test rather than asserted:

- No cross-account enumeration via `/entities/list` — `scope: 'all'`,
  `'directory'` and unset all resolve to own-account plus explicit grants.
- `scope: 'channel'` requires membership; `/channels/list-members` requires it
  for private channels.
- Own-entity existence is no longer disclosed: "not yours" and "does not exist"
  answer identically.
- Grant listing shows only grants you are party to.
- Every entity-scoped route takes identity from an authenticated session.

## What must not be built

- Any control that lists, searches or autocompletes across accounts.
- Any error that distinguishes "no such account/entity" from "not yours" —
  including validation messages and field-level hints.
- A global operator view. If one is ever needed, it is a **separate capability
  with its own authorization**, not a mode of this console.
