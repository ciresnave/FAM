# FAM Roadmap

Source of truth for phased development. Phases are executed in order unless
noted; each phase ships tests alongside implementation. Locked policy
decisions are marked LOCKED and must not be changed without the owner's
sign-off.

## Completed

### Phase 0 — Foundation
- Format versioning (`src/utils/versioning.ts`): every persisted/wire format
  carries `version` = FAM semver; legacy (no version) = compatible; newer =
  rejected (`UnsupportedFormatVersionError`). Applied to: EncryptedKeyFile,
  message ciphertext envelope, credentials.json, all WS frames.
- Send-path deduplication: `MessageSendService` is the single authoritative
  path for DM + channel sends (HTTP and WS both delegate). Rate limiting
  stays transport-level.
- Migration framework: `SCHEMA_SQL` frozen as v1 baseline; versioned
  `MIGRATIONS` registry with per-step transactions.

### Phase 1 — Permissions & Grants (LOCKED policy)
- Cross-account DMs: default-DENY; require active grant (target's account is
  grantor, sender's account is grantee, per target entity). Deny rules
  override grants. Grant `capabilities.can_send === false` blocks.
- Same-account DMs: default-ALLOW; explicit deny rules revoke.
- Channel sends: membership implies allow; persistence never blocked; deny
  rules filter pushes per member only. Most-specific rule wins.
- Admin API (`/admin/api/*`) with account-token auth: grants
  create/list/revoke, permission rules create/list/delete, ownership checks.
- Channel bans retired entirely (moderation = kick + set-role).

### Hardening Sprint (post-audit)
- `getById` decrypts; `getByIdRaw` for metadata-only callers.
- Admin routes parse body once; shared DB context in WS upgrade; MCP server
  uses shared versioned credential loader.
- Migration v4: permissions table rebuilt with CHECK constraints (rule-shape
  hygiene); legacy ambiguous rows normalized on upgrade.
- ISO-8601 vs SQLite datetime comparison fixed in grants/invitations expiry.
- Encryption-mode startup warning; WS inbound frame version validation;
  batch ownership validation in `/messages/delivered`.

### Phase 2 — Availability Toggle (LOCKED semantics)
- `entities.availability` (user intent) separate from connection-derived
  `status`. `unavailable` = all pushes suppressed, messages queue silently.
- Flip back to `available` = queued backlog pushed immediately (client still
  acks via `/messages/delivered`; at-least-once).
- `POST /entities/availability` (session-authenticated); availability frame
  broadcast; `fam_set_availability` MCP tool; `fam entity availability` CLI.

### Admin API Existence Oracles (partial — one class open)
Found while designing Phase 4 against the existing admin API rather than by
reviewing it. The directory-scoping ruling forbids cross-account enumeration;
an admin surface leaks it back not through a list but through an ERROR that
distinguishes "does not exist" from "exists but is not yours".

**Closed.** Your OWN entity, in `/admin/api/grants` and in a permission rule's
target, answered 403 when it existed elsewhere and 404 when it did not — so any
entity id could be probed. Both now answer 404 identically. You can only grant
or target your own, so the distinction served no caller and enumerated for an
attacker.

**Open, and a Phase 4 design question.** Existence of a FOREIGN subject is still
disclosed: grant creation answers 201 vs 404 on whether the grantee account
exists, and a permission rule does the same for its source entity/account.
- All three are enforced by FOREIGN KEYS, not by the route checks. Verified by
  removing the checks: the inserts still failed, just with a worse error.
- Closing the class therefore needs those FKs dropped — a migration — plus a
  decision on whether a rule or grant may name a subject that does not exist
  (a pending-invite model).
- "May one account holder learn whether an email has a FAM account?" is a
  product decision, not an implementation one.
- No test enshrines the current behaviour, deliberately.

**Also fixed:** `/admin/api/permissions` caught EVERY error and reported 409
Conflict, so a foreign-key violation read as "rule already exists" — which is
what made the ineffective fix above look like it had worked. Only a genuine
duplicate is a conflict now.

### Retention Compares Instants, Not Strings (LOCKED)
- `deleteOlderThan` compared `sent_at` against `datetime('now','-N days')`,
  which yields a SPACE-separated string. FAM writes the same shape, so the
  comparison happened to be right — a correctness that depended on both sides
  being spelled the same way rather than on either being correct.
- It broke for ISO-8601 (`T`/`Z`) rows on the CUTOFF DAY only: `'T'` (0x54)
  sorts above `' '` (0x20), so such a row is retained however old it is.
  Demonstrated — a row an hour older than the cutoff survived while the same
  instant in native shape was swept.
- Latent, not live: FAM writes only native-shape timestamps today. It becomes
  reachable the moment a row carries ISO-8601 — a federation import, a
  client-supplied timestamp, or a restored backup.
- `julianday()` on both sides. Same defect and same fix as the claude-peers
  broker retention sweep; found by checking whether FAM had the bug rather than
  assuming it did not.

### WebSocket Version Handshake (LOCKED)
- The client declares `version` on the `/ws` URL; the server refuses a client
  NEWER than itself during the HTTP upgrade, before the socket exists.
- Previously only inbound FRAMES were version-checked, and only once
  connected — so a newer client connected successfully and then failed frame by
  frame, staying attached in a state where nothing worked.
- **426 deliberately**, not 400 or 401. A client that cannot distinguish "you
  are too new for this server" from "your session is bad" retries forever
  against the wrong problem. Asserted by test that the two differ.
- Absent version is accepted: the versioning contract treats a missing version
  as predating versioning, so requiring it would lock out exactly the clients it
  is meant to accommodate.
- **Malformed versions are refused, not treated as ancient.** `compareSemver`
  uses `parseInt(n) || 0`, so `"not-a-version"` parses as `0.0.0` and compares
  as OLDER than everything — lenient parsing is right for ordering two versions
  FAM produced and wrong for validating one a client supplied. `isValidSemver`
  gates it.
- Mutation-verified: removing the shape check reddens the malformed-version
  test.

### Concurrent Admin Ops (LOCKED)
- Every `/admin/api/*` handler has exactly ONE `await` (`requireAccount`);
  every read, conflict check and write after it is synchronous. So concurrent
  requests interleave only at the auth boundary, and the ordering that would
  break these invariants — read, read, write, write — cannot occur in a single
  process. Recorded as a property of THIS server, not of the code: more than
  one process against the same database, or federation, makes it reachable.
- **Mutation changed the conclusion, twice.**
  - Opening a yield between check and write did NOT redden the grants test —
    `grants` carries `UNIQUE(grantor, grantee, entity)` and the database
    refuses the second row regardless of the code. That test verifies the
    CONSTRAINT, not the handler, despite reading as though it verifies both.
  - The same mutation DID redden the permissions test: 20 concurrent requests
    produced **4 duplicate rules**. That invariant was held by code atomicity
    alone.
- **Migration v8** adds a UNIQUE expression index over the permission tuple,
  using `COALESCE` on the three nullable columns — SQLite treats NULL as
  distinct from NULL in a UNIQUE index, so a plain one would permit exactly the
  duplicates it exists to prevent. Verified: with the yield re-opened AND the
  index present, the invariant holds.
- This also repairs a claim the permission resolver already relied on — its
  comment says ties at equal specificity are impossible "because the tuple is
  unique". Nothing enforced that until v8.
- Reversal of an earlier decision, deliberately: this gap was previously
  recorded-not-fixed on the grounds that a fix which cannot be born-red should
  not ship. The mutation supplied the born-red, so the reason not to fix it
  no longer applied.
- Two test-harness defects surfaced while doing this and are worth keeping:
  - A rewind test deleted only its exact `schema_version` row, so a LATER
    migration left `MAX(version)` untouched and the migration under test never
    re-ran — the test passed while exercising nothing. Rewinds now delete
    `>= target`.
  - The "v5 database" fixture omitted the `permissions` table, which a genuine
    v5 database has from migration 3. It was a database that could never have
    existed; migration 8 exposed it.
  - Migration 8 was not re-appliable until the fixed rewind test re-ran it.
    Now `IF NOT EXISTS`.

### Send-Path Atomicity (LOCKED)
- **The authorizing check and the row it authorizes are now committed
  together.** `sendDirectMessage` checked the permission synchronously and then
  `await`ed the persist; a grant revoked in that window still produced a stored
  message. Measured, not reasoned: 200/200 unforced attempts persisted a
  message under a revoked grant.
- Encryption — the only genuinely asynchronous part of sending — now happens
  BEFORE the check. `prepareStoredText` is async; `insertDirectMessage` and
  `insertChannelMessage` are synchronous, and the service wraps check-and-insert
  in a transaction with no `await` between them.
- Channel sends get the same treatment: membership is re-checked inside the
  transaction.
- Mutation-verified: restoring the `await` between check and insert reddens the
  demonstration test.
- **Test labelling convention, introduced here and to be kept.** Concurrency
  tests are marked in the file, not the PR:
  - `DEMONSTRATION` — the interleaving is forced, so it proves the window
    exists and what happens in it. It says nothing about production frequency.
    Where an ordering is forced, that is stated at the assertion.
  - `EVIDENCE` — the interleaving is not forced. Passing means the invariant
    held for the orderings that actually occurred, which is weaker than holding
    for all of them.
  Prefer an INVARIANT over a SEQUENCE: "no message exists that only a revoked
  grant would have permitted" can fail for the right reason; "revocation lands
  before the read" passes by luck.
- Related: `permissions.create` was atomic only against the event loop.
  Superseded — migration v8 makes it schema-enforced. See Concurrent Admin Ops.

### MCP Reconnect (LOCKED)
- **Permanent failures stop reconnecting.** `attemptReconnect` caught every
  error identically, so a deleted entity (404) or a revoked one (401/403) was
  retried on the same schedule as a dropped connection.
- Correcting the original framing: this was **not** a hot loop — backoff is
  exponential and attempts capped at 10. What it cost was ~17 minutes of
  pointless re-authentication, an agent unusable throughout, and then a silent
  give-up that reached only a console line.
- `request()` now throws `FamHttpError` carrying the status, so classification
  reads a field instead of parsing a message string.
- **Backoff is capped at 30s.** Uncapped doubling reached 512s by attempt 10,
  so the last retries were minutes apart — long enough that a recovered server
  went unnoticed.
- **Stopping is now observable.** `onTerminalFailure` notifies the consumer, and
  the MCP server prints what happened and that messages will not arrive.
  Previously "between retries" and "finished forever" were indistinguishable
  from outside.
- Classification is deliberately narrow: 5xx, 429 and network errors stay
  transient, so a server restart is ridden out rather than evicting every
  client.
- **The classifier is joined to reality by integration tests**, not just unit
  tests: `/entities/connect` is asserted to answer 404 for a revoked entity and
  401 for a key mismatch. Unit tests assert what 404 MEANS; without these, a
  route that started returning 500 would make the whole fix inert while every
  test still passed.
- Mutation-verified: making permanent failures look transient reddens the
  classification test.

### Encryption Toggle Safety (LOCKED)
- `FAM_ENCRYPT_MESSAGES` is a boolean over a database that may already hold rows
  written under the other setting. Both directions failed badly and neither was
  covered:
  - **ON over plaintext rows** surfaced AES-GCM's *"The provided data is too
    small"* — accurate, useless, and indistinguishable from corruption or a
    wrong key. Now raises `MessageEncryptionMismatchError` naming the flag and
    saying enabling it does not retroactively encrypt existing rows.
  - **OFF over ciphertext rows was SILENT.** The repository skipped decryption
    and returned the raw envelope JSON *as the message text*, showing a person
    ciphertext as if someone had written it. Now refused by `assertNotSealed`,
    which names the offending message id.
- The silent direction was the dangerous one and is the reason this outranked
  building anything new: it was reachable by flipping one env var on a live
  database, and produced no error to notice.
- Detection keys on the full envelope shape **including `version`**, so a user
  whose message text is legitimately JSON — including `{"iv":"x","ct":"y"}` —
  is not mistaken for ciphertext. Covered by test.
- Verified end to end across separate processes (the flag is read at module
  load) on a database holding one row from each setting: both directions now
  throw with actionable text.
- Mutation-verified: disabling the guard reddens two tests.

### Key Rotation (LOCKED)
- **Rotating `FAM_SERVER_SECRET` is supported.** It was previously documented
  as "don't" — a prohibition standing in for an unhandled case, because the
  ciphertext envelope recorded no key identity and a stored message could not
  say which secret sealed it.
- Envelopes carry `kid`: a short, non-reversible HKDF fingerprint of the
  secret. It travels in plaintext beside the ciphertext, so it is derived
  rather than being any part of the secret.
- `FAM_SERVER_SECRET_PREVIOUS` (comma-separated) holds retired secrets, kept
  ONLY so messages sealed with them stay readable. New messages always use
  `FAM_SERVER_SECRET`.
- `bun run rotate-key` re-seals every message onto the current key. Idempotent
  — rows already on the current `kid` are skipped, so an interrupted run is
  simply repeated.
- **Procedure, and step 4 is last, always:** move the old secret into
  `FAM_SERVER_SECRET_PREVIOUS`; set the new `FAM_SERVER_SECRET`; run
  `rotate-key`; only then drop the retired secret. Dropping it earlier makes
  every message still sealed with it permanently unreadable.
- An unknown `kid` raises `MessageKeyUnavailableError` naming the key and the
  fix, rather than surfacing AES-GCM's "operation failed for an
  operation-specific reason".
- Envelopes with no `kid` predate rotation, so the current secret is their only
  candidate — pre-rotation behaviour preserved.
- Verified end to end across separate processes (env is read at load), with the
  negative case as the discriminator: write under A; read with B alone FAILS
  with the named error; read with B+A succeeds; rotate; **read with B alone
  succeeds and A is no longer needed**; rerun is a no-op.
- Mutation-verified: making key resolution ignore `kid` reddens three tests.
- NOT covered: Ed25519 entity-key rotation. An entity's identity is
  `name@account` and its key proves it, but `entities.public_key` is a single
  column with no history, so rotating it invalidates in-flight challenges.
  Separate problem, not started.

### Directory Scoping (LOCKED policy)
- **No cross-account enumeration by default.** `scope: 'all'`, `'directory'`
  and an unset scope all resolve to the same visibility set: the caller's own
  account plus entities explicitly granted to it.
- Reasoning: a list of another account's entities discloses naming, structure,
  headcount and activity — not being able to message them does not make the
  directory harmless. And a scope value returning everything regardless of
  grants would make the grant system govern delivery but not visibility: two
  different answers to "may A see B", with only one enforced.
- `scope: 'online'` filters the same set rather than listing every online
  entity — otherwise it would leak exactly what `'all'` no longer does and the
  policy would be decorative.
- `scope: 'channel'` requires the caller to be a member. Membership is an
  explicit relationship, so a member may see other members across accounts.
- `/channels/list-members` requires membership for PRIVATE channels, for the
  same reason. Public channels are joinable by anyone, so their roster is not
  a secret.
- A genuine global view (operator console, migration tooling) is a SEPARATE
  capability with its own authorization. A parameter value is the wrong place
  for a privilege boundary — nothing at a call site tells a reader that one
  string is a different security posture than another.
- Revisable on evidence: a concrete consumer that needs global enumeration and
  cannot use a grant.
- Mutation-verified: restoring `getAll()` for the default scope reddens three
  tests.

### Per-Recipient Delivery (LOCKED)
- **`message_deliveries` (migration v7)**: one row per (message, recipient),
  replacing the single `messages.delivered` flag shared by every recipient of a
  channel message. One member acknowledging used to flip it for everyone, so a
  member who was offline — or paused via availability — never received it. The
  column answered "has anyone seen this?" while every caller read it as "has
  THIS entity seen this?".
- **Fan-out happens at SEND time**, to the members as they are then. A later
  joiner no longer inherits history that was never addressed to them, and a
  member who leaves keeps whatever was already queued for them.
- `markDelivered(entityId, messageIds)` now takes the acknowledging entity —
  the previous signature had no recipient at all, which is what made the bug
  possible. `getUndelivered`, `getUndeliveredCount` and `markAllDelivered` are
  all per-recipient.
- **Ownership is now "has a delivery row"** rather than a separate rule over
  `to_entity`/channel membership, so a membership change cannot retroactively
  grant or revoke the right to acknowledge a past message. A sender no longer
  "owns" their own channel message.
- Backfill imprecision, accepted deliberately: channel rows are derived from
  CURRENT membership because send-time membership was never recorded. Someone
  who has since left loses a backlog; someone who has since joined inherits
  history, carrying the old flag so anything already delivered stays delivered.
  It cannot be reconstructed, and from v7 onward the question does not arise.
- `messages.delivered` is **vestigial** — nothing writes it. The COLUMN is
  retained because migration v7's backfill reads it and SQLite cannot drop a
  column cheaply, but it is **removed from the `Message` type**, so the compiler
  refuses reads rather than a comment asking people not to. The CLI history view
  rendered "[undelivered]" from it and would have marked every message
  undelivered forever; that is the bug the omission prevents recurring. Ask
  `getUndelivered` / `getUndeliveredCount` instead.
- Mutation-verified: dropping the `recipient_entity_id` predicate from
  `markDelivered` reddens three tests including the core one.

### Port Separation (LOCKED)
- FAM's default port is **7900**; the claude-peers broker binds 7899. Both can
  run at once, so a migration is reversible instead of a single attempt with no
  back-out.
- Root cause was duplication, not the number: the default was hand-written in
  **fourteen** places across the server, MCP adapter and CLI. All now derive
  from `src/config.ts`, which also names `CLAUDE_PEERS_BROKER_PORT` so the
  constraint is stated rather than implied.
- `src/__tests__/config.test.ts` fails if the literal 7899 reappears anywhere
  under `src/` outside that file — fixing the number without fixing the
  duplication would just mean the next person reintroduces it in one file.
  Mutation-verified: re-adding the literal to `http.ts` reddens the check and
  names the file and line.
- Verified against the LIVE broker serving 17 real peers: FAM came up on 7900,
  the broker's peer count was unchanged, and it survived FAM shutting down.

### Local Bootstrap (LOCKED)
- `bun run bootstrap <email>` creates an account with no provider binding and
  issues an account token. FAM is runnable without registering an OAuth app.
- **Not an HTTP route, deliberately.** An endpoint that mints account
  credentials is an authentication bypass by construction, and gating one on an
  env var makes a misconfiguration a remote hole. It runs against the database
  directly, so reaching it already requires local filesystem access and the
  server secret.
- **Trust-on-first-use adoption removed from `resolveAccountForProvider`.** It
  previously adopted unbound accounts on first OAuth login to cover pre-v6 rows.
  With local accounts that becomes a takeover: a bootstrapped account would be
  claimable by whoever first signed in with the same address. An existing
  account is now never claimed by a provider identity that did not create it.
  Account↔provider linking, if added, needs its own authorisation rather than
  happening as a side effect of logging in.
- Re-running bootstrap issues a new token and invalidates the previous one —
  `authorizations` is `UNIQUE(account_id, server_id)`, so one live token at a time.
- Verified end to end against a fresh database: bootstrap → create entity →
  Ed25519 challenge-response → unauthenticated send refused (401) →
  authenticated send → recipient receives.

### Identity Hardening — session enforcement (LOCKED)
- **Entity identity comes from the session, never from the request body.**
  `requireEntitySession` (`src/server/middleware/auth.ts`) is the single
  enforcement point; every entity-scoped route calls it first. A body-supplied
  `entity_id` is accepted only as a redundant assertion that must agree with
  the session — disagreement is rejected rather than ignored, so a client that
  believes it is acting as someone else is told.
- Applied to all of `/messages/*`, `/channels/*`, `/entities/status` and
  `/entities/list`. `/entities/connect` and `/entities/authenticate` are
  excluded because they establish the session.
- **All entity-scoped routes converged on `requireEntitySession`.**
  `/entities/disconnect`, `/entities/heartbeat` and `/entities/availability`
  previously validated sessions inline and answered 400/404; they now answer
  401 like everything else. A fourth implementation, `validateEntitySession`,
  was defined and never called — deleted rather than left as a second correct
  answer waiting to drift from the first.
  - Behaviour change: heartbeat now enforces the 60s freshness window, so a
    lapsed session cannot be revived by heartbeating it and the client must
    re-authenticate. That was already the effective behaviour once
    `cleanupStaleSessions` ran; the inline check accepted lapsed sessions in
    the window before cleanup fired, which made the stated policy not quite
    the policy.
  - A bogus session id now answers 401 rather than 404 — it is an
    authentication failure, not a missing resource, and 404 disclosed that the
    id was well-formed but unknown.
  - The completeness test no longer carries an exception list: every
    entity-scoped route must answer exactly 401 to an unauthenticated call and
    to a forged session.
- Session id is read from the body ONLY, deliberately not from
  `Authorization: Bearer` — that header already carries the account token on
  `/accounts/*` and `/admin/api/*`, and overloading it would make two different
  credentials indistinguishable by anything but the route.
- Clients updated to match: `FamClient.request` attaches the session to every
  non-establishing call, and the CLI gained `getEntitySession` (challenge-
  response once per process, cached) so entity-scoped commands work.
- Before this, forging a DM as any entity and reading its history required no
  token, session or key — proven with a working exploit and now with tests.
- Cross-account enumeration resolved separately — see Directory Scoping below.

### Identity Hardening — OAuth provider binding (LOCKED)
- **Account identity is bound to the provider that created it.** Migration v6
  adds `accounts.provider` + `accounts.provider_account_id` (the provider's own
  stable user id) with a partial unique index. Resolution is by
  `(provider, provider_account_id)`, never by email; a verified address that
  belongs to another provider identity is rejected with
  `AccountProviderMismatchError` (403).
- **Only provider-verified addresses are accepted.** Google's
  `verified_email`/`email_verified` is now checked; GitHub's profile email is
  ignored entirely in favour of `/user/emails` (the profile field is
  user-settable free text GitHub never verifies). The
  `${login}@github.com` fallback — which minted addresses in a domain nobody
  controls — is removed. Failure raises `UnverifiedEmailError` rather than
  falling back.
- Closed a cross-provider account-takeover path: setting a GitHub profile email
  to a victim's Google address previously yielded a valid account token for
  their account. Demonstrated by a failing test before the fix.
- The OAuth provider's own access token is no longer stored as a FAM
  authorization row.
- Consequence to document for users: one email may only be used with the
  provider it first registered with. Account linking is not implemented.

## Remaining

### Phase 3 — Directory Scoping (DONE — heading was stale)

All three items below are built and tested; the policy is recorded under
"Directory Scoping (LOCKED policy)" in Completed above. Verified 2026-08-27:
`scope: 'directory'` is handled in `/entities/list`, `getDirectoryForAccount`
exists, and `/admin/api/directory` is registered and feeds the console.

- `/entities/list scope: 'directory'`: caller sees own account's entities +
  entities actively granted to their account. `scope: 'all'` unchanged.
- Repo method `getDirectoryForAccount(accountId)`.
- Admin API: list directory for an account (feeds Phase 4 UI).

### Phase 4 — Admin Website
- **Access model designed — see `DESIGN-ADMIN.md`.** Scope: a website for
  account holders to administer access to their agents.
- Core result: **the console needs no cross-account read**, and that falls out
  of the data model rather than being imposed on it — you grant YOUR entity to
  THEIR account by naming an email you already know. So nothing needs to list,
  search or autocomplete outside the account, which removes the three usual
  enumeration leak sites before they are built.
- Revocation verified symmetric with granting: every row in either direction
  contains only what the viewer supplied or was deliberately given. A grant
  between two other accounts appears in neither — tested for specifically.
- **Both blocking decisions RULED by CireSnave (2026-08-19). Neither produced
  the migration that was expected.**
  1. *Retention server-wide or per-account?* — **dissolved rather than answered.**
     He asked whether retention should exist at all: notify the sender that the
     destination is unreachable and let them resolve it, instead of ageing
     messages out silently. Per-account retention needs a column on `accounts`
     ONLY if something is deleted by default; if nothing is, there is nothing to
     configure. **A question answered "no" at the product level deleted schema
     work that both candidate answers would have required.** Worth reaching for
     whenever a queue is shaped like "which of these two" — sometimes the third
     option is that neither is needed. Final shape still open, see Retention below.
  2. *May a grant or rule name a subject that does not exist?* — **YES**, and his
     reason is stronger than the one this document argued. The design argued from
     the enumeration oracle. He argued from workflow: *"account A should be able
     to set up grants and rules for agents that account B hasn't gotten around to
     creating yet. One shouldn't be forced to wait on the other."* Same ruling,
     different artifact — the oracle argument produces an apologetic "pending"
     badge, the workflow argument produces an INVITE. **The justification shapes
     what gets built even when the decision is identical.**

- **Migration v9 (DONE)**: `admin_sessions` table (id, account_id, csrf_token,
  created_at, expires_at) + index. Was written here as "v6" — the schema had
  moved to v8 while this plan sat unrevised, and a stale version in a plan is
  how the next person writes a migration against a schema that no longer
  exists.
- **Browser-auth middleware (DONE)**: `requireAdminSession` — session cookie,
  CSRF token on state-changing methods, Origin checked when present.
  Decision-independent, so built while the two decisions below are outstanding.
  - The threat is NEW to FAM: the entity API is bearer-token only, and a bearer
    token is attached deliberately by a client. A cookie is attached
    automatically by the browser to any request any page can cause. CSRF
    arrives with the cookie, not with the console.
  - Origin MISMATCH is refused; ABSENCE is not — same-origin form posts and
    older clients omit it legitimately, and refusing those breaks the console
    while stopping no attacker, who can simply omit the header too. A control
    an adversary disables by doing LESS is not a control; Origin is defence in
    depth over the CSRF token, never a substitute.
  - Absence is allowed but LOGGED. Modern browsers send Origin on all POSTs
    including same-origin, so absence increasingly means "not a browser". Not
    refusable, but a rise in Origin-absent authenticated writes says something
    about who is calling the console, and it is better to have that signal
    before it is wanted urgently.
  - Each control mutation-verified independently: dropping the CSRF check
    reddens 3 tests, the Origin check 1, and accepting expired sessions 1.
  - Negative controls written BEFORE the positive one. Noted for whoever reads
    this next: the refusals alone are not evidence — while the implementation
    was a stub that threw unconditionally, all seven passed. A deny-everything
    middleware satisfies every negative control. The acceptance tests are what
    make the refusals mean anything.
- **Migration v10 (DONE)**: dropped `grants.grantee_account_id`,
  `permissions.source_entity_id`, `permissions.source_account_id`. Every dropped
  key names SOMEONE ELSE; every kept key names something the actor owns.
  Enforcement was never at the route — three foreign keys held it, which is why
  a product decision needed a migration.
  - Accepted consequence, recorded so it is a known property rather than a later
    discovery: account ids are email addresses, so an account deleted and later
    recreated under the same address inherits any grant still naming it.
    Inherent to naming subjects by email, which is what pending invites require.
  - **The guard for this was vacuous when first written, and the failure is worth
    keeping.** The obvious check — "deleting the grantor's account still removes
    their grants" — PASSES with the grantor FK removed, verified by mutation.
    Deleting an account cascades to its entities, and `grants.entity_id ->
    entities` removes the grant by a second independent path. The test asserted
    an outcome TWO constraints can produce, so it isolated neither, and dropping
    every foreign key on the table would have passed it. Replaced with a
    structural assertion over `PRAGMA foreign_key_list`. **When a change is
    defined as "drop exactly these constraints", the check has to read the
    constraints; anything behavioural is satisfiable by whatever else happens to
    be holding.** Both directions now mutation-verified: over-drop reddens only
    the structural guard, under-drop reddens it plus three behavioural tests.
- **FIXED at `b44c2ba` (2026-08-27) — was carried here as "KNOWN, not fixed"
  for six days after it was closed.** The defect: migration fixtures in
  `schema.test.ts` were hand-written and could not represent a real database.
  The v5 fixture stamped version 5 while omitting tables migration 3 creates.
  Migration 8 hit it, the fix added only the one table it needed, and migration
  10 walked into the same hole two migrations later. **Fixing the instance left
  the class.**
  - The fix is the general one this entry called for: `migrationMatrix.test.ts`
    BUILDS each origin by running the real migrations 1..N, so a fixture cannot
    drift from what that version actually is. Same instinct as deriving CI gates
    from the workflow instead of maintaining a parallel list. Measured
    2026-09-02 at `64e2925`: 19 tests, 0 fail, and the origin list is derived
    from `CURRENT_SCHEMA_VERSION`, so it extends itself.
  - ⚠️ **The stale entry is worth more than the fix it described.** This file is
    the stated source of truth for what is done, and it said a closed defect was
    open. **A stale "not fixed" is the same hazard as the stale "not built yet"
    CLAUDE.md warns about, and in the same direction: it invites someone to
    build a second fix.** The first author of that second fix would have found
    `migrationMatrix.test.ts` only by accident.
  - ⚠️ **And this file already said so, 630 lines further down.** Phase 6 opens
    with *"Migration matrix: DONE, and it maintains itself."* **The document
    contradicted itself and neither entry knew about the other** — which is
    worse than staleness, because a reader who lands on the wrong one has no
    signal to keep looking, and a reader who finds both has no way to tell which
    is current from the text alone.
  - **The tell was available without reading either file: the entry named a
    general fix and a later commit's subject line was that fix.** Nothing
    connected them, because closing a defect and updating the document that
    tracks it are two actions and only one of them is satisfying. **The cheap
    check is a grep for the defect's own noun before filing it as open** — here,
    "migration matrix" would have returned the contradiction immediately.
- **Browser sessions (DONE)**: `POST /admin/api/session/create` exchanges an
  account token for a cookie; `GET /admin/api/session/current` re-supplies the
  CSRF token after a refresh; `POST /admin/api/session/destroy` deletes the row
  rather than only clearing the cookie. A token exchange rather than a second
  OAuth redirect, which would have needed a redirect_uri at every provider and a
  column recording which flow a pending state belongs to.
  - `/admin/api/*` accepts either credential through ONE helper. The cookie is
    checked first and never falls back to the bearer token: a cookie that fails
    to authenticate must not be rescued by another credential on the same
    request.
  - A POST-shaped read is CSRF-checked too. The middleware sees a method, not an
    intention, and exempting "POSTs that are really reads" is a second list that
    fails open.
- **PENDING INVITES ONLY HALF-WORKED UNTIL `673afa6`.** Migration v10 dropped
  the foreign keys, but both routes kept their own `accounts.exists()` check, so
  the database permitted a pending grant and the API went on refusing it with
  404. **The v10 tests called the repository — one level below the claim — and
  were green the whole time.** Verified now through the HTTP stack and in a
  browser.
- **Console (DONE)** at `GET /admin`: agents, access given, access received,
  rules; grant/revoke and rule add/delete. Public route deliberately — it is the
  sign-in screen and holds no account data.
  - **DEVIATION from this plan, deliberate: it is one self-contained HTML file,
    not a React SPA.** React is not a dependency of this project (there are two,
    both runtime protocol libraries), so a React console would add a dependency
    and a bundling step to the server's start path — including in the test
    suite, which boots the real server. Four read screens and two forms do not
    earn that. Revisit if the console grows client-side routing or shared state.
  - **No pending badge, by decision.** See the correction in DESIGN-ADMIN.md:
    marking a grant pending requires knowing whether the grantee has an account,
    which is the account-existence oracle moved from create to list. Every row
    renders identically; a test compares the key sets of a stranger's row and a
    real account's.
  - CSP is `default-src 'none'` with `frame-ancestors 'none'` and
    `connect-src 'self'`; everything the page needs is inline.
- **Entity create/revoke from the console (DONE)**, which required making
  `/accounts/*` accept the browser cookie. They read the token straight from the
  body, so the console could not reach them — and copying the dual-credential
  branch there would have been a SECOND authentication implementation, which
  CLAUDE.md forbids for the reason it gives: an inline check that happens to
  agree today is a second answer waiting to drift. Extracted
  `requireAccountAuth` into `middleware/auth.ts`; admin and account routes now
  share the one helper.
  - `create-entity` and `revoke-entity` also answered **400 before
    authenticating** — "no credential" and "malformed request" were the same
    reply. Identity is now checked first.
  - The key file is shown once, in a panel that says so. It is the entity's
    private key encrypted under a passkey that is never stored, so there is no
    recovery path and the copy must not imply one.
- **`consoleMarkup.test.ts`**: the console is one file with inline script, so
  nothing type-checks it and nothing bundles it. Its characteristic failure is a
  NAME MISMATCH — the script asks for an id the markup lacks, `$()` returns
  null, and the handler throws at click time on a page that renders perfectly.
  The API tests cannot see it: every route can be correct while the button
  wired to it is attached to nothing. Mutation-verified with a typo'd id.
  - The oracle check there is scoped to the SCRIPT deliberately. A first version
    read the whole file and failed on the hint text "a rule may name a source
    that does not exist yet" — static copy about what the system PERMITS, which
    discloses nothing about any particular address. Loosening that sentence to
    satisfy the test would have deleted something true to guard against a thing
    it does not do.

### Declared State — `queue_empty` and `last_state_change` (migration v11)

Requested by CireSnave. Both are DECLARED state and sit beside `availability`,
not beside `status` — only the entity knows whether it has work queued, and
nothing external can derive it.

**The measurement that motivated them:** in one sweep of the claude-peers
network all 17 peers reported `Last seen` inside a **9.5-second window** while
two agents had been idle for hours. A heartbeat says a process is breathing; it
cannot say whether anything is happening.

- `last_state_change` records a **CHANGE**, not a declaration. Re-stating the
  same value does not move it — otherwise an agent looping on one state looks
  perpetually fresh, which is the heartbeat failure coming back through the
  front door. The discriminating test is the negative one: **a heartbeat must
  not move it**, and neither may a status change.
- `queue_empty` is **nullable**, and null means NEVER DECLARED — a different
  claim from a declared `false`. Defaulting to 0 would make every silent entity
  look busy and defaulting to 1 would make them all look idle; both invent a
  declaration nobody made. The row mapper preserves null rather than coercing,
  because it is the one place every reader passes through.
- **It is a TRIPLE, not a pair.** The framing this arrived under was that
  `queue_empty=false` plus an old timestamp means stalled. It does not, quite:
  an agent working steadily on ONE long task has not changed state, so its
  timestamp is legitimately old. What separates a long task from a dead agent is
  liveness — the very thing `last_state_change` refuses to encode.

  ```
  queue_empty=0, timestamp fresh                  -> working, changing
  queue_empty=0, timestamp old, session live      -> one long task
  queue_empty=0, timestamp old, no live session   -> died mid-task
  ```

  Written as a test rather than a comment, because the two-field reading is the
  intuitive one and will be re-derived by whoever meets the columns next.
- **`fam_set_queue_state` in the MCP adapter**, because a field no client can
  set is half a feature — the whole motivation was agents reporting their own
  state, and until this the only way to declare it was raw HTTP. The tool
  description tells the agent to declare on BOTH edges: announcing "empty" and
  never announcing the resumption leaves you looking idle while you work, and
  the reverse leaves you looking busy forever after you stop. **One-edge
  declaring is worse than none**, because it produces a confident wrong answer
  instead of an honest null.
- `POST /entities/queue-state` requires an ENTITY session and an explicit
  boolean. Truthy coercion would let a client send the string `"false"` and
  declare the opposite of what it means, on a field read to decide whether work
  gets dispatched.
- **Migration steps may now be functions.** SQLite has no
  `ADD COLUMN IF NOT EXISTS`, and every migration here is expected to survive
  re-application — 7 through 10 all use `IF NOT EXISTS` deliberately. A step
  that cannot be repeated is also one that cannot be retried after a partial
  failure. `addColumnIfMissing` covers it; the rewind test caught the bare
  ALTER immediately.

### Account-Holder Control — RULED and built

> **CireSnave:** "An account holder should be able to change their entity's
> availability. They should be able to have `queue_empty` rederived from the
> queue itself, but they should not be able to set it to an invalid setting —
> `queue_empty = true` while the queue is not empty is an error."

Two fields, two different mechanisms, and the difference is the interesting part.

**`availability` — a WRITE.** `POST /admin/api/entities/availability`. Nothing
external can contradict an intent, so an account holder setting it is exercising
authority over their own agent. Routed through `wsManager.setAvailability`, the
same call the entity's own route makes, so it broadcasts and flushes the queued
backlog identically. Writing the column directly would have been a second
availability path that agrees on the value and differs on the behaviour — the
harder kind of divergence to notice.

**`queue_empty` — a DERIVATION, never a write.** `POST
/admin/api/entities/rederive-queue` accepts no value, and supplying one is
**refused rather than ignored**: ignoring it lets a caller believe they set
something they did not.

**WHICH QUEUE — the ambiguity in the ruling, resolved and stated.** FAM observes
exactly one queue: undelivered messages. It cannot see an agent's internal task
list, which is why the field was declared rather than computed to begin with.
That asymmetry decides everything:

```
FAM CAN DISPROVE "empty"  -- messages are waiting, so work is pending.
FAM CANNOT PROVE "empty"  -- an empty inbox says nothing about internal work.
```

So rederivation is a **correction**, not a recompute: it overwrites a value the
evidence contradicts and leaves alone one it merely cannot confirm. Asserting
`true` on an empty inbox would be FAM inventing a declaration on the entity's
behalf — precisely what the nullable column exists to prevent.

And the error is an **error**. `updateQueueEmpty(id, true)` with messages
waiting throws `QueueNotEmptyError` (409, carrying the count) rather than
quietly writing `false`. A silent correction is indistinguishable from success
to the caller, who then believes a declaration that was never accepted.

**Consequence worth holding: the refusal binds the ENTITY too, not just the
account holder.** The invariant lives in the repository, so an agent declaring
its own queue empty while messages wait is refused on the same terms. That is
the right place for it — a rule enforced at one route is a rule the next route
forgets.

**One of the three is pullable.** With rederivation available, `queue_empty` can
be refreshed on demand by an outside party; `last_state_change` and session
liveness can only ever be pushed. A supervisor suspecting a stall can force a
current answer for one of the three.

### Test Harness — two defects found by chasing one flake

**1. A leaked listener on the integration test port.** `startServer` stored its
server in a module-level variable, so a second caller silently overwrote the
first handle:

```
integration.test.ts   startServer(17899)  -> server = S1
adminConsole.test.ts  startServer(17901)  -> server = S2   (S1's handle lost)
adminConsole afterAll stopServer()        -> stops S2, server = null
integration  afterAll stopServer()        -> finds null; S1 NEVER STOPPED
```

S1 then held 17899 until the process died, and **the next run failed to bind**.
The leak bites the FOLLOWING run, which is why it looked intermittent and why a
single run always passed. Introduced when `adminConsole.test.ts` became the
second test file to start a server.

`startServer` now returns its handle and `stopServer(handle?)` stops the one it
is given; the shared teardown (websocket manager, database) runs only when the
last server is gone, because one caller's shutdown was closing a database
another was still using — the same overwrite hazard one level down.

The portfolio PM reproduced this independently in an 8-run loop: clean for four
runs, then failing on 5, 6, 7 and 8 consecutively, which is the signature of a
leak that never releases rather than a race.

**2. Three per-test timeout overrides that undid the project default.** The only
`}, 15000)` arguments in the codebase sat on the three slowest tests —
Argon2id at 64MB/t=3/p=4, twice each — and a per-test timeout **overrides**
`--timeout 60000` (confirmed by probe: a 3s test with a 1000ms argument fails at
1011ms under `--timeout 60000`). So the tests the project deliberately gave 60
seconds were running on a 15-second budget.

That produced the "unexplained crypto flake": failures at ~18s, over the local
budget and far under the intended one. **And the failure it produced was worse
than a slow test** — `fails decryption with wrong passkey` going red reads as a
negative control passing, as decryption succeeding with the wrong key, when it
actually meant the test was killed before the assertion ran. **A timeout on a
security test is indistinguishable at a glance from that test finding something
terrible.**

Fixed by deleting overrides that should not have existed, not by raising them.

### CLOSED — the crypto flake was a timeout, settled by its own duration

Carried as open on the grounds that the mechanism was explained but the event
never reproduced. **It is closeable, and the deciding evidence was in hand the
whole time — I was waiting for the wrong thing.**

I said the discriminator was the assertion text: `"timed out after ..."` versus
`"expected promise to reject, but it resolved"`. **The recorded DURATIONS settle
it without that.**

```
per-test budget (the `}, 15000)` override, since removed):  15000 ms
observed failures:                          16120 / 18200 / 18199 ms
uncontended cost of those tests:            ~4300 ms each
```

**A test that reports a duration greater than its own timeout was killed by the
deadline.** An assertion failure requires the test to run to COMPLETION, and a
test that completes does so within its budget or is killed first — so any
duration above the budget is a timeout by construction. All three exceeded it.
A negative control passing would have surfaced at roughly the normal ~4.3s.

The cause is understood and removed: three per-test overrides granting 15s where
the project deliberately allows 60, on the three slowest tests in the suite.
Zero recurrences since.

**The lesson is the one worth keeping.** The timing was in every report I filed
and I read it as incidental to the failure rather than as evidence about it.
**I held out for a stronger discriminator while a sufficient one sat in the
numbers I had already written down** — which is the same shape as everything
else this file records: the answer present one step from where someone stopped.

**Guarded against recurrence** by `src/__tests__/testTimeouts.test.ts`: no test
may give itself LESS time than the project budget. A larger override is fine —
a slow test asking for more room is deliberate. Asking for less than the project
already decided is almost always a number copied from somewhere it made sense.
Mutation-verified: reintroducing a `}, 15000)` reddens it.

### Superseded note — encryption tests, when the mechanism was unknown

`Encryption > fails decryption with wrong passkey` and `> produces different
ciphertext with different passkeys` have failed **twice in roughly six full-suite
runs**, both times at ~18s, never on demand. They pass in isolation (3/3, 11s)
and the suite passes on re-run (322/0).

**Not dismissed, because of WHICH tests they are.** "Fails decryption with a
wrong passkey" going red is consistent with a negative control passing — the
one failure class this codebase has spent the most effort hunting. It is also
consistent with resource pressure: Argon2id at 64MB/t=3/p=4 across concurrently
executing test files.

Two attempts to capture the failure message did not reproduce it. **Wanted: the
actual assertion text.** Until then this is an open question, not a known-benign
flake, and it should not be re-run away.

### RESOLVED — availability toggle (was blocked on a ruling)

The console cannot set an entity's availability, and should not until this is
decided. `/entities/availability` requires an ENTITY session: availability is
the entity's own DECLARED INTENT, deliberately distinct from `status`, which is
connection-derived. CLAUDE.md says to preserve that separation.

The console holds an ACCOUNT session. Adding an account-scoped override would
let an account holder set an intent the entity did not declare — which is
either obviously right (it is their agent, and an agent that will not go quiet
is worse) or a quiet collapse of the distinction the model rests on.

**The question for CireSnave:** may an account holder force one of their own
entities unavailable, overriding what the entity itself declares? If yes, it is
a new account-scoped route and one screen. If no, the console shows availability
read-only, which is what it does today.

**The same ruling now governs `queue_empty`, and there it is sharper.** An
account holder marking an agent's queue empty when the agent has not said so is
the same override — but a supervisor reading that field dispatches work on it,
so a wrong declaration sends work to something mid-task. A yes for availability
is not automatically a yes for this one.

`last_state_change` needs no ruling: nobody sets it directly. It is stamped by
whichever declaration moved, so it inherits whatever the other two decide.


### Messaging Model — what agents need to send each other (DESIGN, nothing built)

Opened by CireSnave 2026-09-01, worked with the portfolio PM. **See
`DESIGN-MESSAGING.md`** for the reasoning, the worked cases and the attributions.

Summary of where it landed:

- **References, not payloads.** FAM has no artifact handoff today
  (`messages.text` and nothing else) and should not gain byte attachments: not
  one handoff in the portfolio has ever needed bytes, and a broker holding
  content becomes a storage system. The failure is that a reference cannot be
  VERIFIED, not that bytes cannot move.
- **One mechanism, two verification modes.** Documents and rulings are
  VERIFIABLE (re-fetch, or query the record). Measurements are only
  REPRODUCIBLE — re-running produces a NEW measurement and does not confirm the
  old one. A measurement reference can resolve perfectly and be false.
- **A ruling is a RECORD the recipient queries**, not a claim relayed through a
  channel the recipient is told to distrust. Currently blocking a real licensing
  fix in vulkane.
- **Task ownership is a first-class object.** Nothing detects an orphaned task;
  fuel #29 cost four days. Distinct from every agent-liveness signal FAM has.
- **Restart persistence:** declared intent persists, observed state does not.
  Assignment is the one that fails the test today.

**Buildable items are Phase 7 below**, with the Phase 5 precondition attached
there.

### Phase 7 — Messaging Model (7.1–7.4 DONE; 7.5 unscheduled)

Derived from `DESIGN-MESSAGING.md`.

> **ORDER, ruled by the portfolio PM 2026-09-02: 7.3 → 7.1 → 7.2 → 7.4.**
> 7.5 unscheduled.

**This reverses my draft (`7.1 → 7.2 → 7.3 → 7.4`) and the correction is worth
keeping.** I noted that 7.3 is independent of 7.1 and then did not use it:
because it is independent, **putting it first costs the reference chain nothing**
— 7.1 starts immediately after. There was no sequencing argument against it,
only the pull of building the elegant thing first.

**And the deciding cost was one I could not see from inside this repo.**
Restart-orphaning is portfolio-wide, and one restart produced it three ways at
once: two fuel lanes unallocated while the architect believed otherwise; PR #29
approved and unmerged for four days because its author was killed; and 17 blank
summaries in which a live lane and a dead one are identical. **The architect
found their own unallocated lanes only because they re-checked task-against-live-
peer-ID rather than working from memory — a check nothing surfaced.**

> **A cost with a workaround and a cost with none are not comparable on size
> alone.** 7.2's cost is real and bounded and has a human fix available today
> (CireSnave telling vulkane directly). **7.3's cost has no workaround at all** —
> nothing detects an orphaned task. A blocker whose fix is one human sentence
> should not set build order.

**7.1 before 7.2 and 7.4 stands** — a ruling is a reference to a record and a
measurement is a reference with a construct and a mode, so building either first
means building the mechanism inside it and generalising later.

### 7.1 open question — RULED: the durability check lives in the ADAPTER

**The core must not run `git`.** The argument is FAM's own test: the core flags
`weird.tenant_slug` exactly as readily as `mcp.cwd`, and that test exists because
it is the property keeping filesystem knowledge out of the protocol. **A core
that resolves a repository has learned what a repository is** — the same
concept-smuggling refused when a bare `cwd` key was rejected. The core compares
and carries; it does not resolve.

So the adapter checks `compare...main` and the core stores the **result**, plus
what was checked and when.

⚠️ **And the stored result is itself a MEASUREMENT, not a fact.** `durable: true`
was true at the moment the adapter looked. By this design's own two-mode split it
is **reproducible, not verifiable**, and therefore needs the ref it was checked
at — a `durable` flag without one is precisely the unverifiable self-attestation
the predicate exists to replace.

**7.1 — Typed reference. DONE** (migration v15). `message_refs` table, attached
on send and pushed with the message, plus a `git_ref` option on the MCP send tool
that emits the durability claim alongside it.
- **The core validates STRUCTURE and never meaning.** It does not know what
  `git.ref` is and accepts `weird.tenant_slug` on identical terms — there is a
  test asserting that, because it is the property keeping FAM a federation
  protocol rather than a git client. Kinds are namespaced for the same reason
  context keys are.
- **THE RULES BIND TO THE MODE, NOT THE KIND.** That is what lets the core
  enforce them while staying ignorant: it does not know what a measurement is,
  only that anything claiming to be *reproducible* must say when, as whom, and
  over what.
  - `verifiable` → requires a `digest` to compare after re-fetching. Without one
    it is a name, and a name is what *"see DESIGN.md"* already was.
  - `reproducible` → requires `construct`, `taken_at` and `taken_as`.
- **`taken_as` came from the PM and earns its place with a three-hour-old case:**
  `GET /branches/main/protection` returns **404 to a non-admin and 404 to an
  admin with opposite meanings**, separated only by the body. **After any
  privilege change, every absence recorded earlier is UNVERIFIED — not wrong,
  unverified** — and without the identity it was taken as, a stored zero cannot
  be re-read at all.
- **Durability is a SEPARATE reproducible reference, not a field.** `git.ref` is
  verifiable (re-fetch the sha); `git.durable` is reproducible (re-run the
  reachability check). Emitting `durable: true` as a field on the verifiable ref
  would have made an adapter's momentary observation look like a property of the
  commit. Verified discriminating: a merged commit reports `true`, a fabricated
  sha reports `false`, both against a named `origin/main` head.
- **The check runs in the ADAPTER**, per the ruling: a core that runs `git` has
  learned what a repository is.
- References are attached **before** the push, so an online recipient gets the
  message with them rather than a bare text it must ask about — and an invalid
  reference **fails the send** rather than letting the message land silently
  without it.

**7.1 — Typed reference (original scope).** The shared mechanism the other items
rest on. A namespaced, opaque-to-the-core reference attached to a message:
`{kind, ...fields, mode}` where `mode` is `verifiable` or `reproducible`. FAM
carries and compares; it never resolves or interprets. Migration for the table,
a send-path field, adapter surface, console display.
- **`durable` for `git.ref` must be CHECKED AT SEND TIME** — squash-merge orphans
  PR-head SHAs, so a sender-asserted flag is one more unverifiable claim.
  **RULED: the check lives in the adapter, the core stores the result with the
  ref it was checked at.** See the ruling above.

**7.2 — Rulings as records. DONE** (migration v16). `rulings` table,
`POST /rulings/check` for the grantee, admin create/list/revoke, `fam_check_ruling`
in the MCP adapter, and an **Authority** tab in the console.
- **The granter is the AUTHENTICATED account and is never read from a body** —
  the same rule the entity routes follow. A recorder who could name someone else
  as granter would turn the table back into the relayed claim it replaces.
- **`/rulings/check` is the feature in one call:** an agent asks FAM whether its
  own account holds an authority, instead of believing a message that says so.
  **A caller may only ask about authority granted TO them** — any pair would make
  this a directory of who trusts whom.
- **`granted: false` is an ANSWER, not a 404.** A caller that cannot tell "no
  such authority" from "the lookup failed" is back where it started.
- **BODY vs NOTE, and the second failure it prevents.** A derived convention was
  once filed ADJACENT to a quoted grant, under the granter's name, and thereafter
  read back as theirs. `body` is verbatim and the granter's; `note` is an
  interpretation and carries its author. **A note without an author is refused**,
  because an unattributed reading beside an attributed quote is exactly how the
  derived thing acquires authority nobody gave it. The console renders them
  together — mutation-verified: dropping the author reddens that test alone.
- **Revocation does not delete.** That authority was once given stays part of the
  record; a grantee who acted while it stood needs it to still be there.
- `grantee_account_id` carries **no foreign key**, matching migration 10 —
  authority may be recorded for an account that does not exist yet, and requiring
  existence would be an existence oracle as well as making A wait on B.

**7.2 — Rulings as records (original scope).** A ruling is stored and QUERIED by the grantee, not
relayed as a claim. Needs: a `rulings` table (granter account, scope, body,
issued_at, revoked_at), a create path behind account auth, a lookup the grantee
can call, and console surfaces. **Server-attested; see the Phase 5 precondition
below.**
- **Currently has a running cost**: vulkane cannot act on a relayed publish grant,
  so a licensing defect in published crates stays unfixed. **That specific
  instance does not need this feature — it needs CireSnave to tell vulkane
  directly.** The feature stops it recurring.

**7.3 — Task ownership. DONE** (migration v14). `tasks` table, `/tasks/*` routes,
four MCP tools, and an "unattended" banner in the console.
- **`owner_entity_id` is `ON DELETE SET NULL`, deliberately and not by default.**
  Deleting an entity must ORPHAN the work, not destroy it — destroying work when
  its owner is removed is the exact failure this exists to prevent, and a CASCADE
  would have implemented it. Mutation-verified: switching to CASCADE reddens
  exactly the test that says so.
- **Unattended is DERIVED at read time, never stored.** A flag goes stale the
  moment an owner reconnects, the same reason context collisions are computed.
- **The two causes are kept apart: `unowned` and `owner_offline`.** Collapsing
  them into one "orphaned" label makes the list say less than the query knows —
  "assign it to somebody" and "re-queue it" are different actions.
- **The age is reported, not judged.** An owner offline four minutes and one
  offline four days are both "not connected"; only the reader knows which
  matters, so no threshold is baked in.
- **Closed work is never unattended.** Padding the list with things nobody can
  act on trains a reader to skim it, and a skimmed list is how a real orphan is
  missed.
- **Assignment reuses `canDirectMessage`** rather than inventing a second
  authority — with the limit stated: an assignment is a RECORD that somebody owns
  something, not a command that compels them. If it ever becomes compelling
  (auto-dispatch, forced re-queue) it needs its own authority, because "may talk
  to" and "may direct" stop being the same question then.
- The MCP tool text tells an agent that is stopping to **assign the task to null
  rather than leaving it owned** — an unowned task is visible; a task owned by a
  process that is gone only looks assigned.

**7.3 — Task ownership (original scope).** An assignment object whose owner is an entity, so
"owner not currently connected" is a query rather than something a coordinator
must remember. **Nothing in FAM answers this today**: `queue_empty`,
`last_state_change` and session liveness all answer *"is this agent stalled"*, and
an orphaned task is work that HAD an owner and LOST them. Cost of the gap: fuel
PR #29, four days.
- Persists across restart by the test in DESIGN-MESSAGING: a human should not
  have to re-tell a coordinator what its lanes were doing.

**7.4 — Measurement provenance. DONE.** No migration — 7.1 already built the
mechanism and `reproducible` already enforces `construct` / `taken_at` /
`taken_as`. What remained was the adapter surface, and the PM's framing decided
its shape:

> `taken_as` is your unit argument. A measurement whose construct and whose
> STATED construct can drift apart is the identical defect one level up.

- **You supply the COMMAND and its output, not the number and a description.**
  The command is recorded **verbatim** as the construct. **There is no
  parameter for a caller's own wording**, which is what makes drift impossible
  rather than discouraged. *"48 vectors mentioning NaN"* becoming *"48 NaN
  vectors"* is the defect; a per-function line count that swept the next
  function's doc comments is another; `86/208` reported against a rule written
  about `86/143` is a third. **The number was right every time.**
- **This also makes `reproducible` mean what it claimed.** A recipient cannot
  re-run prose. They can re-run a command. **A reproducible reference whose
  construct is a description was never actually reproducible** — 7.1 defined the
  mode correctly and the adapter surface is what makes it true.
- ⚠️ **THE ADAPTER DOES NOT EXECUTE THE COMMAND, and that is a correction.** The
  first version ran it via `sh -c` to guarantee the value came from the command.
  A security review rejected it and was right: **the command arrives as an MCP
  tool parameter, an agent's context can hold untrusted content, and a prompt
  injection would therefore reach a shell THROUGH A MESSAGE-SENDING TOOL** —
  plus an unbounded read and no timeout. The reasoning that let it through was
  *"the agent can run commands anyway"*, **which is wrong in the way that
  matters: when the agent runs one it passes through the harness's permission
  layer, and that path did not.**
  - **The deeper error was building a guarantee the design already provides.** A
    `reproducible` reference is verified by the **recipient re-running it** —
    that is the definition of the mode. Executing it in the adapter bought
    nothing re-running does not, and paid remote code execution for it.
  - The two protections divide cleanly, and neither needs execution:
    **paraphrase drift is impossible because there is no prose field**;
    **a fabricated value is caught by re-running**, which is the mode's contract.
- **A failed command attaches NOTHING and says so.** "Could not measure" and
  "measured zero" are different facts — the same distinction the durability
  check had to learn. **An empty stdout with exit 0 IS a measurement** and is
  kept, because discarding it alongside the failures would erase exactly the
  finding a negative control exists to produce.
- Same fix as the unit argument on `assertWithinLimit`: the defect was never a
  wrong choice, it was that **the count and the statement of the count were
  independently specifiable.**

**7.4 — Measurement provenance (original scope).** `{value, construct, ref, taken_at}` as a
`reproducible` reference. `construct` is the load-bearing field — four incidents
in one day where the arithmetic was correct and the subject it ranged over was
never stated. Staleness must be a **checkable ref**, not a wall clock: "taken at
`origin/main` 5ecba5ce" lets a reader count commits; a timestamp only says it is
old.

**7.5 — Correlation (`reply_to`).** Lowest ranked, **on bounded evidence**. The
PM sees dispatch-shaped PM-to-lane traffic which is naturally self-contained, and
says it costs verbosity without changing decisions. CireSnave named customer
support as a target environment, which would look nothing like that traffic.
**Do not close this on the current evidence; it is unmeasured for the shapes that
would need it.**

⚠️ **BLOCKING DEPENDENCY ON PHASE 5, recorded so it is remembered rather than
discovered:** 7.2's server attestation means *"the broker says so"*, which stops
being sufficient the moment a ruling crosses to a server the recipient does not
control. **Federation requires entity-signed rulings with a verifiable
account→entity ownership chain.** Accounts hold no key material today
(`entities` have keypairs; `accounts` have id, display_name and timestamps), so
this is a schema question and not only a protocol one.

### Injection-Shape Audit (2026-09-02) — one finding, already fixed; nothing else

Dispatched after the 7.4 RCE: audit FAM's whole surface for the same shape, not
just the adapter that had it.

**THE CLASS SEARCHED FOR:** any place a parameter, header, body field, or stored
value is interpolated into a command string, or reaches an interpreter —
process execution, shell invocation, SQL built by interpolation, `eval` /
`new Function`, HTML injected as markup, or a file path derived from input.

**SEARCH SPACE, stated so the null means something:** all 69 tracked non-test
source files under `src/`, all 35 test files, and the 6 legacy claude-peers
files at the repo root (`broker.ts`, `cli.ts`, `index.ts`, `server.ts`,
`shared/*`). Measured at `24ee1ed`.

**THE NETWORK-FACING SURFACE IS CLEAN, and that is the result that matters.**
`src/server/` — every route, the WebSocket handler, every repository reachable
from them:

```
process execution of any kind   0
shell invocation                0
eval / new Function             0
SQL built by interpolation      0
file path derived from a request 0
```

Every query binds its parameters; every response is `JSON.stringify` or a static
file. **No request field reaches an interpreter anywhere.**

**Four sites carry the SHAPE and each is dispositioned, not waved past:**

- **`src/scripts/gates.ts` — `sh -c` with a command from `.github/workflows/test.yml`.**
  Real shell execution, and it is the tool's stated purpose: run locally exactly
  what CI runs. The input is a repo-tracked file, so anyone who can change it can
  already change CI. **No remote or agent-supplied input reaches it.** Accepted.
- **`src/db/schema.ts` — `PRAGMA table_info(${table})` and `ALTER TABLE ${table}`.**
  Both helpers are module-private and every call site is a string literal inside
  the `MIGRATIONS` registry. **No runtime input path exists.** Accepted.
- **`src/adapters/cli/commands/auth.ts` — `Bun.spawn(['open', authUrl])`.**
  argv array, no shell. `authUrl` is built from local config plus a CLI-supplied
  provider — the operator's own values on their own machine. Accepted.
- **`src/admin/console.html` — `innerHTML`.** Every use is either `''`, a static
  string, or a class name that is only ever `ok`/`err`. **All server data goes
  through `textContent`.** Accepted.

**And the adapter's remaining spawns:** five, all argv arrays with a fixed `git`
verb. The sha passed to `merge-base` is an argument, never interpolated into a
string. **Zero shell invocations remain anywhere outside the gates script.**

> **The distinction that decides every one of these is argv-versus-shell.** A
> fixed verb with arguments cannot be made to run something else; a string handed
> to `sh -c` can. That is the whole difference between the five that stayed and
> the one that was removed.

### Phase 5 — Federation (DESIGNED at `64e2925`; first increment building)

Specified in `DESIGN.md` (Phase 5: Federation) and for a long time never given a
ROADMAP section, so the one entirely-unbuilt phase was also the one this
document did not mention. **That is no longer true and this heading has been
corrected rather than left to age** — it is the same defect as the stale
"KNOWN, not fixed" corrected under Phase 4 above.

**Designed in `DESIGN-FEDERATION.md`**, merged as PR #9. Two tiers of key: an
account key held by the human, vouching for entity keys held by agents.
Discovery and key distribution ride the account holder's own forge repository.
Three items **dissolved rather than being built** — retention, entity transfer,
and countersigned rotation — each because a decision elsewhere removed the
problem instead of answering it.

#### 5.1 Message sealing — DONE at `33dd549`

**RULED by CireSnave 2026-09-02: encrypt messages.** Built as ephemeral-static
ECDH (libsodium's `crypto_box_seal` shape) in `src/crypto/sealing.ts`.

- **Entities now carry a second keypair, X25519, because Ed25519 cannot
  encrypt.** ⚠️ Do not "simplify" this back to one key. Measured on Bun 1.3.14,
  an Ed25519 public key **imports as X25519 and derives 32 plausible bytes**,
  while its own private half is refused — **ciphertext the recipient can never
  open, and every check short of testing AGREEMENT passes.**
- **`message-encryption.ts` is not superseded and is not the same thing.** It
  encrypts at rest under `FAM_SERVER_SECRET`, so the server reads everything;
  sealing is end-to-end, so it reads nothing. Both are wanted. **Say under whose
  key.**
- ⚠️ **TWO MUTANTS SURVIVED THE FULL BLACK-BOX SUITE, and one was a total
  break.** Deriving the content key from 32 zero bytes instead of the ECDH
  secret leaves every KDF input public — anyone holding an envelope derives its
  key — **and all ten tests passed.** "A different key cannot open it" passed
  because the mutant's salt still contained the recipient's public key. **It
  passed for a reason unrelated to the property it names.** Dropping the
  key-binding survives symmetrically; each mutant is masked by the half the
  other keeps, so running them one at a time made both look covered.
- **No test over `seal`/`open` can separate them** — the distinguishing
  operation, deriving a key from public inputs alone, is one that API never
  offers. So the KDF seam is tested directly by holding one input fixed and
  varying the other, and both mutants now die to the test written for them.

#### Remaining in Phase 5

- ⚠️ **NO CLIENT SEALS YET, so nothing in FAM is end-to-end encrypted in
  practice.** Every primitive, route and send path exists; `src/adapters/mcp/`
  and `src/adapters/cli/` both still send plaintext, and neither generates an
  X25519 pair. **This is first on the list deliberately** — the arc reads as
  finished from the commit log and is not, and a roadmap that lets it read that
  way is the stale-claim defect this file has already been corrected for twice.

- ⚠️ **ENTITY IDENTITY KEYS ARE GENERATED SERVER-SIDE, which makes envelope
  signing conditional in a way the design text did not say.** Measured
  2026-09-02 at `4a4de70`: `POST /accounts/create-entity` mints the Ed25519
  pair (`src/server/routes/accounts.ts:215`) and returns the private half
  encrypted under the passkey. It is **not stored** — `grep private_key
  src/db/` returns nothing — **but the server held it.**
  - **The asymmetry is the finding.** `POST /entities/encryption-key` accepts a
    PUBLIC key only, so FAM never holds an X25519 private half and
    confidentiality from the relay is genuine BY CONSTRUCTION. Identity has no
    such guarantee: a server compromised at creation time keeps the key and
    forges that entity's signatures indefinitely.
  - **Fix: entity creation must accept a client-generated public key.** It
    changes the creation flow, `bun run bootstrap`, and every test that creates
    an entity — its own increment, not an appendix to another one.
  - **Found by asking where the adapters would get their keys**, not by
    reviewing the crypto. The crypto is right; the custody around it was not.

- **Signing the envelope** — authenticity, still the Ed25519 half. Sealing
  deliberately says nothing about who sent a message.
- **Per-recipient content-key wrapping for channels.** `messages.text` is one
  column; migration 7 split *delivery* per recipient, not *content*. One content
  key wrapped per recipient, not N ciphertexts.
- **Wiring into `MessageSendService`**, the single authoritative send path, plus
  the migration that adds entity encryption keys.
- **Vouchers and revocations on the wire** — granularity ruled individual, not
  wildcard: a wildcard would let a FAM compromise mint agents, which is the
  property the key model exists to remove.

Federation remains the largest outstanding item in the project, and every
"pre-alpha, not ready to deploy" statement still rests on it.

### Phase 6 — Test Backlog & Data-Model Fixes
- **Migration matrix: DONE, and it maintains itself.** `migrationMatrix.test.ts`
  builds each origin by running the REAL migrations 1..N via `migrateTo`, then
  upgrades to current. A version-N database is by construction what a version-N
  database is, and the loop is bounded by `CURRENT_SCHEMA_VERSION` — **so adding
  a migration extends the coverage instead of the untested list. There is no
  list to fall behind.**
  - **This also closes the hand-written-fixture class**, which had bitten twice
    (migrations 8 and 10), both times by a fixture stamping version N while
    lacking objects version N would have. Fixing the instance had left the class
    both times.
  - **It found four real defects immediately: migrations 2, 3, 5 and 6 were NOT
    re-appliable** — bare `ALTER TABLE ADD COLUMN` and `CREATE INDEX` without
    `IF NOT EXISTS`. Everything from 7 onward was, because that is when the
    discipline started, so the invariant the codebase states was only half true.
    Not a correctness bug (each migration runs in a transaction that rolls back)
    but an invariant half-held is worse than one not claimed. All are idempotent
    now, verified by mutation: reverting migration 12 to a bare ALTER reddens
    exactly the re-appliability test.
  - The old note said: covered as origins fresh, v1, v3, v5, v6 — **PARTIAL.**
  Covered as starting points: fresh, v1, v3, v5, v6. **Not covered: v2, v4, v7,
  v8, v9, v10.** Every version added since the matrix was written has gone
  untested as an upgrade origin, which is the direction that matters — the
  rewind test found two real defects (migration 8 not re-appliable, migration 11
  a bare ALTER) and only in the versions it happens to cover.
- Availability + directory scoping coverage. **DONE** — `declaredState.test.ts`
  and the directory-scoping tests under Completed.

### Phase 6b — Findings from operating claude-peers at scale

Derived from four days of field data across 17-18 concurrent agents (portfolio
PM session, 2026-08-19). These are failure modes observed in production on the
predecessor system, not speculative hardening. Ordered by measured impact.

- **Delivery state in the send response. DONE.** `/messages/send` and the
  WebSocket ack now carry a `delivery` block: `outcome` is `pushed`, `paused` or
  `offline`, alongside the recipient's status, availability and declared queue
  state. The MCP adapter renders it in words an agent acts on — "DELIVERED …
  silence from here is theirs" versus "QUEUED … DO NOT read silence as a reply".
  - **The outcome is captured AT THE PUSH, not re-derived.** `pushToEntity`
    already had all three branches and discarded the answer; re-querying
    connection state afterwards races with a disconnect and can report a
    delivery that did not happen.
  - Channel sends report the **weakest** member outcome, because "pushed" would
    overstate a fan-out where anyone was offline. Per-member truth is in
    `message_deliveries`.
  - The caveat survives in the field name `declared_by_recipient`: `paused` is
    honest-broadcast, not enforced truth.
  - **This closes the half left open by the retention fix.** That stopped the
    system destroying undelivered mail; this stops it lying about the mail's
    fate. Same rule, both directions: *any outcome that is not delivery must be
    legible to the sender.*

- ~~**Delivery state in the send response.**~~ Highest value of the four. Sending
  to an offline or `unavailable` entity currently returns `201 + message_id`:
  persisted, queued, and indistinguishable from delivered. The server already
  knows the answer and does not tell the sender. Field data: of 12 peers pinged
  in one window, 4 replied; the other 8 were busy, stopped, or never going to
  answer, and the sender could not tell which. Return recipient `status` +
  `availability` so the sender can distinguish *connected-and-available*
  (busy, likely to answer) from *declared-unavailable* (don't wait) from
  *offline-queued* (will see it on reconnect). Ship with the caveat that
  availability is honest-broadcast, not enforced truth — it reports what a peer
  declared, not whether it will reply. Generalized rule: **any outcome that is
  not delivery must be legible to the sender.**
- **Free-text summary field on entities. DONE** (migration v12). `entities.summary`
  plus `POST /entities/summary`, `fam_set_summary` in the MCP adapter, and a
  "Doing" column in the console. Entity session required — the value of the
  field is that nobody else wrote the words. Bounded at 500 characters and
  **refused rather than truncated**, because a cut-off summary is a claim the
  entity did not make.

- **Staleness stamps on summaries. DONE**, and the plan's own suggestion was the
  bug. It proposed reusing `last_seen` — *"already recorded, so rendering 'set
  4d ago' is nearly free"*. **`last_seen` is CONNECTION-DERIVED.** A live agent
  carrying a six-month-old summary would render "set 2 minutes ago", which is
  exactly the misreading the item exists to prevent, implemented by the fix.
  Shipped as `summary_set_at`, recording when the summary was ASSERTED.
  - **Deliberately opposite to `last_state_change`.** That records a CHANGE and
    ignores repeats. This refreshes on every assertion including a repeat,
    because staleness asks when someone last VOUCHED for the words — "still
    true" is new information about an old sentence. Two timestamp columns whose
    correct behaviour on a repeat is opposite, which is why each has a test
    naming the other.
  - The console renders the summary and its age **in one cell**, so a column
    reorder or a copied string cannot separate them. Mutation-verified: removing
    the age reddens exactly the two tests that exist for it.
  - The MCP tool tells agents to **re-set a summary that is still true**, since
    a stale summary is worse than none and only the entity can refresh it.

- ~~**Free-text summary field on entities.**~~ Regression vs claude-peers, which has
  `set_summary`. `display_name` + `capabilities` describe identity but not
  current intent, and intent is what routing actually needs. Field data: of 17
  peers, the 5 with summaries were the only ones routable without broadcasting;
  one summary was the sole reason a project stayed reachable across a four-day
  gap.
- **Staleness stamps on summaries.** `last_seen` is already recorded, so
  rendering "set 4d ago" beside a summary is nearly free. Observed harm: a
  four-day-old summary read as current caused one project to conclude another
  was blocked on work that had already shipped, and act on it. The fix moves the
  discount from something a reader must remember to something they cannot avoid
  seeing.
- **Adapter-populated context bag. DONE** (migration v13). `entities.context`
  holds an OPAQUE map of namespaced keys to strings; `POST /entities/context`
  publishes it, the MCP adapter fills `mcp.cwd` and `mcp.git_root` automatically
  on connect, and the console surfaces collisions as a banner.
  - **The core stays ignorant, which was the constraint.** It compares strings
    for equality and never parses one — it would flag a collision on
    `weird.tenant_slug` just as readily, and there is a test asserting exactly
    that. Keys MUST be namespaced: a bare `cwd` would be FAM claiming a concept
    of a working directory, which is what does not belong in a federation
    protocol.
  - **`mcp.git_root` as well as `mcp.cwd`**, because two sessions in different
    subdirectories of one repository share a checkout and would not collide on
    cwd alone — which is the case that caused the harm.
  - **Own-account only.** A collision between two of your sessions is useful;
    telling you a stranger's session runs from the same path is a disclosure
    nobody asked for. Tested with a foreign entity deliberately sharing a value
    and not being reported.
  - **Rendered as a banner, not a column.** A collision is a fact about a PAIR;
    a per-row field would make the reader reconstruct it by comparing rows,
    which is exactly what nobody did when two sessions shared a checkout and
    both claimed the same three commits.
  - Publishing is best-effort at connect: a session that cannot report where it
    lives is still a usable session.

- ~~**Adapter-populated context bag for framework-local identity.**~~ FAM correctly
  has no `cwd`/repo concept — those do not belong in a federation protocol — but
  dropping them cost collision detection that claude-peers had via `from_cwd`.
  Observed harm: two sessions sharing one checkout, mutually invisible, both
  claiming authorship of the same three commits; the network held both `cwd`
  values throughout and had no way to say so. 9 of 18 sessions were sharing a
  checkout with at least one sibling. Let adapters populate a namespaced context
  blob (the MCP adapter supplies cwd/git root) that the directory can surface
  and collision-check, without the core schema learning about filesystems.

Cross-cutting instrumentation note: **count near-misses, not just failures.** A
directory lookup that returns "no such entity" is a caught error and must be
logged as one. Observed rate of a failure mode under-samples it in proportion to
how disciplined the surrounding population is, so a low rate in the wild is
evidence of careful operators rather than a healthy protocol.
