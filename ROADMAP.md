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

### Phase 3 — Directory Scoping (in progress)
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
- **Blocked on two decisions, both carrying migrations**, both in DESIGN-ADMIN.md
  with options and screens sketched:
  1. Retention server-wide or per-account? (per-account = column on `accounts`)
  2. May a grant or rule name a subject that does not exist? (= drop three FKs;
     the product form is "may one account holder learn whether an email has a
     FAM account?")

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
    while stopping no attacker, who can simply omit the header too.
  - Each control mutation-verified independently: dropping the CSRF check
    reddens 3 tests, the Origin check 1, and accepting expired sessions 1.
  - Negative controls written BEFORE the positive one. Noted for whoever reads
    this next: the refusals alone are not evidence — while the implementation
    was a stub that threw unconditionally, all seven passed. A deny-everything
    middleware satisfies every negative control. The acceptance tests are what
    make the refusals mean anything.
- React SPA served from the same Bun.serve at `/admin/*` (HTML imports,
  no vite): entity CRUD, grants UI, permission matrix UI, availability
  toggle, directory view.


### Phase 6 — Test Backlog & Data-Model Fixes
- Migration matrix: fresh → current, each older version → current.
- Availability + directory scoping coverage.

### Phase 6b — Findings from operating claude-peers at scale

Derived from four days of field data across 17-18 concurrent agents (portfolio
PM session, 2026-08-19). These are failure modes observed in production on the
predecessor system, not speculative hardening. Ordered by measured impact.

- **Delivery state in the send response.** Highest value of the four. Sending
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
- **Free-text summary field on entities.** Regression vs claude-peers, which has
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
- **Adapter-populated context bag for framework-local identity.** FAM correctly
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
