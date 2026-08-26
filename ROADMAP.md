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
- `messages.delivered` is now **vestigial** — nothing writes it. It is retained
  because the backfill reads it and SQLite cannot drop a column cheaply. The CLI
  history view no longer renders a delivery marker; a single flag cannot answer
  a per-recipient question.
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
- Migration v6: `admin_sessions` table (id, account_id, created_at,
  expires_at, csrf_token).
- Cookie + CSRF auth middleware reusing existing OAuth account login.
- React SPA served from the same Bun.serve at `/admin/*` (HTML imports,
  no vite): entity CRUD, grants UI, permission matrix UI, availability
  toggle, directory view.

### Phase 5 — Versioning Completion / Key Rotation
- `key_id` in the versioned ciphertext envelope; HKDF salt per key version.
- Key rotation CLI (`fam key rotate`) + migration to re-encrypt existing rows.
- WS envelope: client sends `version` on connect; reject newer-than-server.
- Document rotation procedure (current guidance: don't rotate; messages
  become undecryptable).

### Phase 6 — Test Backlog & Data-Model Fixes
- Encryption toggle tests (enable/disable over existing data).
- MCP reconnect flows (server restart, undelivered delivery, fatal-error
  handling on revoked/deleted entity — stop reconnecting on 404/401).
- Admin edge cases: grant revocation during active DM, concurrent admin ops.
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
