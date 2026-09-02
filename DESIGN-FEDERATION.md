# FAM — Federation

**Status:** design, nothing built. Scoped with CireSnave 2026-09-02, replacing
the four unchecked boxes that were `DESIGN.md`'s entire Phase 5 specification.

**Positions are attributed where the design changed hands**, because two of the
load-bearing ideas here are his and the record should say so rather than
flattening the conversation into a single voice.

---

## What federation is for

**Many account holders whose agents work together on shared projects.**

Not a hostile-parties protocol. CireSnave's framing, and it is a better one than
the trusted-vs-distrusting split this started from:

> *"Many account owners having their agents speak freely to work together on
> projects both account holders are involved in. Distrust doesn't have to be
> part of it since any artifacts the agents create can be gated by the account
> owners beyond what FAM is or needs to be."*

**One correction carried forward, and it is not a disagreement about people.**
"Cooperating" describes the *operators*. The protocol talks to a *server*, and a
trustworthy operator can still run a compromised or buggy one. The design below
means that distinction stops mattering — not because anyone is assumed hostile,
but because **no server is ever asked to be believed.**

### It is also not only a collaboration feature

The operational case is what makes it necessary, and it was nearly missed by
reasoning only from the collaboration story:

> *"Assume a Windows Update happens on this laptop. All of my agents are down. I
> can restart them on my other PC but the server is non-existent until the
> laptop finishes its update."*

**Server availability becomes agent availability.** That is a single point of
failure on a *maintenance window* — scheduled, routine, and outside the
operator's control. A design where an agent's identity lives on one machine
cannot survive an operating-system update.

---

## The model: two tiers of key

**CireSnave's proposal, and it is the primary-key/subkey pattern** — the same
shape as PGP primary keys with subkeys, or an SSH certificate authority per
account.

```
ACCOUNT KEY   held by the human. Exchanged out-of-band, once, per peer.
              Signs vouchers and revocations. Never signs a message.

ENTITY KEY    held by the agent. Vouched for by its account key.
              Signs every message that agent sends.
```

A recipient verifies a message by checking the entity signature, then checking
the voucher that binds that entity key to an account key it already holds.
**Neither check involves the server that delivered it.**

### What this settles

**Authenticity is path-independent.** Today a message's authenticity is a claim
by whichever server relayed it — messages carry no signature, only a session id
the server issued. Under this model a forged message requires a private key, not
a compromised relay.

**Servers stop needing identities at all.** If authenticity comes entirely from
signatures, a server is transport. TLS for confidentiality; no server keys, no
server-to-server trust, no question about what a relay may assert. **A large
simplification that falls out of the key model rather than being designed.**

**Entity transfer stops being a protocol.** `DESIGN.md` listed it as one of four
Phase 5 items. If identity is the keypair, "moving" an agent is presenting the
same public key to a different server — there is nothing to hand over, because
the identity was never the server's to hold. **The laptop case is then a
non-event: agents restart against the other server and keep their identities.**

There is precedent for the move in this repo. Migration 6 bound accounts to
`(provider, provider_account_id)` and demoted email to *"a label rather than a
key."* This is the same step one level up: **the name becomes a label, the key
becomes the identity.**

**And it closes a precondition already recorded as blocking.** `DESIGN-MESSAGING.md`
notes that server-attested rulings stop working the moment a ruling crosses a
server the recipient does not control, and that the fix needs "entity-signed
rulings with a verifiable account→entity ownership chain" — with accounts
holding no key material to anchor it. **The account key is that anchor.**

### What it does NOT settle, stated so it is not discovered later

| | |
| --- | --- |
| **Account-key compromise** | No higher authority can revoke it. Recovery is the two humans re-exchanging out-of-band. Acceptable: rare, and human-scale. |
| **First contact** | Not eliminated — **concentrated.** Entity keys stop being trust-on-first-use entirely. The account key is still a first contact, but a deliberate one between two people already agreeing to collaborate. Avoid calling it "solved": that invites someone to skip the out-of-band step. |
| **Account-key ROTATION after compromise** | Signing a new key with the old one proves continuity and nothing else — a thief holding the key can perform exactly the same operation. See the correction under key distribution. |
| **Account-key custody** | Improved but concentrated. N unrecoverable keys become one protected key plus N recoverable ones — you can afford real protection on one key and cannot on twenty. |

---

## Where the keys live

### The account private key: held by the human, not the server

Accounts hold **no key material today** — `accounts` is id, display_name and
timestamps. This is new, and where it lives is the sharpest question the design
raises.

**Rejected: the server holds it.** Convenient, but a compromised FAM could mint
vouchers for entities that then talk to peers as legitimate members of the
account. **That extends the blast radius past the operator's own machine**, which
is the one thing the whole model exists to prevent.

**Chosen: the account holder holds it**, encrypted at rest and decrypted only to
sign. This needs almost no new machinery — **store it exactly as entity key files
already are**, Argon2id + AES-256-GCM via `encryptPrivateKey`/`decryptPrivateKey`.
Same format, one level up.

Vouching and revoking are rare, so the passkey friction lands where it is cheap.

### Peer account PUBLIC keys: in git — but in WHOSE repository

**Two schemes were considered. The second supersedes the first, and the first is
kept because its failure is the reason the second is right.**

#### Scheme A — the project's repository (SUPERSEDED)

**CireSnave's proposal:**

> *"Could the account holder public keys be stored in the git repositories those
> agents work with? That way anyone interacting with a project need only pull a
> file (or directory of files) to have the latest account holder verification for
> everyone involved."*

**Take it. The distribution problem is already solved by a thing collaborators
already do**, with no directory service, no DNS, and no new infrastructure. It
also gives an auditable append-only history with authorship, and reuses the
repository's existing write control.

**And it scopes trust the right way, which is a bonus rather than a side effect:**
trusting Alice in project A does not imply trusting her in project B. **That is
exactly the per-project consent model, enforced by where the file lives.**

> ⚠️ **THE CORRECTION: git solves DISTRIBUTION. It does not solve INITIAL TRUST,
> and it solves ROTATION only for the voluntary case — see the compromise
> correction below. Left alone, push access becomes impersonation power.**
>
> In a repository with twenty collaborators, twenty people can replace Alice's
> key file with their own and impersonate her to everyone who pulls. Branch
> protection and CODEOWNERS help, but they are forge policy rather than
> cryptography, and they do not survive a fork or a self-hosted mirror.

**So each key file is self-signed, and a rotation is signed by the key it
replaces.** A repository writer who tampers then produces a file that *fails
verification* rather than one that verifies as someone else — **the failure
degrades to denial of service, not to forgery.**

> ⚠️ **BUT OLD-SIGNS-NEW IS NO DEFENCE AGAINST COMPROMISE, and an earlier draft
> of this document implied otherwise.** CireSnave caught it:
>
> > *"If a compromised key is used to sign its replacement key isn't that
> > effectively no security at all?"*
>
> **A voluntary rotation and a compromise-takeover are cryptographically
> identical.** Both are a valid signature by the current key over a new key.
> **Nothing in the signature distinguishes them.** An attacker holding Alice's
> key rotates the identity to their own, pushes it, and every peer who pulls
> trusts them as Alice — while Alice's competing rotation is equally valid. The
> mechanism is most useless in precisely the case it looks like it covers.
>
> **So the discriminator has to come from outside the cryptography.**

**Each mechanism defends exactly one case, and they must not be conflated:**

| Threat | What defends it |
| --- | --- |
| A repo writer WITHOUT the key substitutes a file | **Self-signature.** The file fails verification: denial of service, not forgery. |
| Alice VOLUNTARILY rotates | **Old-signs-new.** Proves continuity; no out-of-band step needed. |
| **Alice's key is COMPROMISED** | **Neither.** Out-of-band re-establishment, plus the rotation being a reviewable commit. |

**What makes the third case survivable here is that the repository is a REVIEWED
channel.** A key rotation is a commit — visible, attributed, and reviewable by
the other collaborators, unlike a silent update to a directory service. Git does
not prevent the takeover; it makes it **loud**, and a rotation that Alice did not
perform is a rotation Alice's collaborators can see and challenge.

That is weaker than a cryptographic guarantee and it should be described as
weaker. It is also the same answer already recorded above: **account-key
compromise is recovered by the two humans re-exchanging out-of-band.** The
correction is that git-carried rotation does not remove that obligation, and the
earlier draft read as though it did.

**An option not yet decided — countersignature.** In a project that already has
a set of mutually-known collaborators, a rotation could require signatures from
N existing key holders rather than only from the key being replaced. That does
defend the compromise case cryptographically, at the cost of coordination every
time someone rotates. **Attractive for a 20-collaborator project, heavy for a
two-person one.** Listed under Still open rather than chosen.

First contact still requires the out-of-band exchange, once, per peer, **and so
does recovery from a compromised account key.** Git carries the routine
traffic between those two events — which is the part that does not scale with
humans, and is most of the lifetime of a key.

#### Scheme B — one repository per account holder (CHOSEN)

**CireSnave's refinement:**

> *"Each account holder could add their public key to a separate repo that only
> they control. That would mean their git account would have to be compromised
> in order to compromise their key and, even then, no one else's key would be
> endangered."*

Correct, and stronger than stated.

**It removes shared fate.** In a shared project repository, one compromised
collaborator out of twenty can substitute all twenty keys. A single gatekeeper
(CODEOWNERS pointing at one person) is worse in kind rather than better: that
person's forge account becomes the master key for every identity in the project,
they block rotation whenever unavailable, and their protection is a settings
toggle a fork silently drops. **Both schemes recreate a party who must be
trusted, inside a design whose whole point is that nobody is believed.**

Per-account repositories have no shared file, no shared repository and no shared
gatekeeper. **Compromising Bob's forge account yields Bob's key and nothing
else.**

> ⚠️ **AND IT INTRODUCES A SECOND FACTOR, which narrows the rotation hole above.**
> Publishing a key requires the holder's FORGE account — a credential entirely
> separate from their FAM account key.
>
> ```
> thief holds the FAM KEY only    -> can forge messages, but CANNOT publish a
>                                    rotation or suppress the real revocation.
>                                    Alice revokes, peers pull, thief is cut off.
> thief holds the FORGE ACCOUNT   -> can publish, but holds no old key to sign a
>                                    valid rotation with.
> ```
>
> **A full takeover needs BOTH.** Defence in depth rather than a cryptographic
> guarantee — two independent credentials, not a proof — but it turns
> "old-signs-new gives nothing" from a hole into a substantially narrowed one.

**It also answers a question Scheme A could not:** which repository is
authoritative when an agent works across several. **The holder's own, always.**
Alice publishes once; every project she joins reads the same place.

#### Where exactly: the forge's own per-user repository

**CireSnave:** *"GitHub already has a repo for user information. My ciresnave
GitHub account has a ciresnave repo."*

**That is the right location and it removes the pointer problem.** GitHub's
profile repository — `github.com/<user>/<user>` — is owned solely by that user,
writable only by them, and **named deterministically**. Knowing the username
gives the location by construction, so no directory, no pointer file and no
lookup service is needed to find a key.

⚠️ **But the CORE must not know this.** A protocol that hard-codes GitHub has
learned what a forge is — the same concept-smuggling refused when a bare `cwd`
key was rejected and when the durability check was moved out of the core. So:

```
CORE      stores an opaque location string. Never parses it, never fetches it.
ADAPTER   knows the convention "github.com/<user>/<user>", and that other
          forges and self-hosted git exist.
```

**Convention, not requirement.** It makes the common case need no configuration
at all while leaving anyone who does not use GitHub — or who prefers a
self-hosted remote — a location field that works identically.

**What it costs, named rather than discovered:** trust moves onto forge-account
security, which is the same class as email-account compromise and is **the
holder's own risk rather than a shared one**; a verifier fetches N small
repositories instead of one, which is cacheable; and a username change moves the
conventional location, so the stored location must remain the authority rather
than being re-derived from a name each time.

**Unchanged by any of this:** first contact is still the out-of-band exchange.
Nothing here tells Bob that a repository is *Alice's* — only that whoever
controls it has been consistent.

**But it becomes a much cheaper exchange.** Instead of comparing a key
fingerprint, the two people exchange **forge usernames** — something they very
likely already know about each other, and which carries a public history that a
freshly minted key does not.

⚠️ **Weaker in one specific way, and worth knowing:** a username can be
typosquatted in a way a fingerprint cannot. `github.com/ciresnave` and a
lookalike are one glyph apart, and a key comparison has no such failure mode.
**The mitigation is that a forge account has a visible history — commits,
organisations, collaborators — so a wrong one is unusually easy to notice.**

#### The same repository answers discovery

**CireSnave:** *"If we know where they push their git repos, we know their keys,
agents, etc."*

**The account holder's repository carries the server address alongside the
key**, so finding a peer's FAM server is the same fetch that finds their key. No
DNS, no rendezvous service, no directory to run.

**And here the address can be SIGNED**, which is better than the untrusted phone
book described earlier: it is published in a repository only the holder can push
to, and can additionally be signed by their account key. A peer reading it knows
both where to connect and that the holder said so.

```
github.com/<user>/<user>
  fam/account.pub     the account public key
  fam/server          where this holder's FAM server currently is
```

⚠️ **But NOT the agent roster.** Vouchers bind entity keys to the account key,
and they are verifiable by anyone holding that account key — so they travel over
FAM itself, signed, rather than being published. Two reasons:

- **Publishing the roster would reverse a decision already made.** FAM went to
  some trouble to avoid enumeration: grants may name accounts that do not exist,
  and error messages refuse to distinguish "not yours" from "no such entity". A
  world-readable list of every agent an account runs undoes that for no gain.
- **It would make routine work a git operation.** Creating an agent should not
  require a push.

**So the repository carries the ROOT OF TRUST and the ADDRESS — the two things a
peer cannot get any other way. Everything else flows in-band, signed.**

**The cost is a staleness window on the address.** A holder who moves machines
pushes, and peers reach them once they re-fetch. Cached addresses keep working
until then; a peer that cannot connect should re-fetch before concluding the
peer is gone.

### Revocation has a staleness window, and it needs two paths

Git is pull, not push: a peer does not learn of a revocation until they fetch.
So a revocation travels **both** ways — committed to the repository, and
propagated over FAM itself. Because it is signed, the FAM path needs no trust;
it is a faster copy of the same verifiable statement.

---

## Consent and addressing are different problems

An earlier draft ran these together and CireSnave separated them:

> *"We can temporarily make pairing manual but it is highly inconvenient…
> Account holders aren't going to tolerate having to manually change IP
> addresses for long."*

```
CONSENT   may these agents talk?   rare, deliberate, human, per project
ADDRESS   where is that server?    frequent, automatic, must never need a human
```

**Consent stays explicit** — an account holder states that one or more of their
agents may talk to one or more of another holder's, or to all of that holder's
agents. This was settled earlier and is unchanged.

**Addressing must be dynamic.** The bar is a public project with 20+
collaborators whose IP addresses change. Manual entry fails that bar, and
"temporarily manual" must not become the shipped answer.

> **Signing makes this much easier: a directory that says where to connect does
> NOT need to be trusted.** If it lies, you fail to connect or reach the wrong
> host — and that host cannot forge a signed message. **The directory is a phone
> book, not an authority.**

Options, undecided: DNS-based discovery (needs a domain, which many
collaborators will not have); a rendezvous directory (untrusted, per above); or
the git repository carrying a current address alongside each key. **The last is
worth considering precisely because it reuses the mechanism already chosen** —
though it inherits git's staleness window, which matters more for addresses than
for keys.

---

## Replay: a signature proves authorship, not recency

Every signed statement — voucher, revocation, ruling, message — carries a
timestamp and a monotonic sequence per signing key. Without it an old voucher
can be replayed after its revocation.

**Small, and it has to be in the format from the start.** Adding it later means
every previously signed statement is ambiguous.

---

## What must not be built

- **Server identities or server-to-server trust.** Authenticity comes from
  signatures. A server that must be believed is a server that can lie.
- **Any path where the server holds an account private key.** It moves the blast
  radius of a compromise beyond the operator's own machine.
- **A trusted directory.** If discovery requires trust, the signature model has
  been given away for convenience.
- **Key files in git without self-signatures.** That is the version where repo
  write access becomes identity forgery.
- **A single gatekeeper approving all key changes.** It works mechanically and
  recreates a party who must be trusted: a bottleneck when unavailable, a single
  point of compromise whose forge account becomes the master key for every
  identity in the project, and a protection that is a settings toggle a fork
  drops silently.
- **Keys for several account holders in one repository others can push to.**
  Shared fate — one compromised collaborator substitutes everybody.
- **A core that knows what GitHub is.** The conventional location belongs to the
  adapter; the core stores an opaque string and never resolves it.
- **Treating the out-of-band exchange as optional** once git distribution works.
  Git carries keys; it does not vouch for the first one.

---

## Still open

1. ~~**Discovery mechanism.**~~ **SETTLED:** the account holder's own repository
   carries the server address beside the key, so discovery is the fetch that
   already had to happen. What remains is not a design question but a
   measurement — how long a stale address is tolerable before a peer re-fetches.
2. ~~**Countersigned rotation.**~~ **DISSOLVED, not decided.** It existed to
   solve "a compromised key signs its own replacement". Under per-account
   repositories that problem has no instance: **a rotation is not authorized by
   the FAM key at all — it is authorized by forge write access.** A thief holding
   the account key cannot publish anything. The mechanism has no job.

   ⚠️ **The property this chooses, stated so it is a decision rather than an
   inheritance: there is no cryptographic continuity on the root key.** Whoever
   controls the forge account controls the identity, with no signature chain
   linking a new key to the old one. Requiring the old key to *also* sign the new
   one would block a forge-compromised attacker — at the cost that losing the FAM
   key would force out-of-band re-establishment with every peer. **Chosen:
   recoverability over attack resistance**, because the account key is a human
   credential and humans lose those, while a forge account is one they already
   defend with 2FA.
3. **Whether entity keys are vouched individually or by a wildcard** ("all
   agents of this account"), which interacts with how consent is expressed.
4. **What a voucher and a revocation look like on the wire** — format, and where
   the sequence number lives.
5. **Whether messages are also encrypted**, not merely signed. Signing answers
   authenticity; confidentiality from the relay is a separate decision and is
   not required by anything above.
