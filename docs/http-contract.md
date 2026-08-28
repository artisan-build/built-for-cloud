# The Built for Cloud HTTP contract

This is the versioned public contract of every HTTP surface the `built-for-cloud` package mounts,
written for a consumer with **no PHP**: plain HTTP + JSON. Scalpels consumes exactly this contract;
so can a customer's own control plane, an internal app in any language, or a shell script. Any PHP
client the ecosystem ships is a convenience — **this document, not any client library, is the
contract** (GATE-3).

Every route below is verified mechanically: a package test enumerates the registered routes and
asserts each appears here, and that every route this document names is real. A route heading has
the form `### METHOD /path`.

One mounting switch exists, and only one: the surface-selection key (PRD 1.14,
`built-for-cloud.surfaces.routes`) can unmount this **entire HTTP surface as one family** —
for apps that use the package's store and CLI without serving its HTTP contract. No single
route is individually configurable, no route ever moves behind a prefix except the legacy
credential API's documented one, and an instance that serves any of this contract serves all
of it.

## Versioning and compatibility

Two discriminators, reported by [`GET /bfc/meta`](#get-bfcmeta):

- **`api_version`** (integer, currently **2**) — the contract's major version. It bumps whenever a
  **documented request or response shape changes incompatibly**: a field is removed or renamed, a
  type changes, or the semantics of an existing field change. It does **not** bump for additive
  changes.
- **`bfc_version`** (string, e.g. `0.4.0`) — the package release, for feature detection at finer
  grain than the major, alongside the `capabilities` array.

The rules a consumer may rely on:

1. **Additive changes do not bump `api_version`.** New response fields, new routes, new
   `capabilities` entries, and new enum values in fields documented as open sets may appear in any
   release. **Consumers must ignore unknown fields** and unknown capabilities.
2. **What you may pin:** the major `api_version` (pin `2`, refuse to talk to a higher major until
   updated), plus `bfc_version`/`capabilities` for feature detection. Do not pin exact response
   key sets, key order, or the full contents of `capabilities`.
3. **The version discriminator hierarchy:** branch on `api_version` first (wire compatibility),
   then on `bfc_version` or `capabilities` (feature presence). The `capabilities` array is
   feature-detection by membership, never by position.
4. On the claim surfaces, **the `error` enum is the contract** — branch on `error`, never on the
   HTTP status (statuses are stated as guidance and stable in practice).

### Changelog

**api_version 2** (bfc 0.5, this release). All changes since version 1, in one inventory.
Additive unless marked otherwise:

- `GET /api/credentials` listing rows gained `id`, `request_count`, `subject_type` (nullable),
  `subject_ref` (nullable), `status`, and `presentation_cadence_seconds` (nullable); the listing
  gained the `BFC-Presentation-Cadence` response header (present only when the app declares a
  cadence). *(These fields shipped across 0.4.x while `api_version` incorrectly stayed 1 — the
  stagnation this rule now forbids.)*
- New route `DELETE /api/credentials/id/{id}` — revoke-by-id, the precise verb.
- **Changed (the one non-additive change):** `DELETE /api/credentials/{name}` now returns
  `200 {"revoked_ids": [...]}` instead of an empty `204`. Callers that checked for any 2xx keep
  working; callers that assumed an empty body must read the new shape.
- New unified-store verb routes: `GET /bfc/credentials`, `POST /bfc/credentials`,
  `DELETE /bfc/credentials/{id}`.
- New rotation routes (PRD 1.7): `POST /bfc/credentials/{id}/rotate` and
  `POST /api/credentials/id/{id}/rotate` — rotate-by-id, the primary verb, on both stores.
  Unified-store summary rows gained the nullable `rotated_at` field (rotation provenance).
  Legacy rotation's replacement now inherits the source row's exact abilities, subject binding
  and remaining expiry (previously it was minted unscoped and non-expiring — the D6 defect), and
  name-based rotation refuses whenever more than one resolvable row shares the name. A row
  already superseded by rotation never mints again (the lineage never forks): with a live
  successor, re-invoking the rotate route performs the retirement-only **cutover completion**
  (a `200` with `completed_cutover: true` and no secret); without one it refuses. The
  onboarding exchange sweep spares unified-store rows in rotation grace, as it always has on
  `api_tokens` — where the exemption requires the shape rotation actually leaves (the stamp
  plus a grace-bounded expiry), and `rotated_at` is not mass-assignable, so the exemption
  cannot be forged.
- `GET /bfc/meta` `capabilities` gained `credentials`.
- `POST /bfc/onboarding/issue` requires `ttl_seconds` (bounds below) and accepts nullable
  `email`; the claim surfaces speak the claim-contract error enum documented here.
- New route `POST /bfc/invitations` — the machine-callable invite verb (PRD 1.13, SEC-V3-05):
  invitations ARE claim codes (hashed at rest, required bounded `ttl_seconds`, single-use
  `at_exchange` burn on accept), optionally addressed, optionally carrying an ordered
  integration event (namespace + stable event id + monotonic entitlement version + external
  subject). The human path answers `201` with the single reveal, shape-identical whatever the
  prior state; the integration path answers one uniform `202` acknowledgement carrying no
  invitation data, with delivery to an addressed invitee by mail. An addressed human invite
  supersedes prior pending invitations of the same email; an applying integration event
  supersedes only its own namespace+subject history.

- **The `hmac` kind ships (PRD 1.21 / D9, SEC-V3-01/07/08).** All additive. `POST
  /bfc/credentials` now mints `kind: "hmac"` — a per-subject symmetric signing key, born
  `pending`, encrypted at rest with a ciphertext key-version — with two new `delivery` shapes
  (`signing_key`, `signing_key_code`). `POST /bfc/onboarding/exchange` gains the signing-key
  response variant: exchanging a code linked to a pending hmac key delivers the key material
  and **never activates** — activation is the new separate operator verb
  `POST /bfc/credentials/{id}/activate`, which requires the **delivery fingerprint** the
  receiver confirmed (every signing-key delivery carries one), binding the cutover to the
  exact delivery installed. `POST /bfc/credentials/{id}/rotate` implements the hmac branch
  (previously a documented 403): rotate mints the replacement PENDING while the old key keeps
  signing; activation cuts over; the old key verifies through a one-hour grace window from
  activation. Every ciphertext-producing hmac path (mint, rotate, exchange redelivery) pauses
  while an APP_KEY rewrap is in progress. Summary rows are unchanged. The lifecycle event
  stream gains `activated`.

- New route `POST /bfc/claim` — the hitch claim contract (PRD 1.12 / OSS-8), additive: the
  same claim-code primitive as the onboarding exchange, in hitch's published wire shape
  (`claim_code` in, `200 {"version", "token", "name", "expires_at"}` out, the same error
  enum), unconditional at a fixed path.
- New route `POST /bfc/subjects/offboard` — the offboard verb (PRD 1.15, SEC-V3-04):
  full account containment behind the `subject:offboard` ability, riding the invite verb's
  shared integration version gate for integration-driven offboards. The lifecycle event
  stream gains `offboarded`.
- **The operator ability vocabulary ships (PRD 1.10 + GATE-3.7).** All additive, and a
  NARROWING only for credentials that never existed before it: the operator routes now
  authorize per verb family (`credential:read` / `credential:mint` / `credential:rotate` /
  `credential:revoke` / `subject:offboard` / `audit:read`), with `credential:admin` as the
  explicit admin-equivalent break-glass (every previously minted operator credential holds
  it, so nothing already issued loses access) and `mcp:read` / `mcp:admin` as the per-tool
  MCP pair. Operator writes are rate-limited (`bfc-operator-write`); operator sensitive
  reads, denials, and token-auth failures are audited (`sensitive_read` / `denied_action`
  lifecycle events, ids only).

**api_version 1** — the 0.3.x baseline: `/bfc/meta`, `/bfc/ownership/*`, the pre-0.4 credential
API listing shape.

## Authentication

- **Admin-token routes** (marked *admin token* below) require
  `Authorization: Bearer <token>` where the token is an `api_tokens` row carrying the `admin`
  ability — the row minted by the ownership claim, `token:create --local --abilities=admin`, or
  the credential API. Missing/unknown token → `401`; a valid token without `admin` → `403`.
- **Public routes** are unauthenticated but rate-limited per IP: `bfc-public` (60/min) and
  `bfc-claim` (10/min), returning `429` beyond the limit.
- **Operator routes** (the `/bfc/credentials`, `/bfc/invitations` and `/bfc/subjects` verbs)
  additionally accept a unified-store `operator` credential, authorized **per verb family**
  (GATE-3.7 least privilege). The ability vocabulary: `credential:read` (the listing — an
  audited sensitive read), `credential:mint` (mint + invitations), `credential:rotate`
  (rotate + the hmac activate cutover, same family), `credential:revoke`, `subject:offboard`,
  and `audit:read` (vocabulary now; the first audit-read surface will enforce it). The MCP
  pair `mcp:read` / `mcp:admin` is the per-tool vocabulary consuming apps wire in front of
  each MCP tool (read vs destructive administration — distinct grants, checked exact-match;
  no operator ability implies either). `metadata:read` remains RESERVED, unissued and
  unenforced. There is **no wildcard**; a credential with no abilities can do nothing. The
  one admin-equivalent name is **`credential:admin`** — the explicit break-glass, expanding
  to exactly the six operator abilities above (never the MCP pair); it is what
  `bfc:install:operator-credential` mints, and holding that literal name in the abilities
  list is how a break-glass credential is marked. A legacy admin `api_tokens` row remains
  admin-equivalent on these routes.
- **Operator rate limits:** write and expensive operator verbs (mint, rotate, activate,
  revoke, invite, offboard) are limited per operator credential + IP (`bfc-operator-write`,
  60/min, keyed on the sha256 of the presented bearer so failed-auth hammering shares the
  bound) under a global ceiling of 600/min, returning `429` beyond either.
- **Operator observability:** every operator sensitive read, denied action, and token-auth
  failure on the operator gate appends a `sensitive_read` / `denied_action` event to the
  audit stream — ids only, never presented secrets.
- Validation failures on JSON bodies return Laravel's standard
  `422 {"message": ..., "errors": {field: [...]}}` shape.

Secrets appear in exactly one place each: the response field documented as the **single reveal**.
No secret is ever retrievable again; store it on receipt.

## Endpoint classification

Every endpoint carries exactly one `classification`, chosen from its documented success-path
(2xx) response shape. This column is the durable privacy boundary that future vendor-side
surfaces (the product vendor's control plane and Console) rely on:

- **`metadata`** — the response carries bounded scalars and enum values only, no free-text
  strings. Safe for vendor-side reads.
- **`content`** — the response carries application data (free-text names, identities, prose,
  or any single-reveal secret). Content never transits the vendor.

Error responses are outside the column: every surface shares prose `message` fields, which are
server-generated operational text and — per the single-reveal rule above — never carry a secret.

| endpoint | classification | basis (success response shape) |
|---|---|---|
| `GET /bfc/meta` | `content` | `product` is an unbounded config-declared string; a future revision may bound it to reclassify |
| `POST /bfc/ownership/claim` | `content` | single reveal of `owner_token` and `webhook_secret` |
| `POST /bfc/ownership/release` | `content` | single reveal of the ownership claim code |
| `POST /bfc/ownership/cancel-transfer` | `metadata` | `{"ok": true}` — a bounded boolean |
| `POST /bfc/onboarding/issue` | `content` | single reveal of the claim code, plus a free-text email address |
| `POST /bfc/claim` | `content` | single reveal of the durable secret (`token`), plus the free-text suggested name |
| `POST /bfc/onboarding/exchange` | `content` | single reveal of the durable secret, plus the free-text credential name |
| `POST /bfc/onboarding/verify` | `content` | carries the free-text credential name |
| `POST /bfc/invitations` | `content` | single reveal of the invitation code, plus a free-text email address |
| `GET /api/credentials` | `content` | rows carry free-text names, subject refs and client identities |
| `GET /api/credentials/client-observations` | `content` | client-claimed free-text identities |
| `POST /api/credentials` | `content` | single reveal of the minted plaintext, plus the free-text name |
| `DELETE /api/credentials/id/{id}` | `metadata` | empty `204` body |
| `POST /api/credentials/id/{id}/rotate` | `content` | single reveal of the replacement plaintext |
| `DELETE /api/credentials/{name}` | `metadata` | `revoked_ids` only — bounded opaque identifiers |
| `GET /bfc/credentials` | `content` | summary rows carry free-text names and subject refs |
| `POST /bfc/credentials` | `content` | the `delivery` single reveal, plus free-text name/subject fields |
| `DELETE /bfc/credentials/{id}` | `metadata` | empty `204` body |
| `POST /bfc/credentials/{id}/rotate` | `content` | the `delivery` single reveal, plus summary rows |
| `POST /bfc/credentials/{id}/activate` | `content` | no secret ever — but the summary row carries free-text names and subject refs |
| `POST /bfc/subjects/offboard` | `metadata` | `{"offboarded": true, "fully_contained": bool}` / `{"accepted": true}` — bounded booleans only |

Vendor-side reads of `metadata`-classified endpoints will be governed by the reserved
`metadata:read` ability family (see [the Console reservations](#reserved--console-fast-follow-not-implemented)).

Vendor-side (Console) reads will want the version-discovery endpoint, so a future BEHAVIORAL
revision may constrain `product` to a bounded shape, letting `GET /bfc/meta` honestly become
`metadata`; until then it is `content`, because an unrestricted config string is
operator-authored free text.

---

## Metadata

### GET /bfc/meta

Public (`bfc-public` throttle). Identifies the instance.

**200**

```json
{
  "product": "Sink",
  "bfc_version": "0.4.0",
  "api_version": 2,
  "capabilities": ["tokens", "ownership", "onboarding", "webhooks", "credentials"],
  "claimed": true
}
```

`capabilities` is an open set — ignore unknown entries. `claimed` says whether an owner control
plane holds this instance.

---

## Ownership

### POST /bfc/ownership/claim

Public (`bfc-claim` throttle). Exchange a one-time ownership claim token for the owner's admin
token. The claim token comes from `bfc:ownership:mint-claim` (TTY, shown once) or from a
release handoff. The install migration's initial mint deliberately yields NO deliverable
token: its plaintext is dropped, never logged (the D7 fix — a logged claim token is an
admin-yielding secret in the application log), so an unclaimed environment re-mints with the
command.

**Request** — `{"token": "<claim token>", "notify_callback": "https://..." | null}`
(`notify_callback` optional: where ownership webhooks are delivered.)

- **201** — `{"owner_token": "...", "webhook_secret": "...", "product": "..."}` — the single
  reveal of both secrets. The owner token is an admin-ability `api_tokens` row with no expiry;
  ownership transfer, not a clock, ends its life.
- **401** — the claim token is unknown, expired, or already consumed.
- **409** — `{"message": "already claimed"}` — a live owner exists and no transfer is pending.

### POST /bfc/ownership/release

*Admin token.* Begin a make-before-break ownership transfer: mints a fresh one-time ownership
claim code for the successor. The current owner token keeps working until the successor claims.

- **201** — `{"ownership_claim_code": "..."}` — the single reveal.
- **409** — `{"message": "ownership is not claimed"}`.

### POST /bfc/ownership/cancel-transfer

*Admin token.* Cancel a pending transfer (consumes the outstanding claim code).

- **200** — `{"ok": true}`. Idempotent: also `200` when no transfer was pending.

---

## Onboarding — the claim-code primitive

Short-lived, optionally addressed, single-use codes exchanged for durable credentials
(make-before-break). The **error enum is the contract** on these surfaces; `message` is prose for
humans, printed verbatim by clients, and never carries a secret.

Error shape: `{"version": 1, "error": "<enum>", "message": "..."}` with enum values and their
advisory statuses:

| `error` | status | meaning |
|---|---|---|
| `invalid_code` | 400 | malformed input or no credential presented |
| `code_not_found` | 404 | nothing matches what was presented |
| `code_already_claimed` | 409 | the single-use code was already exchanged |
| `code_expired` | 410 | the code's ttl elapsed |
| `unsupported_version` | 400 | the server does not speak the requested contract version |
| `server_error` | 500 | unexpected failure; safe to retry |

### POST /bfc/onboarding/issue

*Admin token.* Mint a claim code.

**Request** — `{"email": "a@b.c" | null, "scope": "consume" | "admin" | "onboard", "ttl_seconds": 3600}`.
`ttl_seconds` is **required**, bounded 60–604800 (7 days) — the ttl lives on the code, never on
the durable it buys. `scope` defaults to `consume`. Issuing an addressed code supersedes any
pending code for the same address+scope but never touches a live durable credential.

- **201** — `{"claim_code": "...", "email": "a@b.c" | null}` — the single reveal of the code.

### POST /bfc/claim

Public (`bfc-claim` throttle). **The hitch claim contract** (PRD 1.12 / OSS-8): the wire face
any `hitch install <url> --claim <code> --claim-url <this route>` client — or anything else
speaking hitch's published claim contract — exchanges against. It runs the SAME single-use
claim-code primitive as [`POST /bfc/onboarding/exchange`](#post-bfconboardingexchange)
(make-before-break semantics included); only the field names and success status differ,
because the shape here is hitch's, not this package's. Mounted **unconditionally at this
fixed path** — never behind a configurable prefix, never behind its own env flag.

**Request** — `{"claim_code": "<claim code>", "version": 1}`. The code travels in the body,
never the URL. `version` is **required** — it is the contract version the client speaks
(hitch always sends it); a missing or non-`1` version is refused as `unsupported_version`,
and a malformed or missing `claim_code` is `invalid_code` (never a Laravel `422` — the enum
shapes every failure on this surface). The onboarding exchange keeps its documented
`version` default; only this hitch-conformant face is strict.

- **200** —

```json
{
  "version": 1,
  "token": "tok_…",
  "name": "ci",
  "expires_at": null
}
```

  `token` is the **single reveal** of the durable secret. `name` is the suggested server
  name (advisory — the client's own `--name` wins); `expires_at` is the durable's expiry as
  RFC 3339 or `null` (advisory). There is deliberately no `server_url` field. The response
  may grow additive fields; clients ignore what they do not know.

- Errors: the enum above, `{"version": 1, "error": "<enum>", "message": "..."}` — clients
  branch on `error`, never the status. A re-claim before the token's first use returns a
  usable token (a FRESH one; the pending previous mint is revoked in the same transaction —
  at most one live token per code, ever); after first use, `code_already_claimed`.
- A code that redeems a **signing key** is refused as `invalid_code` — before any burn, so
  the code stays presentable on `POST /bfc/onboarding/exchange`, the surface that can
  deliver it. The hitch success shape requires a bearer `token`, which a pending signing-key
  delivery cannot honestly fill.

### POST /bfc/onboarding/exchange

Public (`bfc-claim` throttle). Exchange a claim code for a durable credential.

**Request** — `{"token": "<claim code>", "version": 1}` (`version` optional, default 1).

- **201** — `{"durable_token": "...", "name": "..."}` — the single reveal of the durable secret.
- Errors: the enum above. A re-exchange of a consumed code is `code_already_claimed`.

Semantics: exchange is **make-before-break** — it mints the fresh durable and, in the same
transaction, revokes the durable a previous exchange of this code minted (and any live durable of
the same name+scope not governed by another pending code and not a rotation-grace row). Where the
code burns depends on the app's declared burn mode: `at_exchange` consumes the code at redemption;
`first_use` (the default) consumes it the first time the minted durable authenticates.

**The signing-key variant (PRD 1.21, SEC-V3-01).** A code issued for an hmac credential (the
`signing_key_code` delivery of the mint and rotate verbs) exchanges into the PENDING signing
key instead of a durable token:

- **201** — `{"signing_key": "...", "key_id": "...", "kind": "hmac", "status": "pending",
  "delivery_fingerprint": "..."}` — the single reveal of this delivery. **The exchange delivers
  and NEVER activates**: the key remains `pending`, signs nothing and verifies nothing, and
  live signing state is untouched — an inbox interceptor who redeems the link gains dead bytes
  and flips nothing. Activation is the separate operator verb below, and **it binds to this
  exact delivery**: `delivery_fingerprint` is a non-recoverable hash naming this delivery of
  this key (never the key itself); the receiver quotes it back when confirming installation
  out-of-band, and the activation verb requires it — so a redelivery that re-keys the row after
  a confirmation makes that confirmation stale rather than activating key material the
  confirmer never saw. The receiver installs the key (indexed by `key_id`), confirms the
  fingerprint, and the operator activates with it.

Where the hmac code burns follows the declared burn mode exactly as above: under `at_exchange`
a second presentation — the legitimate receiver behind an interceptor — fails loudly as
`code_already_claimed`; under `first_use` (the default) **activation is this kind's first
observable use** and consumes the code, and a re-claim before activation (the dropped-response
case) answers with a FRESH key for the same `key_id` — the pending row is re-keyed in place, so
every previously delivered plaintext is dead, its `delivery_fingerprint` with it, and at most
one live pending delivery per code ever exists. A redelivery attempted while an APP_KEY rewrap
is in progress answers the retryable `server_error` (the re-key writes a fresh ciphertext, and
every ciphertext-producing path pauses mid-cutover); the FIRST delivery of a code still works
through the staged cutover window — it only reads through the keyring — though while the
`bfc:hmac:rewrap` sweep itself is RUNNING (minutes, not the whole window), every signing-key
delivery briefly answers the same retryable `server_error`: deliveries and the sweep's
completion verification share one lock, so no write can straddle the verified zero-count.

Which store the durable lands in is the app's declaration: `api_tokens` by default; an app
rebuilt on the unified store receives a `credentials` row instead (same wire shape here either
way — the difference is visible in which listing the row appears in). Each code records which
store its durable was minted into, and make-before-break always revokes in the RECORDED store —
so an app switching stores between exchanges never strands a still-live durable in the old one
(the name/scope sweep covers the current target store plus the recorded store of the code's own
linked durable).

### POST /bfc/onboarding/verify

Public (`bfc-public` throttle). Verify a durable credential works. Present it as
`Authorization: Bearer <durable token>`. For `first_use` apps this is a use — the first
verification burns the claim code that minted the credential.

- **200** — `{"ok": true, "name": "...", "scope": "consume"}`.
- **400 `invalid_code`** — no credential presented; **404 `code_not_found`** — nothing live
  matches.

### Envelope versioning and reserved extensions

The claim handshake is versioned end to end: the exchange request carries `version` (default
`1`), the error envelope answers with its own `version`, and a server that does not speak a
requested version refuses with `unsupported_version` rather than guessing. Compatibility rule 1
applies to these surfaces exactly as everywhere else: **the claim-surface response envelopes —
the ownership claim's and the onboarding exchange's alike — may grow additive fields in any
release without an `api_version` bump**, and consumers must ignore fields they do not recognize.

Two extension slots are RESERVED by name — documented intent only, not implemented, carrying no
fields and no routes in this release:

- **A countersigning-key exchange at claim time.** A future revision may add additive
  key-exchange fields to the claim/exchange envelopes so the two parties can countersign at
  claim. No key material of any kind travels on these surfaces today.
- **A re-key verb for already-claimed apps.** A future additive route letting an app that has
  already claimed re-run the key exchange without re-onboarding. New routes are additive under
  rule 1.

Neither reservation changes any request or response shape in this release.

---

## Invitations — the invite verb

Invitations are claim codes for HUMANS (PRD 1.13, D4 + D1e): hashed at rest, single-use with an
`at_exchange` burn, optionally addressed, and what one buys is not a secret but an
account-creation ceremony inside the consuming app (`Invitation::accept()` creates the app's
user; acceptance is an app surface, not an HTTP route here). The verb is machine-callable by
design (D1e): an operator's integration triggers the INVITATION — it never mints a key, because
minting would hand the integration a plaintext credential to deliver.

### POST /bfc/invitations

*Admin token or operator credential* — the same gate as the `/bfc/credentials` verb routes; the
same two-transport rule (`bfc:invitation:issue --local` runs the identical action).

**Request:**

```json
{
  "email": "person@example.com",
  "ttl_seconds": 86400,
  "invited_by": "42",
  "role": "member",
  "integration_namespace": "github-sponsors",
  "event_id": "evt_0001",
  "entitlement_version": 7,
  "external_subject": "sponsor-login"
}
```

`ttl_seconds` is **required**, bounded 60–604800 (7 days) — the invitation is a claim code and
never defaults its lifetime. `email` is optional: omitted issues an OPEN code whose registrant
supplies their own address at accept; provided, the address is forced onto the created user and
the recipient is notified through the app's lifecycle-notification policy (an unaddressed
invitation notifies nobody). `invited_by` is a nullable free-text inviter reference (max 64
characters); `role` is stored and never interpreted — the app's accept hook projects it. The
other free-text fields are bounded to 255 characters; oversize input is a `422` on both
transports.

**Supersession, scoped precisely:** issuing an addressed HUMAN invitation consumes every prior
pending (unaccepted, unexpired) invitation of the same email — an issuer replaces a code by
issuing again, and the old link then refuses as `code_already_claimed`. An APPLYING integration
event consumes ONLY its own (namespace, external subject) pending history — never another
namespace's invitation, and never a human invitation that happens to share the recipient
address. Open, non-integration codes supersede nothing (there is no subject to match).

The four integration-event fields are **all-or-none** (SEC-V3-05): a plain human-issued invite
carries none; a machine-issued event carries every one. `entitlement_version` is a whole number
bounded to **[1, 9007199254740992]** (2^53 — exactly representable by every JSON producer);
values outside the range are rejected, never truncated or saturated. The version gate stores
the latest accepted version per (`integration_namespace`, `external_subject`) and
**transactionally ignores any event whose version is not newer**; a replayed `event_id` answers
idempotently — same response, no second invitation, no state change — and a replay after the
invitation was accepted does not resurrect it. Concurrent deliveries racing a gate-row create
are re-decided against the winner — up to **3 whole transactional attempts** per request
(one request can lose the entitlement race and then the event-id race); past the bound the
verb answers a clean `500 {"message": ...}` with **no partial state** — nothing was applied,
and retrying is safe.

**The two response shapes, keyed on the REQUEST (never on state):**

- **Human path (no integration event): `201` — always issues, always reveals**,
  shape-identical for a fresh subject, a re-invite, and a subject who already accepted:

```json
{
  "invitation_id": "9d3f..." ,
  "invitation_code": "…the single reveal…",
  "email": "person@example.com"
}
```

  `invitation_code` is the **single reveal** — the code exists nowhere else and is never
  retrievable again; the human issuer delivers it as an accept link.

- **Integration path: `202 {"accepted": true}` — always**, whatever the gate decided
  (applied, ignored-older, or replayed): the event is acknowledged and the body carries **no
  invitation data**, so even an authorized caller cannot probe gate state from the response.
  Delivery is the instance's job (D1e — the integration triggers; the instance delivers): an
  ADDRESSED applying event mails the invitee the invitation code after the transaction
  commits, and that mail is the code's one documented egress on this path. An event with no
  `email` is acknowledged and its invitation has no delivery channel — deliver via the
  admin/human surfaces by issuing an addressed invitation, which supersedes it. Response
  TIMING is best-effort uniform only: an applying event does more work than an ignored one,
  and the difference is not masked.

- **403** — `{"message": "..."}`: the declaration's verb matrix denies `issue` for the invited
  subject. Identical refusal on the CLI transport.
- **422** — `{"message": "..."}`: shared input validation — missing/out-of-bounds
  `ttl_seconds`, a malformed email, an out-of-bounds or non-integer `entitlement_version`, an
  over-length field, or a PARTIAL integration-event group. Identical refusals on the CLI
  transport.

**Authority note:** the version gate trusts any caller this route's gate admits — any admin
token or `credential:mint`/`credential:admin` operator credential can advance any
integration namespace. The 1.10 ability vocabulary is per **verb family**, deliberately not
per namespace; give each integration its own credential for AUDIT attribution, not
authority isolation.

Emits an `issued` audit event (ids only, never the code) in the issue's own transaction; the
app's accept surface emits `exchanged` the same way.

---

## The legacy credential API (`api_tokens` store)

Disabled by default; an app enables it with `BUILT_FOR_CLOUD_CREDENTIAL_API_ENABLED=true`. Its
prefix is configurable (`BUILT_FOR_CLOUD_CREDENTIAL_API_PREFIX`); this document uses the default
`api/credentials`. All routes: *admin token*.

### GET /api/credentials

List every `api_tokens` row. Rows the app's declaration denies `list_metadata` for are filtered
out (a blanket deny is an empty `200 []`, not a `403`).

**200** — an array (bare, unenveloped — pinned for compatibility) of:

```json
{
  "name": "ci",
  "last_used_at": "2026-08-28T12:00:00.000000Z",
  "expires_at": null,
  "revoked_at": null,
  "abilities": ["consume"],
  "client_identity": "client-a" ,
  "client_identity_last_seen_at": null,
  "id": "9d3f...",
  "request_count": 12,
  "subject_type": "external_consumer",
  "subject_ref": "acme",
  "status": "active",
  "presentation_cadence_seconds": null
}
```

`subject_type`/`subject_ref` are null on rows that predate subjects — never guessed. `status` is
`active` / `expired` / `revoked` / `unknown`; **`unknown` never escalates to a failure state** (it
means the row structurally cannot carry a usage signal), and the instance-reported status is an
input to the consumer's own health mapper, never a verdict. `presentation_cadence_seconds` is the
app's declared presentation rhythm (null = none declared); when declared it is also sent once as
the `BFC-Presentation-Cadence` response header.

### GET /api/credentials/client-observations

Identities claimed on requests that presented **no valid credential**. Advisory and spoofable by
design — the payload says so itself.

**200** — `{"enabled": bool, "advisory": true, "spoofable": true, "note": "...",
"at_capacity": bool, "max_observations": 100, "observations": [{"client_identity": "...",
"first_seen_at": "...", "last_seen_at": "...", "observation_count": 3}]}`. `observations` is
`[]` while the feature is disabled (`enabled` distinguishes "off" from "on and quiet").

### POST /api/credentials

Mint an `api_tokens` row.

**Request** — `{"name": "ci", "expires_at": "2027-01-01T00:00:00Z" | null,
"abilities": ["consume" | "admin" | "onboard"] | null}`. The name `fallback` is reserved
(`422`). A declaration denying the `issue` verb → `403`.

- **201** — `{"name": "ci", "plaintext": "tok_...", "expires_at": ..., "abilities": [...]}` —
  the single reveal. Emits an `issued` audit event.

### DELETE /api/credentials/id/{id}

Revoke exactly one row — the precise verb. A same-named sibling (a rotation-grace row, another
install's credential) survives.

- **204** — revoked, or already dead (idempotent — one death, one audit event).
- **404** — no such id. **403** — the declaration denies `revoke` for the row's subject.

### POST /api/credentials/id/{id}/rotate

Rotate exactly one row — the primary rotation verb on this store. Make-before-break: the
replacement is minted FIRST, inheriting the source row's **exact abilities, subject binding and
remaining expiry**; the old row is stamped `rotated_at` and stays resolvable through a one-hour
grace window (unless its own expiry comes sooner — rotation never extends a lifetime), then dies
by its own expiry. No reaper is involved.

**Request** — `{"emergency": false}`. `emergency: true` collapses the grace window: the old row
dies immediately.

- **201** — `{"id": "...", "name": "ci", "plaintext": "tok_...", "expires_at": ...,
  "abilities": [...], "superseded_id": "..."}` — the single reveal, plus the supersession
  lineage. Emits `issued` (replacement) and `rotated` (old row, carrying old → new lineage)
  audit events in the mint's own transaction.
- **404** — no such id. **403** — the declaration denies `rotate` for the row's subject.
- **200 — cutover completion.** Invoking this route on a row already superseded by rotation
  (`rotated_at` set) whose lineage-recorded successor still resolves never mints again — it
  retires the stamped row (immediately with `emergency: true`) under the `rotate` verb's own
  authority, audited with reason `cutover_completion`. The body names the standing successor
  and carries **no `plaintext`** (nothing was minted):
  `{"id": "<successor>", "name": ..., "expires_at": ..., "abilities": [...],
  "superseded_id": "<retired row>", "completed_cutover": true}`.
- **409** — `{"message": "..."}`: the row no longer resolves (revoked or expired) — there is
  nothing to rotate; mint a replacement instead — or it was already superseded by rotation and
  its successor no longer resolves: nothing to complete, and re-rotating would fork the
  lineage; mint a fresh credential.
- **500** — `{"message": "..."}`: the replacement was minted but the old row could not be
  retired. The message names both ids: the old row is STILL LIVE (listed, `rotated_at`
  stamped). Recovery needs no authority beyond the rotation itself: invoke this route on the
  stamped row again (the 200 completion above), or `DELETE /api/credentials/id/{id}` where
  revoke is authorized; no plaintext was delivered, so rotate the standing replacement for a
  fresh delivery, or revoke it by id if unneeded.

Name-based rotation survives only as the `token:rotate` CLI convenience, and it now **refuses
whenever more than one resolvable row shares the name** — it never picks one. Rotate by id here
instead.

**Names are byte-exact identifiers.** Everywhere a name selects rows — this store's name-based
revoke and the CLI's name-based rotation alike — the match is on the exact bytes stored:
nothing is trimmed, and no case normalization is applied, so `CI` and `ci` are two different
names to the package. One caveat rides on the consuming app's database: a case-insensitive
column collation (MySQL's `utf8mb4_0900_ai_ci` default among them) makes the DATABASE compare
names the package treats as distinct as equal, which can only widen a name's match set — and a
widened set trips the refuse-on-ambiguity rule rather than touching an unintended row.

### DELETE /api/credentials/{name}

Revoke EVERY resolvable row of the name — the CLI-compatibility verb. Fails closed against the
declaration: if any resolvable row of the name is denied, nothing is revoked.

- **200** — `{"revoked_ids": ["..."]}` — the ids that actually died (a name can resolve to
  several rows, or to fewer than assumed under a narrowing declaration).
- **403** — some row of the name is denied.

The two-segment `/id/{id}` path exists so a token literally named `id` still deletes by name here.

---

## The unified credential store (`/bfc/credentials`)

The two-transport verbs (PRD 1.0): each of these routes runs the **same action class** as its
`--local` artisan command (`bfc:credential:mint` / `list` / `revoke`), so the two transports
cannot diverge. Always mounted, at a fixed path. Rotation for this store ships in a later
release.

**Authentication on these routes** accepts either credential shape:

- a legacy **admin `api_tokens` token** (exactly what every other admin route accepts —
  admin-equivalent on every verb), or
- a **unified-store `operator` credential** holding the route's **verb-family ability**
  (see [Authentication](#authentication)): `credential:read` for the listing,
  `credential:mint` for mint, `credential:rotate` for rotate AND activate,
  `credential:revoke` for revoke — or the explicit admin-equivalent `credential:admin`,
  which is what `bfc:install:operator-credential` mints at install time, so a fresh install
  can manage its credentials with the one secret it was handed. A valid unified credential
  without the verb's authority is `403` (and the denial is audited); the deprecated
  `FALLBACK_TOKEN` is explicitly rejected with a distinguishable `403` message. Audit actors
  reflect the store that authenticated (`admin_token` vs `operator_integration`). Write
  verbs ride the `bfc-operator-write` limiter.

**The scope of the transport-parity guarantee:** parity is defined over the verb's own inputs —
the subject, the options, the abilities, the target row. The declaration's `authorizeVerb` hook
receives each transport's real request by design (subject derivation needs real context), so a
declaration that keys its authorization on request internals (headers, IPs, session state)
introduces app-owned divergence between the transports. That divergence is the app's choice and
its responsibility — it is outside what this contract (and the shipped parity suite) guarantees.

Input validation is shared: both transports normalize options through one input object and
reject the same junk with the same message (HTTP as a `422 {"message": ...}`, the CLI as a
failure exit). A non-integer `code_ttl_seconds` (e.g. `"60junk"`) is rejected, never truncated;
a negative one hits the same bounds error on both transports. `abilities` is bounded: at most
32 entries, each at most 128 characters. **An empty `abilities` list normalizes to `null`** —
both grant nothing, and summaries always serialize the one canonical shape (`null`).

Summary rows share one shape:

```json
{
  "id": "9d3f...",
  "kind": "bearer",
  "subject_type": "external_consumer",
  "subject_ref": "acme",
  "name": "ci" ,
  "abilities": ["consume"],
  "status": "active",
  "created_at": "2026-08-28T12:00:00+00:00",
  "last_used_at": null,
  "expires_at": null,
  "revoked_at": null,
  "rotated_at": null,
  "presentation_cadence_seconds": null,
  "unsupported": []
}
```

`kind` is `bearer` / `basic` / `asymmetric` / `hmac`; `status` is `pending` / `active` /
`expired` / `revoked` (`unknown` reserved). **`unsupported` is the declared-unsupported
discrimination:** a field named there is one the app's declaration says this store structurally
cannot express — it is serialized null *and* listed, so null-and-listed means "unknowable here"
while null-and-not-listed means "absent". Consumers must not render or alert on unsupported
fields. `rotated_at` is rotation provenance: non-null names a row superseded by rotation and
living out its grace window — expected to appear beside its active replacement until the grace
expiry passes.

### GET /bfc/credentials

**200** — an array of summary rows, oldest first. Per-row `list_metadata` filtering as in the
legacy listing; `BFC-Presentation-Cadence` header when a cadence is declared.

### POST /bfc/credentials

Mint a credential for a **subject** — `mint(Subject, MintOptions)`; there is no mint-by-id,
because the row does not exist yet.

**Request:**

```json
{
  "subject_type": "external_consumer",
  "subject_ref": "acme",
  "kind": "bearer",
  "name": "ci",
  "abilities": ["consume"],
  "expires_at": null,
  "user_id": null,
  "code_ttl_seconds": null
}
```

`subject_type` and `subject_ref` are required; everything else optional. `expires_at` omitted
means **no expiry** — the package never defaults one. `code_ttl_seconds` is required (60–604800)
when `kind` is `asymmetric`; for `kind: "hmac"` it is **optional and selects the delivery**
(present → a claim code for an outside counterparty; absent → the reveal-once `signing_key`
delivery for a counterparty the operator controls); it is ignored otherwise.

**The `hmac` kind** (PRD 1.21 / D9) is a per-subject symmetric signing key. The row is born
**`pending`**: a pending key signs nothing and verifies nothing until the separate
[activation verb](#post-bfccredentialsidactivate) cuts it over (SEC-V3-01). Stated honestly
(D9.1): the key is stored **encrypted, not hashed** — both sides need it to sign — so hmac is
the one kind whose secret a database-plus-APP_KEY compromise yields; that is intrinsic to
symmetric signing and industry-normal for webhook secrets, and the `asymmetric` kind is the
upgrade path for any case that cannot accept it.

- **201:**

```json
{
  "credential": { "…": "a summary row as above" },
  "delivery": { "shape": "bearer", "secret": "tok_..." }
}
```

`delivery` is the **single reveal**, shaped by `delivery.shape`:

| `shape` | fields | meaning |
|---|---|---|
| `bearer` | `secret` | present as `Authorization: Bearer <secret>` |
| `basic_auth` | `username`, `password` | the Composer `auth.json` pair; the username is presentation-only and grants nothing |
| `enrollment_code` | `enrollment_code` | a claim-primitive code (ttl = `code_ttl_seconds`); the client redeems it by generating its own keypair. The code never carries key material, and the credential row is `pending` until enrollment completes. The enrollment-completing exchange ships with the first asymmetric consumer's rebuild; until then the code is issued, listable and revocable, but completes no enrollment |
| `signing_key` | `signing_key`, `key_id`, `delivery_fingerprint` | the reveal-once delivery of a PENDING hmac signing key — the operator-controlled-counterparty path. `key_id` is the (non-secret) row id the signature header will carry; `delivery_fingerprint` (non-secret) names THIS delivery, and the activation verb requires it. The key signs nothing until activated |
| `signing_key_code` | `claim_code` | a claim-primitive code (ttl = `code_ttl_seconds`) whose [exchange](#post-bfconboardingexchange) delivers the PENDING hmac key — and its `delivery_fingerprint` — to an outside counterparty, and **never activates it** (SEC-V3-01) |
| `none` | — | the secret was never ours to hand over |

- **403** — `{"message": "..."}`: the declaration denies `issue` for this subject, the request
  widens abilities or lifetime past a declared ceiling, or sets a declared-unsupported field.
  Identical refusals on the CLI transport.
- **409** — `{"message": "..."}`: an hmac mint while an APP_KEY rewrap is in progress — every
  ciphertext-producing path pauses mid-cutover; retry after `bfc:hmac:rewrap` completes.
- **422** — validation (unknown `subject_type`/`kind`, out-of-bounds `code_ttl_seconds`, …).

Emits an `issued` audit event (ids only, never values) in the mint's own transaction, on both
transports.

### DELETE /bfc/credentials/{id}

Revoke by id — the precise verb; `pending` enrollments are revocable too, and revoking one also
consumes its outstanding enrollment code.

- **204** — revoked, or already dead (idempotent — one death, one `revoked` audit event).
- **404** — no such id. **403** — `{"message": "..."}` per the declaration's `revoke` verb.

### POST /bfc/credentials/{id}/rotate

Rotate by id — the primary verb (there is no name path over HTTP; `bfc:credential:rotate
--name` is a CLI convenience that refuses on ambiguity). Make-before-break: the replacement is
minted FIRST, then the old row is retired into its grace window.

**Default rotation preserves EXACTLY**: the ability set, the subject binding
(`subject_type` / `subject_ref` / `user_id`), the decorative name, and the remaining expiry of
the row it replaces — never widening, never lifetime extension, silently. The old row is
stamped `rotated_at`, stays resolvable through a one-hour grace window (unless its own expiry
comes sooner — rotation never extends any lifetime), and dies at grace end by its own expiry.
No reaper is involved.

**Request:**

```json
{
  "emergency": false,
  "override": false,
  "abilities": null,
  "expires_at": null,
  "code_ttl_seconds": null
}
```

Everything is optional, and **presence is the signal**: an ABSENT `abilities` / `expires_at`
always means "preserve the source's", while a PRESENT one requests a changed replacement —
including "explicitly none": `"expires_at": null` overrides a finite expiry to NO expiry, and
`"abilities": []` narrows to NO abilities (which grant nothing). `emergency: true` kills the
old row immediately instead of granting grace.

A provided change is consumed only under `override: true` — any change without the flag,
**narrowing included** (predictability beats cleverness), is refused with a `422`; the flag
with nothing provided is refused the same way. The override is a SEPARATELY authorized
operation, and it **fails closed**: the app's declaration must explicitly opt in by
implementing the dedicated `AuthorizesRotationOverrides` hook (which receives the requested
delta), and a declaration that has not opted in denies every override — routine (preserving)
rotation is unaffected. An authorized override must ALSO fit the same ceilings the mint verb
enforces: it is refused (`403`, same messages as mint) if the replacement's effective abilities
or lifetime — inherited dimensions included — exceed what a mint of that shape could have been
authorized for. Its audit events record the `override` reason code plus the delta.
`code_ttl_seconds` (60–604800) is required when rotating an `asymmetric` credential; optional
for `hmac`, where it selects claim-code delivery over the reveal-once default; ignored
otherwise.

Per kind:

| kind | rotation semantics |
|---|---|
| `bearer` / `basic` | a fresh secret is minted and delivered once, in this response's `delivery` (same shapes as the mint route) |
| `asymmetric` | a fresh **enrollment code** is delivered against a new `pending` row — the client generates the new keypair itself; no key material ever travels. The old credential's public key keeps verifying through the grace window, so both rows are listed side by side. The enrollment-completing exchange ships with the first asymmetric consumer's rebuild |
| `hmac` | the pending→activate dance (D6 point 6 / D9): rotate mints the replacement key **`pending`** — delivered in this response's `delivery` (`signing_key` reveal-once, or `signing_key_code` when `code_ttl_seconds` is provided) — while **the old key keeps signing, unretired**. Delivery installs it receiver-side; [activation](#post-bfccredentialsidactivate) cuts signing over and starts the old key's one-hour verification grace; the old key dies at grace end. `emergency: true` kills the old key **now** instead (a compromised key must not keep signing), at the stated price of a signing outage until the replacement activates. Re-invoking rotate on the stamped row while the replacement is still pending is a `409` pointing at the activate verb; hmac rotation is refused (`409`) while an APP_KEY rewrap is in progress |

- **201:**

```json
{
  "credential": { "…": "the replacement's summary row" },
  "superseded_id": "the old row's id",
  "delivery": { "shape": "bearer", "secret": "tok_..." }
}
```

`delivery` is the **single reveal**, exactly as on `POST /bfc/credentials`. Emits `issued`
(replacement) and `rotated` (old row, with old → new supersession lineage) audit events in the
mint's own transaction; if any of those follow-up writes fail, EVERYTHING rolls back — no
orphan credential — and retrying works.

- **200 — cutover completion.** Invoking this route on a row **already superseded by
  rotation** (`rotated_at` set) whose lineage-recorded successor is still live never mints
  again — the lineage never forks. Instead it performs the narrowly-scoped retirement the
  original rotation still owed (or, with `emergency: true`, kills a compromised graced old
  row immediately), under the `rotate` verb's own authority — no `revoke` authority is
  consulted, and it is not a revoke bypass: an unstamped row always gets the full
  make-before-break (something is minted before anything is retired), and a stamped row
  without a live successor refuses. Audited as a `rotated` event with reason
  `cutover_completion`. Override options are refused on this path (`422`) — nothing is minted
  for them to change. The body carries the standing successor and no secret:

```json
{
  "credential": { "…": "the standing successor's summary row" },
  "superseded_id": "the retired row's id",
  "delivery": { "shape": "none" },
  "completed_cutover": true
}
```

- **404** — no such id. **403** — `{"message": "..."}`: the declaration denies `rotate` for
  the row's subject, or the override is not authorized (not opted in, denied, or past a mint
  ceiling).
- **409** — `{"message": "..."}`: the row is revoked, expired, or a pending row — none of
  which is a rotatable source — or it was already superseded by rotation and its successor is
  **no longer live** (no cutover to complete, re-rotating would fork the lineage; mint fresh),
  or the successor is an hmac key **still pending activation** (activate it instead), or an
  hmac rewrap is in progress (retry after `bfc:hmac:rewrap` completes).
- **422** — `{"message": "..."}`: shared input validation (a change without `override`,
  out-of-bounds `code_ttl_seconds`, malformed abilities/expiry/booleans, override options on
  a completion) — identical refusals on the CLI transport.
- **500** — `{"message": "..."}`: the replacement was committed but the old row could not be
  retired. The message names both ids; the old row is STILL LIVE, listed with its `rotated_at`
  stamp. The recovery needs no authority beyond the rotation itself: **invoke this route on
  the stamped row again** — the 200 completion above — or `DELETE /bfc/credentials/{id}`
  where revoke is authorized. **No secret was delivered** — the sealed carrier is discarded —
  so rotate the standing replacement for a fresh delivery, or revoke it by id if unneeded.

### POST /bfc/credentials/{id}/activate

Cut a delivered **pending hmac signing key** over to active (PRD 1.21, SEC-V3-01) — the
operator-authorized transition the claim exchange deliberately is not: exchange DELIVERS key
material; only this verb flips live signing state, taken after the receiver confirms
installation out-of-band. Two-transport like every verb (`bfc:credential:activate <id>
--fingerprint=<fp> --local` runs the identical action); the matrix verb consulted is
**`activate`** — its own authority, so a declaration can allow rotation while reserving the
cutover.

**Request** — `{"delivery_fingerprint": "..."}`, **required**: the delivery fingerprint the
receiver confirmed installed (it rides every signing-key delivery — the mint/rotate
`delivery` payload and the exchange response). **Activation binds to one exact delivery**:
it refuses unless the fingerprint matches the row's CURRENT delivery, so a redelivery that
re-keyed the row between the confirmation and the activation — an interceptor re-claiming
the link included — makes the stale confirmation refuse instead of cutting signing over to
key material the confirmer never saw. The fingerprint survives an APP_KEY rewrap (it names
the delivered key, not its ciphertext).

- **200** — no secret, ever (activation reveals nothing; the key was already delivered):

```json
{
  "credential": { "…": "the now-active summary row" },
  "superseded_id": "the old key's id, when this activation completed a rotation — else null",
  "grace_ends_at": "2026-08-28T13:00:00+00:00 — the LATEST end of the old key's grace window, else null"
}
```

  Activation consumes the credential's outstanding claim code (this kind's `first_use` burn
  point), so a link left in an inbox cannot re-deliver a live key. When the activated key was
  minted by a rotation, the superseded old key stops signing NOW, keeps **verifying** through a
  one-hour grace window from activation (its own earlier expiry still wins — retirement never
  extends a life), then dies by its own expiry.

- **404** — no such id. **403** — `{"message": "..."}`: the declaration denies `activate` for
  the row's subject. **422** — `{"message": "..."}`: no `delivery_fingerprint` was provided —
  an id alone cannot say which delivery was confirmed.
- **409** — `{"message": "..."}`, refused because of the row's state, identically on the CLI:
  a non-hmac kind (nothing to activate); a revoked or expired row; a row **already active** —
  duplicate activation is deliberately NOT idempotent, so a surprised operator investigates
  instead of assuming; an **undelivered key** (premature activation: neither revealed at mint
  nor exchanged — the receiver cannot have installed it); a **stale confirmation** (the
  fingerprint is not the row's current delivery — the key was re-delivered and re-keyed after
  that confirmation; ask the receiver which fingerprint they actually hold); or an APP_KEY
  rewrap in progress (retry after `bfc:hmac:rewrap` completes).
- **500** — `{"message": "..."}`: the activation COMMITTED (the new key signs) but the
  superseded old key could not be retired into its grace window and still verifies unbounded.
  The message names both ids; recovery is the rotate route's cutover completion on the stamped
  old row, or revoke-by-id.

**The elsewhere-hosted / manual case.** When no automation can install the new secret (the
credential lives in a system only a human can reach), this verb is still the whole flow: it
mints, reveals once, and holds the grace window while the human installs the secret at their
own pace. Nothing is left untracked at any point — the listing shows the old row in grace
(`rotated_at` set, expiry = grace end) beside the active replacement, the audit stream carries
the old → new lineage, and if the human misses the window the old row is already dead and the
new one already works. Use `emergency` only when the old secret is known-compromised, because
it trades the installation window away.

---

## Subjects — the offboard verb

### POST /bfc/subjects/offboard

*Admin token or operator credential holding `subject:offboard`* (its own verb-family
ability — the widest verb, deliberately not granted by `credential:mint` or
`credential:revoke`); the same two-transport rule (`bfc:subject:offboard --local` runs the
identical action). Rate-limited via `bfc-operator-write`.

**Full account containment** (PRD 1.15, SEC-V3-04). Deactivates a subject and, in one
action: revokes EVERY bound credential in EVERY lifecycle state (active, rotation-grace,
and pending — unexchanged enrollments and pending hmac signing keys included, in both the
unified store and subject-stamped `api_tokens` rows); consumes the principal's outstanding
claim codes (and their never-used make-before-break durables); cancels the principal's
pending invitations; deletes the principal's password-reset tokens; invalidates sessions;
and writes the containment registry on which the `bfc` guard — and the auth-foundation
session middleware — reject the offboarded subject and its deactivated bound users on
every request thereafter.

**Session compensation, stated — and surfaced:** a database session store on the default
connection is cleared inside the offboard transaction. A database store on another
connection is cleared after commit (deferred is not done — the response reports it); any
other driver's storage cannot be enumerated per user. Every step the transaction could not
complete is named in the result and the direct-path response answers
`"fully_contained": false` — a compensated offboard is never reported as a complete sweep.
In every compensated case the registry row commits WITH the credential revocations, so
whatever survives in session storage, the principal is rejected at every
**package-enforced** point: the `bfc` guard, the operator gate, the hmac verifier, and the
auth-foundation middleware (`bfc.auth` and `bfc.admin` both) — which also invalidate a
surviving session on its first appearance. **The honest boundary:** a consuming app's OWN
plain `auth`-guarded routes are outside the package's reach; the app must consult the
documented integration point — `OffboardedSubject::userIsOffboarded($userId)` /
`OffboardedSubject::rejects($credential)` — or stack the package middleware on them. The
package cannot invalidate an arbitrary session store it does not own, and does not claim
to.

**Request:**

```json
{
  "subject_type": "external_consumer",
  "subject_ref": "acme",
  "integration_namespace": "github-sponsors",
  "event_id": "evt_0002",
  "entitlement_version": 8,
  "external_subject": "sponsor-login"
}
```

The four integration-event fields are **all-or-none**, exactly as on the invite verb — and
they ride the SAME version gate (the shared `integration_events` / `integration_entitlements`
tables), so one monotonic entitlement version per (`integration_namespace`,
`external_subject`) orders invites and offboards together: an offboard event **not newer**
than the latest accepted version is transactionally acknowledged-and-ignored, and a
replayed `event_id` answers idempotently with no state change.

**The gate is bound to the target.** On the integration path the offboard TARGET is derived
server-side from the gated identity — `subject_type: external_consumer`,
`subject_ref: <external_subject>`, the same binding the invite verb applies — so the identity
whose version the gate checks is exactly the identity that gets contained. `subject_type` /
`subject_ref` may be omitted on this path; if supplied they must equal the derivation, and a
mismatch is refused (`422`) — an event can never pass a decoy identity's gate while naming a
different victim. And the gate is bound by **namespace** too: every gate effect is keyed on
the (`integration_namespace`, `external_subject`) pair, so a namespace with NO entitlement
history for an external subject that already has history under another namespace is refused
(`422`, nothing recorded, nothing advanced) — a decoy namespace cannot ride its own empty
gate to contain a subject whose real gate stands at a higher version. A namespace with its
own established history is ordered by that history as before; a subject with no history
anywhere can be gate-established by any authorized namespace. On the direct path (no event
fields) the subject pair is required.

**The two response shapes, keyed on the REQUEST (never on state):**

- **Direct path (no integration event): `200 {"offboarded": true, "fully_contained": bool}`**
  — identical shape for a first containment and an idempotent repeat (a repeat revokes
  nothing, writes no new audit rows, and changes nothing). `fully_contained` is `false` when
  a containment step could not complete inside the transaction (see the compensation above);
  re-run the idempotent verb after fixing the store to retry the step.
- **Integration path: `202 {"accepted": true}` — always**, whatever the gate decided
  (applied, ignored-older, or replayed); the body carries nothing a caller could probe gate
  state from.
- **403** — `{"message": "..."}`: the declaration's verb matrix denies `offboard` for the
  subject. **422** — `{"message": "..."}`: shared input validation (unknown `subject_type`,
  missing `subject_ref`, a partial integration-event group, an out-of-bounds or non-integer
  `entitlement_version`, an over-length field). **500** — `{"message": "..."}`: the gate
  lost every bounded contention attempt; nothing was applied, retrying is safe. Identical
  refusals on the CLI transport.

Audit shape (D8, one shape): a single `offboarded` lifecycle event carrying the acting
principal and the contained subject (ids only), plus one ordinary `revoked` event per
credential death with reason `offboarding`. A repeat offboard appends nothing.

---

## RESERVED — Console fast-follow (not implemented)

The vendor-side Console is a decided fast-follow. So that it can land without reopening this
shipped contract, the following names are RESERVED here now. **None of this exists in this
release: no routes, no guard, no table, no ability issuance.** This section deliberately
contains no `### METHOD /path` route headings — the mechanical route-completeness check covers
live routes only, and nothing here is one.

- **Guard name `bfc-console`** — reserved for the Console's delegated-session guard. No guard
  by this name is registered.
- **Endpoint namespace `/bfc/console/*`** — reserved for Console endpoints; the first known
  member will be `/bfc/console/enter`. No route under this namespace exists.
- **Table name `bfc_delegated_actors`** — reserved for the Console's delegated-actor records.
  No such table or migration exists.
- **Dual-session precedence (reserved matrix row).** The session/token precedence matrix (the
  `bfc` guard's docblock and `release-notes/unified-store-guard.md`) reserves a row for the
  future `bfc-console` delegated-session guard, recording the decided rule now: on a request
  carrying both a local `web` session and a delegated session, **the delegated guard wins —
  for the acting principal and for any UI/attribution branching — never a union of the two.**
  Nothing enforces this in this release.
- **Ability family `metadata:read`** — reserved in the ability vocabulary alongside `admin`
  and `credential:admin`: least-privilege, read-audited, for future vendor-side reads of
  `metadata`-classified endpoints (see [Endpoint classification](#endpoint-classification)).
  No credential is issued with it and nothing enforces it in this release.

Everything else Console-related remains held behind the Console PRD's decision D6; this
section reserves exactly these names and nothing more.
