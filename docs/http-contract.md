# The Built for Cloud HTTP contract

This is the versioned public contract of every HTTP surface the `built-for-cloud` package mounts,
written for a consumer with **no PHP**: plain HTTP + JSON. Scalpels consumes exactly this contract;
so can a customer's own control plane, an internal app in any language, or a shell script. Any PHP
client the ecosystem ships is a convenience — **this document, not any client library, is the
contract** (GATE-3).

Every route below is verified mechanically: a package test enumerates the registered routes and
asserts each appears here, and that every route this document names is real. A route heading has
the form `### METHOD /path`.

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
  name-based rotation refuses whenever more than one resolvable row shares the name.
- `GET /bfc/meta` `capabilities` gained `credentials`.
- `POST /bfc/onboarding/issue` requires `ttl_seconds` (bounds below) and accepts nullable
  `email`; the claim surfaces speak the claim-contract error enum documented here.

**api_version 1** — the 0.3.x baseline: `/bfc/meta`, `/bfc/ownership/*`, the pre-0.4 credential
API listing shape.

## Authentication

- **Admin-token routes** (marked *admin token* below) require
  `Authorization: Bearer <token>` where the token is an `api_tokens` row carrying the `admin`
  ability — the row minted by the ownership claim, `token:create --local --abilities=admin`, or
  the credential API. Missing/unknown token → `401`; a valid token without `admin` → `403`.
- **Public routes** are unauthenticated but rate-limited per IP: `bfc-public` (60/min) and
  `bfc-claim` (10/min), returning `429` beyond the limit.
- Validation failures on JSON bodies return Laravel's standard
  `422 {"message": ..., "errors": {field: [...]}}` shape.

Secrets appear in exactly one place each: the response field documented as the **single reveal**.
No secret is ever retrievable again; store it on receipt.

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
token. The claim token comes from the install migration's TTY output, from
`bfc:ownership:mint-claim`, or from a release handoff.

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
- **409** — `{"message": "..."}`: the row no longer resolves (revoked or expired) — there is
  nothing to rotate; mint a replacement instead.
- **500** — `{"message": "..."}`: the replacement was minted but the old row could not be
  retired. The message names both ids: the old row is STILL LIVE (listed, `rotated_at` stamped)
  and `DELETE /api/credentials/id/{id}` can always kill it; no plaintext was delivered, so the
  unused replacement can simply be revoked by id, and retrying the rotation works.

Name-based rotation survives only as the `token:rotate` CLI convenience, and it now **refuses
whenever more than one resolvable row shares the name** — it never picks one. Rotate by id here
instead.

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

**Authentication on these three routes** accepts either credential shape:

- a legacy **admin `api_tokens` token** (exactly what every other admin route accepts), or
- a **unified-store `operator` credential** holding the `credential:admin` ability — what
  `bfc:install:operator-credential` mints at install time, so a fresh install can manage its
  credentials with the one secret it was handed. A valid unified credential without operator
  authority is `403`; the deprecated `FALLBACK_TOKEN` is explicitly rejected with a
  distinguishable `403` message. Audit actors reflect the store that authenticated
  (`admin_token` vs `operator_integration`).

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
when `kind` is `asymmetric` and ignored otherwise.

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
| `none` | — | the secret was never ours to hand over |

- **403** — `{"message": "..."}`: the declaration denies `issue` for this subject, the request
  widens abilities or lifetime past a declared ceiling, sets a declared-unsupported field, or
  names a kind that is not mintable (`hmac`, this release). Identical refusals on the CLI
  transport.
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

Everything is optional. `emergency: true` kills the old row immediately instead of granting
grace. `abilities` / `expires_at` request a CHANGED replacement and are consumed only under
`override: true` — any change without the flag, **narrowing included** (predictability beats
cleverness), is refused with a `422`; the flag with nothing to change is refused the same way.
An override is authorized through the verb matrix as its own consultation — the declaration's
`authorizeVerb(rotate, …)` hook sees the request attribute `bfc.rotation_override` carrying the
requested delta — and its audit events record the `override` reason code plus the delta.
`code_ttl_seconds` is required (60–604800) when rotating an `asymmetric` credential and ignored
otherwise.

Per kind:

| kind | rotation semantics |
|---|---|
| `bearer` / `basic` | a fresh secret is minted and delivered once, in this response's `delivery` (same shapes as the mint route) |
| `asymmetric` | a fresh **enrollment code** is delivered against a new `pending` row — the client generates the new keypair itself; no key material ever travels. The old credential's public key keeps verifying through the grace window, so both rows are listed side by side. The enrollment-completing exchange ships with the first asymmetric consumer's rebuild |
| `hmac` | **403, explicitly not implemented**: hmac rotation is the pending→active cutover (rotate creates the new key pending while the old keeps signing; delivery installs it; activation cuts over) and ships with the kind itself. Nothing falls through to bearer semantics |

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

- **404** — no such id. **403** — `{"message": "..."}`: the declaration denies `rotate` (or the
  override) for the row's subject, or the kind does not rotate (`hmac`).
- **409** — `{"message": "..."}`: the row is revoked, expired, or a pending enrollment — none
  of which is a rotatable source.
- **422** — `{"message": "..."}`: shared input validation (a change without `override`,
  out-of-bounds `code_ttl_seconds`, malformed abilities/expiry/booleans) — identical refusals
  on the CLI transport.
- **500** — `{"message": "..."}`: the replacement was committed but the old row could not be
  retired. The message names both ids; the old row is STILL LIVE, listed with its `rotated_at`
  stamp, and `DELETE /bfc/credentials/{id}` can always kill it. **No secret was delivered** —
  the sealed carrier is discarded — so the unused replacement can simply be revoked by id, and
  retrying the rotation works.

**The elsewhere-hosted / manual case.** When no automation can install the new secret (the
credential lives in a system only a human can reach), this verb is still the whole flow: it
mints, reveals once, and holds the grace window while the human installs the secret at their
own pace. Nothing is left untracked at any point — the listing shows the old row in grace
(`rotated_at` set, expiry = grace end) beside the active replacement, the audit stream carries
the old → new lineage, and if the human misses the window the old row is already dead and the
new one already works. Use `emergency` only when the old secret is known-compromised, because
it trades the installation window away.
