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
- New personal-credentials routes (PRD 1.17): `GET /bfc/me/credentials`,
  `POST /bfc/me/credentials` and `DELETE /bfc/me/credentials/{id}` — the session-authenticated
  self-service front to the same unified-store verbs, whose subject is derived server-side from
  the authenticated session and never from request input (SEC-V3-07), whose ABILITIES come from
  an application-declared self-service policy and never from the requesting user, and whose
  mutations are CSRF-protected browser routes. Additive: no existing route, request or response
  shape changes.
- `GET /bfc/meta` `capabilities` gained `credentials`, and — with the console key surfaces
  below — `console-keys`.
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
  lifecycle events, ids only). *(The Console bullet below adds one more name in this same
  release — `console:key:write`. The complete, current vocabulary is under
  [Authentication](#authentication), which is the list the test suite pins.)*

- **Console countersigning-key custody ships (Console PRD D12).** All additive; both of the
  previous release's RESERVED extension slots are now implemented, and `api_version` stays 2
  because a new route and new optional fields are exactly the additive case rule 1 names.
  `POST /bfc/ownership/claim` and `POST /bfc/onboarding/exchange` accept an optional
  `console_key` object and answer with one when they were given one — an envelope carrying no
  `console_key` is unchanged, response keys included. New route `POST /bfc/console/re-key`
  (the new `console:key:write` ability, operator write limits) files and activates a key on an
  already-claimed deployment without re-onboarding, with `bfc:console:re-key --local` as its
  CLI transport. Filing is make-before-break: it activates the new key and retires nothing, so
  both keys verify during the overlap; retirement stays a separate, later operation with no
  HTTP verb in this release. The lifecycle stream's `delivered` / `activated` / `denied_action`
  events now also carry console-key events (`credential_id` null, the key id in the note). No
  surface here returns key material, and none has any use for a private key — but see the
  HONEST LIMIT under [Console key custody](#console-key-custody): a 32-byte Ed25519 seed cannot
  be told apart from a public key by inspection, so "no private key is stored" is a property of
  the provisioning protocol, not something these surfaces can enforce.
  `POST /bfc/onboarding/issue` gains optional `console_key_authority`: only a code issued with
  it may deliver a key, and only once. The operator ability vocabulary gains
  `console:key:write` — deliberately NOT the `credential:rotate` family, so no
  already-issued credential gains console key-custody power on upgrade.

**api_version 1** — the 0.3.x baseline: `/bfc/meta`, `/bfc/ownership/*`, the pre-0.4 credential
API listing shape.

## Authentication

- **Admin-token routes** (marked *admin token* below) require
  `Authorization: Bearer <token>` where the token is an `api_tokens` row carrying the `admin`
  ability — the row minted by the ownership claim, `token:create --local --abilities=admin`, or
  the credential API. Missing/unknown token → `401`; a valid token without `admin` → `403`.
- **Public routes** are unauthenticated but rate-limited per IP: `bfc-public` (60/min) and
  `bfc-claim` (10/min), returning `429` beyond the limit.
- **Operator-route refusals are NOT uniform, deliberately.** Missing, unknown, expired and
  revoked bearers all answer `401` with one body; a bearer that authenticates but lacks the
  route's ability answers `403`. The split is safe because a caller reaching the `403` has
  already proved it holds a live credential, so nothing about credential existence leaks — and
  it is useful, because "wrong ability" and "bad token" need different fixes. The one exception
  is [`POST /bfc/console/re-key`](#post-bfcconsolere-key), where what the split would reveal is
  worth more to an attacker than the diagnostic is to an operator; it answers one uniform `403`
  to every pre-authorization failure alike.
- **Operator routes** (the `/bfc/credentials`, `/bfc/invitations` and `/bfc/subjects` verbs)
  additionally accept a unified-store `operator` credential, authorized **per verb family**
  (GATE-3.7 least privilege). The ability vocabulary: `credential:read` (the listing — an
  audited sensitive read), `credential:mint` (mint + invitations), `credential:rotate`
  (rotate + the hmac activate cutover, same family), `credential:revoke`, `subject:offboard`,
  `audit:read` (vocabulary now; the first audit-read surface will enforce it), and
  `console:key:write` (file a console countersigning key —
  [`POST /bfc/console/re-key`](#post-bfcconsolere-key); its own name, and deliberately not the
  `credential:rotate` family, so no already-issued credential gained the power to install a
  delegated-admin trust root on upgrade — **note the declared-mint-ceiling caveat below if your
  app implements one**). The MCP
  pair `mcp:read` / `mcp:admin` is the per-tool vocabulary consuming apps wire in front of
  each MCP tool (read vs destructive administration — distinct grants, checked exact-match;
  no operator ability implies either). `metadata:read` remains RESERVED, unissued and
  unenforced. There is **no wildcard**; a credential with no abilities can do nothing. The
  one admin-equivalent name is **`credential:admin`** — the explicit break-glass, expanding
  to exactly the seven operator abilities `credential:read`, `credential:mint`,
  `credential:rotate`, `credential:revoke`, `subject:offboard`, `audit:read` and
  `console:key:write` (never the MCP pair); it is what
  `bfc:install:operator-credential` mints, and holding that literal name in the abilities
  list is how a break-glass credential is marked.

  Two precise things about that list, because "exactly" is doing more work in the sentence
  above than the code does:

  - **It is a declared inventory, not the enforcement path.** The operator gate grants a
    credential holding `credential:admin` *whatever* ability the route asks for; it does not
    consult the list. The list is therefore an accurate statement of what the operator routes
    ask for TODAY — every one of them names an ability on it — rather than a ceiling the gate
    would enforce if a future route named an ability deliberately left off. Read it as "these
    are the abilities break-glass currently reaches", not as "break-glass is confined to
    these". (The `never the MCP pair` half IS enforced, but by a different middleware: the
    per-tool MCP gate checks exact-match and no operator ability satisfies it.)
  - **A package test pins this sentence to `OperatorAbility::adminEquivalent()`** — the names,
    their order, and the spelled count — so the document and that method cannot disagree. It
    pins nothing else; see that test's own docblock for what it deliberately does not cover.

  **A legacy admin `api_tokens` row remains admin-equivalent on these routes, console key
  custody included — deliberately.** That set is not only the deprecated legacy credential
  API's output: it is above all the **owner token** minted by
  [`POST /bfc/ownership/claim`](#post-bfcownershipclaim), which is the deployment owner's root
  authority and is exactly the party a console key names. Excluding it would also be no
  boundary — **in an app that declares no mint ceiling**, an admin `api_tokens` row can mint
  itself an operator credential carrying `console:key:write` in one request — and it would be
  incoherent with the CLI transport, which already treats host access as sufficient for this
  verb. An operator who wants console key custody held by a narrower credential should not
  issue admin `api_tokens` rows; the unified store's per-verb-family abilities are the
  instrument for that.

  That qualifier does not weaken the decision, and the reason is worth stating rather than
  leaving to be reconstructed. A declared mint ceiling is **not** a check on who is asking:
  `refuseWideningPastCeilings` consults the declaration and the subject only, never the
  credential that authorized the request. So under a ceiling omitting `console:key:write`, the
  ability is unmintable by EVERYONE — admin token, break-glass and narrow operator credential
  alike — and there is no privilege the legacy row holds that excluding it would take away.
  The "exclusion buys nothing" argument therefore holds where there is no ceiling, and is moot
  where there is one. Neither case produces a reason to exclude the legacy admin row.

  **Caveat — an app with a declared mint ceiling cannot mint `console:key:write` until it
  edits its own declaration.** This affects one specific kind of app: one whose credential
  declaration implements `ConstrainsMintedCredentials` and returns a NON-NULL
  `grantableAbilities()` list, written before this ability existed. Most apps are unaffected —
  the interface is opt-in and not implementing it declares no ceiling — but where a ceiling IS
  declared, it is exhaustive by design, so an ability the list does not name simply cannot be
  granted. This is not a gap in the ceiling mechanism; it is the mechanism working, and it is
  called out here because the new name arrives in a release the declaration predates.

  What it looks like, and the second half is the awkward one:

  - `POST /bfc/credentials` requesting `"abilities": ["console:key:write"]` answers **403**
    with an ability-widening message that names the ability. Diagnostic, and it points at the
    real fix. `bfc:credential:mint --local` refuses identically — the ceiling is enforced in
    the one mint action, so no transport routes around it.
  - `POST /bfc/console/re-key`, presented with an operator credential the app can still mint
    **that does not carry `credential:admin`**, answers the uniform **403** described above,
    whose body is constant and says nothing about why. That opacity is deliberate on this
    route and it is not going to distinguish this case from a stolen bearer, so an operator
    who has not read this paragraph will read it as "my credential is wrong" rather than "my
    declaration is short a name".

    The `credential:admin` exception is real and is a third way out: a ceiling written before
    this release may well permit the break-glass name, and an operator credential carrying it
    is both mintable under that ceiling and sufficient for this route — because the gate grants
    `credential:admin` whatever ability a route names (see the inventory note above). Check the
    declaration's `grantableAbilities()` before concluding the route is unreachable.

  **Two paths work meanwhile, neither of which needs a deploy:**

  1. an admin token — the **owner token** from
     [`POST /bfc/ownership/claim`](#post-bfcownershipclaim), or any admin `api_tokens` row —
     which is admin-equivalent on this route (see the paragraph above); or
  2. the CLI transport, `bfc:console:re-key --local`, whose authority is host access and which
     consults no ability at all.

  **The fix** is to add `console:key:write` to the declaration's `grantableAbilities()` for the
  operator subject and redeploy. Do that deliberately: it is the grant of a
  delegated-admin trust root, which is exactly what a declared ceiling exists to make someone
  decide rather than inherit.
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
| `GET /bfc/me/credentials` | `content` | the caller's own summary rows carry free-text names and subject refs, plus the declaration's field lists |
| `POST /bfc/me/credentials` | `content` | the `delivery` single reveal, plus free-text name/subject fields |
| `DELETE /bfc/me/credentials/{id}` | `metadata` | empty `204` body |
| `POST /bfc/console/re-key` | `metadata` | key ids from a bounded charset, a fixed status enum and a timestamp — no free text, and never any key material |
| `POST /bfc/subjects/offboard` | `metadata` | `{"offboarded": true, "fully_contained": bool}` / `{"accepted": true, "fully_contained": bool}` — bounded booleans only |

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
  "capabilities": ["tokens", "ownership", "onboarding", "webhooks", "credentials", "console-keys"],
  "claimed": true
}
```

`capabilities` is an open set — ignore unknown entries. `claimed` says whether an owner control
plane holds this instance.

`console-keys` means this instance serves the countersigning-key surfaces below: the optional
claim-time key exchange and `POST /bfc/console/re-key`. It deliberately does **not** say
`console` — key custody is not the Console. There is no delegated guard, no enter endpoint and
no delegated-actor table in this release, and a control plane that read `console` as "this
deployment can be entered" would be reading a promise nothing here keeps.

---

## Ownership

### POST /bfc/ownership/claim

Public (`bfc-claim` throttle). Exchange a one-time ownership claim token for the owner's admin
token. The claim token comes from `bfc:ownership:mint-claim` (TTY, shown once) or from a
release handoff. The install migration's initial mint deliberately yields NO deliverable
token: its plaintext is dropped, never logged (the D7 fix — a logged claim token is an
admin-yielding secret in the application log), so an unclaimed environment re-mints with the
command.

**Request** — `{"token": "<claim token>", "notify_callback": "https://..." | null,
"console_key": {"key_id": "...", "public_key": "..."} | null}`
(`notify_callback` optional: where ownership webhooks are delivered. `console_key` optional:
the claim-time countersigning-key exchange — see
[Console key custody](#console-key-custody).)

- **201** — `{"owner_token": "...", "webhook_secret": "...", "product": "..."}` — the single
  reveal of both secrets. The owner token is an admin-ability `api_tokens` row with no expiry;
  ownership transfer, not a clock, ends its life. A claim that carried `console_key`
  additionally answers with the `console_key` object documented below; a claim that did not
  carries no such field (absent, never null).
- **401** — the claim token is unknown, expired, or already consumed.
- **409** — `{"message": "already claimed"}` — a live owner exists and no transfer is pending.
  Also `{"message": "..."}` when a delivered `console_key` names a key id already on file, or
  carries material already filed under another key id (retired rows included).
- **422** — `{"message": "..."}` — the delivered `console_key` is not a canonical 32-byte
  Ed25519 public key under a well-formed key id.

**A refused key refuses the whole claim.** The key is filed inside the claim's own transaction,
so a `409`/`422` above means no owner token was minted, no keyring row was created, and the
claim code is **still unconsumed and presentable**. Claiming anyway and reporting the key
failure separately would spend a single-use code on a deployment that ended up unkeyed.

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

**Request** — `{"email": "a@b.c" | null, "scope": "consume" | "admin" | "onboard",
"ttl_seconds": 3600, "console_key_authority": false}`.
`ttl_seconds` is **required**, bounded 60–604800 (7 days) — the ttl lives on the code, never on
the durable it buys. `scope` defaults to `consume`. Issuing an addressed code supersedes any
pending code for the same address+scope but never touches a live durable credential.

`console_key_authority` is optional and defaults to **false**. True grants this code the right
to deliver ONE console countersigning key at exchange — see
[Console key custody](#console-key-custody) for what that authority is worth, which is a great
deal: a filed key can mint delegated-admin entry into the deployment. It is settable only here,
on this admin-gated surface, and never by the party redeeming the code.

- **201** — `{"claim_code": "...", "email": "a@b.c" | null}` — the single reveal of the code.
  A code issued with key-custody authority additionally carries `"console_key_authority": true`
  (absent otherwise, so the pre-console response shape is unchanged).

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

**Request** — `{"token": "<claim code>", "version": 1,
"console_key": {"key_id": "...", "public_key": "..."} | null}` (`version` optional, default 1;
`console_key` optional — the claim-time countersigning-key exchange, and **only on a code
issued with `console_key_authority`**, see [Console key custody](#console-key-custody)).

- **201** — `{"durable_token": "...", "name": "..."}` — the single reveal of the durable secret.
  An exchange that carried `console_key` additionally answers with the `console_key` object
  documented below — on the signing-key variant too. An exchange that did not carries no such
  field (absent, never null).
- Errors: the enum above. A re-exchange of a consumed code is `code_already_claimed`.
- A delivered `console_key` that cannot be filed answers OUTSIDE the enum, with the ordinary
  prose shape: **403** `{"message": "..."}` when the code carries no console key-custody
  authority (or has already spent it); **409** `{"message": "..."}` for a key id already on
  file, for material already on file under another key id, or for an unclaimed deployment;
  **422** `{"message": "..."}` for material that is not a canonical 32-byte Ed25519 public key.
  These are not claim-code failures and deliberately do not borrow the claim enum's vocabulary.
  As on the ownership claim, the filing rides the exchange's own transaction: a refusal means
  no durable was minted, no signing key delivered, no keyring row created, and — under
  `at_exchange` — the code left unburned and still presentable.

`POST /bfc/claim` (the hitch face) deliberately does **not** read `console_key`: it speaks a wire
contract published by another project, and console key custody is not part of it.

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

Two extension slots were RESERVED by name in the previous release. **Both are IMPLEMENTED as of
this one**, exactly as reserved — additively, without an `api_version` bump:

- **A countersigning-key exchange at claim time — IMPLEMENTED.** The claim/exchange envelopes
  (`POST /bfc/ownership/claim` and `POST /bfc/onboarding/exchange`) accept an OPTIONAL
  `console_key` object and answer with an OPTIONAL `console_key` object. Key material now does
  travel INBOUND on these surfaces — a 32-byte Ed25519 verification key, which no surface here
  ever returns. That it is the PUBLIC half is a property of the provisioning protocol, not one
  this contract can check: see the HONEST LIMIT under
  [Console key custody](#console-key-custody). On the onboarding exchange the delivery
  additionally requires a code issued with `console_key_authority`.
- **A re-key verb for already-claimed apps — IMPLEMENTED** as
  [`POST /bfc/console/re-key`](#post-bfcconsolere-key), a new route, additive under rule 1.

An envelope carrying no `console_key` behaves in every respect as it did before, response keys
included, which is what makes both slots additive rather than a version bump.

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

## The personal-credentials surface (`/bfc/me/credentials`)

PRD 1.17: **an authenticated human manages their OWN machine credentials** — list mine, mint
(revealed once), revoke mine. The same store, the same action classes and the same summary shape
as [`/bfc/credentials`](#the-unified-credential-store-bfccredentials) above; what differs is
exactly one thing, and it is the thing that makes the surface safe to put in front of a logged-in
person:

> **The subject is derived SERVER-SIDE from the authenticated session** (SEC-V3-07), by the
> application's own credential declaration. The operator routes take `subject_type` and
> `subject_ref` as validated input. These routes take **neither**, on any verb. A
> `subject_type`, `subject_ref` or `user_id` in a request body to these routes is **not read
> at all** — it is not rejected with a message you could probe, it simply never reaches the
> store. The mint binds to the session's subject and the session's user whatever the body said.

Consequently, and each of these is a named negative test in the package's suite:

- the listing returns only the caller's own rows — another user's rows are not filtered out of a
  rendered answer, they are never fetched;
- a mint binds to the session-derived subject, never to a crafted one;
- a revoke acts only inside the caller's own subject; an id belonging to someone else answers
  **404**, the same answer an id that never existed gets. This is deliberate: a `403` would
  confirm that another user's credential exists, which is a disclosure a `404` does not make.

**Authentication on these routes is the application's session**, not an admin token and not an
operator ability. The package mounts them behind its `bfc.auth` gate, which the consuming
application's authenticated human already passes; an unauthenticated request is `401` (or a
redirect to the app's `login` route when it has one and the request does not expect JSON). That
gate is also where an offboarded user's surviving session dies (PRD 1.15), so offboarding a
subject both revokes its credentials and closes this screen to them. Every request rides the
`bfc-personal` limiter (30/min per session principal, 60/min per IP).

**These are BROWSER routes — the only ones in this contract.** Every other surface documented
here is a token API that wants no session; these three ride the full browser session stack
(cookie encryption, `StartSession`, CSRF validation). Concretely: the package mounts them in the
host application's own **`web` middleware group** when one is registered — so the app's session
driver, cookie handling and any CSRF customization apply to its own settings screen — and falls
back to the equivalent concrete stack when the application registers no such group.

Two consequences for a client:

- **`POST` and `DELETE` require a valid CSRF token.** Send it as a `_token` field or an
  `X-CSRF-TOKEN` / `X-XSRF-TOKEN` header, exactly as for any other form post in the host
  application. A mutation without one is rejected (`419`). `GET` is not CSRF-checked — it is
  where a browser client picks up the `XSRF-TOKEN` cookie it sends back.
- **A session cookie is required**, so this surface is for a browser (or anything that keeps the
  app's session cookie). A machine integration wants the operator routes and a credential, not
  this screen.

**When the application declares no subject for the session** — its declaration's
`resolveSubject()` returns `null`, which is what the package's shipped default declaration does —
every verb answers **403** with a `message`. Fail-closed on purpose: an empty `200` listing would
assert "you hold no credentials", and that is a claim this surface cannot honestly make when it
does not know whose credentials to look for.

**What stays per-application is the MEANING, and it lives in the declaration, not in a branch in
the package.** The screen is identical for every app. A capstan user-bound credential inherits its
user's authority — the declaration's `authorize()` hook is what says so — and dies with the user,
because offboarding revokes every credential under the subject *and* every credential bound to the
user. A crate key carries its own authority, because crate's `authorize()` reads the credential's
own abilities and never the holder's role. Same routes, same store; different declaration.

### GET /bfc/me/credentials

**200:**

```json
{
  "credentials": [ { "…": "a summary row, exactly as on /bfc/credentials" } ],
  "fields": {
    "supported": ["name", "abilities", "last_used_at", "expires_at"],
    "unsupported": []
  }
}
```

Rows are oldest first and carry the identical summary shape (and identical per-row `unsupported`
list) documented for the unified store above; per-row `list_metadata` filtering applies here too.

`fields` is the **declaration-driven rendering contract** (PRD 1.17 + 1.6). `supported` is what a
front end draws; `unsupported` names the summary fields this application's store structurally
cannot express. It is the same discrimination each row already carries, hoisted once so a UI can
choose its columns and its mint form before it has fetched a single row — **a thinner declaration
renders less**. Only `name`, `abilities`, `last_used_at` and `expires_at` are declarable;
structural fields (id, kind, subject, status, timestamps) are always supported. Consumers must not
render or alert on an unsupported field, and must not read a `null` on one as "absent".

- **403** — `{"message": "..."}`: no subject is resolvable for this session (see above).
- **401 / redirect** — no session.

### POST /bfc/me/credentials

Mint for the caller.

**Request:**

```json
{
  "kind": "bearer",
  "name": "my laptop",
  "expires_at": null,
  "code_ttl_seconds": null
}
```

Every field is optional and normalized by the same shared input object the operator transport
uses, so the same junk is rejected the same way with the same message. Send a CSRF token with it
(see above).

**Four fields the operator route accepts are deliberately absent here, and none of them is
merely rejected — none is read at all**, so there is no validation behaviour to probe:

| absent field | why | what decides it instead |
|---|---|---|
| `subject_type`, `subject_ref` | whose credential this is | the session, derived server-side (SEC-V3-07) |
| `user_id` | which user it binds to | the session user |
| `abilities` | **what it can DO** | the application's self-service mint policy |

**The self-service mint fails closed on authority.** The operator route takes abilities from an
authenticated admin who chose them. A logged-in human asking this route for `["mcp:admin"]` is
making a *request*, not an authorization — so the surface does not read it. A self-service
credential's abilities come only from an explicit self-service policy the application's
declaration provides, and **absent that policy it is minted with no abilities at all**: it
authenticates as its holder and holds no operator, MCP or signing power.

`kind` **is** read, and then refused unless the policy offers it. The default offer is `bearer`
alone, so `hmac` (which delivers signing key material) and `asymmetric` (an enrollment code) are
not reachable by naming them — a refusal is a `403` naming the kind.

`expires_at` is the caller's and stays optional: a durable's expiry is never defaulted (PRD 1.3 /
D1b). Lifetime is not the escalation vector; abilities are, and abilities are what fails closed.
An application that does want a lifetime ceiling declares one the normal way, and the mint verb
applies it to both routes alike.

- **201** — `{"credential": {…}, "delivery": {…}}`: the summary row, and the **single reveal**,
  shaped by `delivery.shape` exactly as documented for
  [`POST /bfc/credentials`](#post-bfccredentials). The plaintext appears here and nowhere else —
  not in a later listing, not in the logs, not in the session, not at rest.
- **403** — `{"message": "..."}`: no resolvable subject, a `kind` the self-service policy does
  not offer, the declaration denies `issue` for the subject, a widening past a declared ceiling,
  or a declared-unsupported field.
- **419** — the mutation carried no valid CSRF token.
- **409** — an hmac mint during an APP_KEY rewrap.
- **422** — validation (unknown `kind`, out-of-bounds `code_ttl_seconds`, malformed `abilities`).

Emits an `issued` audit event in the mint's own transaction, with a `bound_user` actor carrying
the session user's **id** — never their name or email.

### DELETE /bfc/me/credentials/{id}

Revoke one of the caller's own credentials, by id.

- **204** — revoked, or already dead (idempotent — one death, one `revoked` audit event).
- **404** — no such id **for this caller**. An id that exists under another subject answers this
  same 404; existence outside the caller's own scope is never disclosed.
- **403** — `{"message": "..."}`: no resolvable subject, or the declaration's `revoke` verb denies
  it for this subject.
- **419** — no valid CSRF token.

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
- **Integration path: `202 {"accepted": true, "fully_contained": bool}` — always**,
  whatever the gate decided (applied, ignored-older, or replayed). `fully_contained` is the
  ONE deliberate exception to decision-uniformity on this verb: an applying event whose
  containment could not complete a step reports `false` — the operator must learn the sweep
  did not finish, at the stated price of revealing that the event applied and hit an
  unreachable store. An ignored or replayed event ran no containment and always reports
  `true`; the body carries nothing else a caller could probe gate state from.
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

## Console key custody

The Console (Console PRD D12) signs a short-lived delegated-entry assertion with the PRIVATE
half of a **per-deployment** Ed25519 keypair. This deployment holds only the PUBLIC half, on a
key ring addressed by key id (`kid`). Two surfaces put a key on that ring — the claim-time
exchange documented on the claim envelopes above, and the re-key verb below.

What the ring will hold, and what it will not:

- **A key is a canonical 32-byte Ed25519 public key**, delivered as lower-case/upper-case hex or
  unpadded base64url, under a key id of 1–64 characters of `[A-Za-z0-9._-]`. Anything else is
  refused at delivery — a truncated key, a PEM blob, or the 128-hex-character 64-byte expanded
  secret key.
- **A key id names exactly one key, for the life of the deployment.** Delivering a key id
  already on file is refused (`409`); the material behind an existing key id is never replaced.
  A rotation or a retrofit delivers a NEW key id.
- **The MATERIAL is filed once too**, under exactly one key id, and that holds in every
  lifecycle state — pending, active and **retired**. Re-delivering a retired key's bytes under
  a fresh key id is refused (`409`). Without that rule, retirement — the only revocation this
  design has, since a console key has no expiry and there is no revocation list — could be
  undone by re-filing.
- **The deployment must already be claimed.** A key names who may enter as an admin, and a
  deployment with no owner has not decided who that is. `POST /bfc/console/re-key` refuses with
  `409` on an unclaimed instance. The ownership claim is exempt by construction: it establishes
  the owner and files the key in the same transaction, in that order.
- **On the onboarding exchange, the claim code must carry the authority.** See below.
- **HONEST LIMIT.** These checks do not, and cannot, prove the delivered bytes are a public key.
  A 32-byte Ed25519 SEED — the private half in compact form — is the same size as a public key
  and, when it happens to encode a usable curve point, is indistinguishable from one by
  inspection. The custody property is held by the PROVISIONING PROTOCOL (the vendor hands over
  the public half and never transports a private one) and by this package containing **no code
  that signs anything**, not by the validation above. What the validation buys is that
  mis-delivered or corrupt material fails loudly at delivery rather than silently refusing every
  assertion later.
- **No secret is ever revealed by these surfaces.** They are the only surfaces in this contract
  that accept key material and the only ones that reveal nothing.

### Who may deliver a key

Filing a key installs a standing authority to mint delegated-ADMIN entry into this deployment,
so each surface answers "who may do this" explicitly:

| surface | authority |
|---|---|
| `POST /bfc/ownership/claim` | the ownership claim code itself. Presenting it already yields an admin owner token in the same response, so naming the console key escalates nothing the holder is not already getting. |
| `POST /bfc/onboarding/exchange` | the code must have been issued with `console_key_authority` (below), and must not have spent it. A routine `scope=consume` code carries none. |
| `POST /bfc/console/re-key` | an operator credential holding **`console:key:write`**, or the `credential:admin` break-glass, or a legacy admin token. `credential:rotate` is **not** sufficient. An app with a declared mint ceiling cannot mint that ability until it names it — see the caveat under [Authentication](#authentication); the owner/admin token and the CLI verb both work meanwhile. |
| `bfc:console:re-key --local` | **host access.** No credential check — see the CLI paragraph below. |

`POST /bfc/onboarding/issue` accepts an optional boolean `console_key_authority` (default
`false`). A code issued with it may deliver exactly ONE console key; the authority is spent by
that delivery and does not return, independently of the app's burn mode — under `first_use` a
code stays presentable, and without the single-use stamp one authorized code could file further
keys under fresh key ids. The field is set only on this admin-gated surface, never by the party
redeeming the code. When granted, the issue response echoes `"console_key_authority": true`
(absent otherwise, so the pre-console response shape is unchanged).

An exchange that delivers `console_key` without that authority answers **403**
`{"message": "..."}` and — because the check runs inside the locked transaction before anything
burns — leaves the claim code entirely untouched.

**Make-before-break.** Filing a key ACTIVATES it and retires nothing. From the moment a delivery
commits, the outgoing key and the incoming key both verify, so a re-key is safe to run against a
deployment that is serving traffic — assertions already in flight under the outgoing key keep
working. **Retirement is a separate, later operation** (there is no HTTP verb for it in this
release; it is a keyring operation on the instance), performed once every assertion minted under
the outgoing key has expired — which D12 bounds at the deployment's configured maximum assertion
TTL, so the safe wait is short and known. Collapsing activation and retirement into one call is
what turns a rotation into an outage.

The success object, identical on all three surfaces (the two claim envelopes and the verb):

```json
{
  "console_key": {
    "key_id": "k2",
    "status": "active",
    "activated_at": "2026-08-29T12:00:00+00:00",
    "active_key_ids": ["k1", "k2"]
  }
}
```

`active_key_ids` is every key id verifying at the moment the delivery committed, sorted — two of
them for the duration of a make-before-break overlap. It is the signal an operator confirms
before retiring the outgoing key.

### POST /bfc/console/re-key

*Admin token or operator credential carrying `console:key:write`* — rate-limited as an operator
write (`bfc-operator-write`). File and activate a countersigning key on an **already-claimed**
deployment, without re-onboarding it. This is the retrofit path: the claim-time exchange only
helps a deployment that has not claimed yet, and a fleet in service has already claimed.

**`console:key:write` is its own ability, and `credential:rotate` does not satisfy it.** A
re-key is a rotation in shape, and this route was first specified on the rotate family for that
reason. That was wrong: every credential already issued with `credential:rotate` — a service
scoped to rotate ordinary integration credentials, say — would have gained the power to install
a delegated-admin trust root the moment this release landed, with no reissue and nobody's
decision. `credential:admin`, the explicit break-glass, does satisfy it, because holding that
literal name is a marking an operator chose.

"Already claimed" is enforced, not assumed: the ownership row is locked and checked inside the
filing transaction. (`bfc:install:operator-credential` can mint an operator credential from the
host before any claim, so the gate alone never proved this.)

**Request** — `{"key_id": "k2", "public_key": "<64 hex chars or unpadded base64url>"}`. The pair
is flat here — it is the whole subject of this route — where the claim envelopes nest the same
two fields under `console_key` because they carry other things too.

- **201** — `{"console_key": {...}}`, the object above. The new key verifies; nothing was
  retired.
- **403** — `{"message": "This request is not permitted to write console countersigning keys."}`
  — **every** pre-authorization failure, byte for byte: no credential, an unknown one, an
  expired or revoked one, and a live credential without the ability. This route deliberately
  departs from the operator gate's usual `401`/`403` split (below), because here that split
  would tell a caller holding a stolen or stale bearer whether it is the credential that can
  take the deployment. The audit stream keeps the distinction; the response does not.
- **409** — `{"message": "..."}` — one of three conflicts, each with its own message and no
  row written: the key id is already on file (re-delivering the SAME key id is this same
  refusal — the surface does not special-case identical material); the MATERIAL is already on
  file under some key id, retired rows included; or the deployment is not claimed.
- **422** — `{"message": "..."}` — the material is not a canonical 32-byte Ed25519 public key,
  or the key id is malformed.
- **429** — beyond the operator write limits.

Both outcomes are audited to the lifecycle stream, ids only, with the actor typed: a success
appends `delivered` (the key was filed) and `activated` (it now verifies, and which key ids
verify with it); a refusal appends `denied_action` naming the refusal reason. A malformed key id
is never written into an audit note. Delivered key material never appears in either.

**The CLI transport** is `bfc:console:re-key {key_id} --local`, with the key material piped in
on **stdin** — never as an argument, because argv lands in shell history and `ps` output, and a
key id plus its material sitting there is a ready-made substitution recipe:

```
printf '%s' "$PUBLIC_KEY" | php artisan bfc:console:re-key k2 --local
```

It runs the same action and produces the same EFFECT. **It does not have the same authority.**
The command performs no credential check at all: its authority is HOST ACCESS, the same
standing this repo already gives `bfc:create-admin`, which creates a full admin user from the
same shell. Anyone who can run artisan here can also write the keyring row through `tinker`, so
the command grants nothing host access did not already carry — what it adds is validation and
an audit row (actor type `cli_operator`). An operator who wants console key custody gated by
credential rather than by shell should turn off the `commands` surface (PRD 1.14) and use the
route. Nothing about this transport's shape should be copied to a verb that handles a secret.

---

## RESERVED — Console fast-follow (not implemented)

The vendor-side Console is a decided fast-follow. So that it can land without reopening this
shipped contract, the following names are RESERVED here now. **Except where a bullet says
otherwise, none of this exists in this release: no guard, no table, no ability issuance.** One
reservation has since been drawn on — the `/bfc/console/*` namespace now has a live member,
documented in [Console key custody](#console-key-custody) above, not here. This section
deliberately contains no `### METHOD /path` route headings — the mechanical route-completeness
check covers live routes only, and nothing here is one.

- **Guard name `bfc-console`** — reserved for the Console's delegated-session guard. No guard
  by this name is registered.
- **Endpoint namespace `/bfc/console/*`** — reserved for Console endpoints. Its first member is
  live: [`POST /bfc/console/re-key`](#post-bfcconsolere-key), the key-custody verb documented
  above. `/bfc/console/enter` remains reserved and unimplemented.
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
