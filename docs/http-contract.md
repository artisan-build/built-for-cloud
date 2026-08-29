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

## Platform requirements

Named here because this contract is written for a consumer with no PHP, and a platform requirement
you cannot see is one you cannot plan for.

**A host serving this contract needs 64-bit PHP 8.3 or newer with the `gmp` extension
(`ext-gmp`).** Both halves come from the assertion cryptography, and neither is optional:

- **`ext-gmp`** arrives with `paragonie/paseto`, which is what verifies the PASETO `v4.public`
  assertion [`POST /bfc/console/enter`](#post-bfcconsoleenter) is gated on, and which declares the
  extension itself.
- **64-bit** is declared by `paragonie/sodium_compat` as `php-64bit`. A 32-bit PHP build cannot
  install this package even with `gmp` present.

Both requirements are **unconditional** — they are dependencies of the package, not of the Console —
so a deployment that never enables the Console carries them too.

Composer resolves both: `composer require` and `composer install` refuse on a host that is missing
either, so the ordinary failure is loud and at install time. One caveat worth a base image's
attention: Composer's generated runtime check (`vendor/composer/platform_check.php`) re-verifies the
PHP **version and word size** — and **not** the extension. So a `vendor/` directory built elsewhere
and copied onto a 32-bit host fails at boot, while the same directory copied onto a 64-bit host
without `gmp` boots fine and fails when the extension is first used.

Everything else is the ordinary Laravel baseline (`ctype`, `filter`, `hash`, `mbstring`, `openssl`,
`session`, `tokenizer`, `json`).

---

## Versioning and compatibility

Two discriminators, reported by [`GET /bfc/meta`](#get-bfcmeta):

- **`api_version`** (integer, currently **2**) — the contract's major version. It bumps whenever a
  **documented request or response shape changes incompatibly**: a field is removed or renamed, a
  type changes, or the semantics of an existing field change. It does **not** bump for additive
  changes.
- **`bfc_version`** (string, semver — the value in the [`GET /bfc/meta`](#get-bfcmeta) example
  below, which is the one place this document spells the current release) — the package release,
  for feature detection at finer grain than the major, alongside the `capabilities` array.

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

**api_version 2** (bfc **0.6.0**, this release). All changes since version 1, in one inventory.
Additive unless marked otherwise.

**Everything the Console adds in 0.6.0 is additive, so `api_version` stays 2. What carries the
signal is `bfc_version` 0.6.0 plus the `capabilities` entries** — `console-keys`, `console-vitals`,
`console-guard`, `console-enter`, `console-chrome-assets` and `app-action-audit-emit`.

**What "additive" covers here, stated as what actually shipped rather than as one paradigm case**,
because a reader applying rule 1 to their own change needs the real list:

- **New routes** — the paradigm additive case rule 1 names, and most of the Console is this.
- **New OPTIONAL request fields on existing routes** — `console_key` on the ownership claim and the
  onboarding exchange, `console_key_authority` on the onboarding issue. A request that omits them
  behaves exactly as it did before.
- **Conditionally additive response fields** — a claim or exchange response carries `console_key`
  only when the request supplied one, so an envelope that named no key is unchanged, response keys
  included.
- **Machinery that is not a route at all** — the `bfc-console` guard, the delegated-actor table and
  the app-action emission point serve no new wire shape and change none.

None of that removes a field, renames one, retypes one, or changes what an existing field means,
which is what rule 1 makes the major bump about. Written down here so it is not re-litigated, along
with the three things that WOULD have moved the major and none of which happened:

- **`GET /bfc/meta` reports the same five keys, with the same types and the same meanings.** Only
  `capabilities` changed, by gaining members — and it is documented above as an open set read by
  membership, never by position or by its full contents.
- **`built-for-cloud.credentials.session_guard` is still a single guard name, not a list.** An app
  that configured one guard resolves exactly what it resolved before. The matrix now has two session
  guards in it, but that key still names one, and the delegated guard is reached through the route's
  own `auth:bfc-console` rather than through this key.
- **No existing endpoint gained a field that changes how an existing field must be read.**
  `console_key` appears on a claim or exchange response only when the request supplied one; an
  envelope carrying none is unchanged, response keys included.

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
- New `capabilities` entry `app-action-audit-emit`, and the app-action audit stream's schema and
  emission (Console PRD D17). Additive: no request or response shape changes, and the stream has
  no read transport — see [the app-action audit stream](#the-app-action-audit-stream).
- New `capabilities` entry `console-chrome-assets` and one new route,
  [`GET /bfc/console/chrome.js`](#get-bfcconsolechromejs) — the console chrome's re-entry
  interceptor, plus the `bfc::` view namespace carrying the single package layout (Console PRD
  D11/D7). Additive: no existing request or response shape changes, and the capability names
  what this deployment SERVES, never that any page of the application renders it. See
  [the console chrome](#the-console-chrome).
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

- **The Console ops-vitals read ships (Console PRD D9/D15/D16).** All additive. New route
  [`GET /bfc/console/vitals`](#get-bfcconsolevitals), classified `metadata`, behind the
  `metadata:read` ability — which moves from RESERVED to ENFORCED in this release, and which
  **`credential:admin` deliberately does not satisfy**: the route is mounted behind its own gate
  rather than the operator gate, because D16 forbids the ownership/admin credential on any
  dashboard read path and the operator gate grants break-glass whatever ability a route names.
  That gate is the whole of the requirement — see the route's own section for the four
  conditions it enforces. `GET /bfc/meta` `capabilities` gains
  `console-vitals`. The `sensitive_read` lifecycle event now also covers vitals reads. Apps
  may declare an optional headline stat through the new
  `ArtisanBuild\BuiltForCloud\Contracts\DeclaresHeadlineStat` declaration interface, whose
  label vocabulary is a backed enum in the app's own repo; the package ships none of its own.
  The route additionally requires an OPERATOR subject and an ability set exactly equal to
  `{metadata:read}` — D16's "unable to touch content-classified or mutating surfaces" clause,
  enforced rather than described. **Two source-breaking PHP changes ride this release** (no wire
  shape changes): `OperatorAbility::RESERVED_METADATA_READ` is removed in favour of the
  `MetadataRead` case, and `DeclaresHeadlineStat` declares its vocabulary as a class CONSTANT.
  Both are documented with migrations in `release-notes/console-vitals.md`. The
  metadata-classification conformance helper in `ContractAssertions` covers **this package's own
  metadata endpoints only**; a general, app-extensible instrument was prototyped in this release
  and withdrawn — see the note under [Endpoint classification](#endpoint-classification).

- **The Console's delegated-session guard ships (Console PRD §4.3 / D7 / D8 / D14).** All
  additive, and `api_version` stays 2: no documented request or response shape changes. It is
  OFF by default behind `built-for-cloud.console.enabled`, and `GET /bfc/meta` `capabilities`
  gains `console-guard` only while that flag is on. What lands is the `bfc-console` guard (a
  real custom guard the package registers itself, scoped per route with Laravel's own
  `auth:bfc-console`), the `bfc_delegated_actors` shadow-actor table, a session-bound claim
  contract, D7's absolute 120-minute assertion-age cap enforced inside the guard by server-side
  session invalidation, and the structured re-entry `401` the new `bfc.console` middleware
  emits. Two package gates change behaviour ONLY for apps that enable the Console: `bfc.admin`
  admits a delegated `admin` on a route the console guard governs, and `bfc.auth` (plus the
  personal-credentials surface) refuses a delegated session rather than acting as the local
  session user. This AMENDS the v3.1 matrix invariant SEC-V3-10 from a token-vs-session rule to
  a session-vs-session one — see `release-notes/unified-store-guard.md`. Full detail under
  [Console — what has landed](#console--what-has-landed-and-what-is-still-reserved).

- **The Console's enter endpoint ships (Console PRD D12/D13).** All additive, and `api_version`
  stays 2: no documented request or response shape changes. New route
  [`POST /bfc/console/enter`](#post-bfcconsoleenter), classified `content`, mounted only on a
  deployment that has the Console enabled AND whose reserved `bfc-console` guard is this
  package's own — `GET /bfc/meta` `capabilities` gains `console-enter` under exactly that
  predicate, and `/bfc/console/enter` therefore moves out of the RESERVED list. What lands with
  it: the single-use `jti` burn (a new `bfc_console_assertion_burns` table, unique-indexed, and
  the only pruned table in the package), D13's **signed handoff state** — the return path rides
  inside the assertion's signature via a new optional `state` claim carrying the sha256 of the
  state blob — a per-IP `bfc-console-enter` limiter at 30/minute, and one uniform `403` for
  every refusal with the reason going to the audit stream as a `denied_action` event. The
  `denied_action` lifecycle event now also covers refused console entries. Apps may narrow where
  an entry may land with the new `built-for-cloud.console.return_path_allowlist` config key,
  which is empty (any in-app path) by default. **One source-additive PHP change rides this
  release** (no wire shape changes): `Assertion` gains a nullable `stateDigest`, and
  `Assertion::fromVerifiedClaims()` gains a matching trailing optional parameter — existing
  callers are unaffected.

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
  no operator ability implies either). `metadata:read` is the Console dashboard's read ability
  ([`GET /bfc/console/vitals`](#get-bfcconsolevitals)) and the ONE name in this vocabulary the
  break-glass below cannot reach — enforced not by the MCP primitive but by that route's own
  gate, which requires an operator subject and an abilities list EXACTLY equal to
  `{metadata:read}`. There is **no wildcard**; a credential with no abilities can do nothing. The
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
| `POST /bfc/console/enter` | `content` | its success is a `303`, not a body: the `Set-Cookie` it establishes IS a single reveal of a live delegated session credential, and the `Location` echoes the return path the issuer signed |
| `GET /bfc/console/chrome.js` | `content` | not a JSON body at all — a static JavaScript asset shipped inside the package. `metadata` is a claim about a bounded JSON shape, and a response with no such shape cannot make one; nothing in the body comes from this deployment's data |
| `GET /bfc/console/vitals` | `metadata` | bounded integers, a fixed health enum, a semver-validated `app_version`, a timestamp, and a headline label drawn from the app's declared vocabulary — no free text anywhere, and deliberately no `product` |
| `POST /bfc/subjects/offboard` | `metadata` | `{"offboarded": true, "fully_contained": bool}` / `{"accepted": true, "fully_contained": bool}` — bounded booleans only |

Vendor-side reads of `metadata`-classified endpoints are governed by the `metadata:read`
ability family. One route enforces it today —
[`GET /bfc/console/vitals`](#get-bfcconsolevitals) — and it is the least-privilege,
read-audited credential the Console dashboard uses. **A `metadata` classification is not by
itself an access grant:** the other rows in this table keep the gates they already had, and
`metadata:read` opens exactly the routes that name it.

**The column describes the success body and nothing else.** One row's success path is a
redirect rather than a body — [`POST /bfc/console/enter`](#post-bfcconsoleenter) — and it is
classified `content` on what that redirect carries, which is a session cookie. Error responses
are outside the column, as stated above: every surface shares prose `message` fields, and a `metadata` classification
makes no claim about a `401`, `403`, `422` or `429` envelope. It is also not an access grant —
see the paragraph above.

The classification is held for these endpoints by ENUMERATION, verified against real 2xx
responses. `ArtisanBuild\BuiltForCloud\Testing\ContractAssertions` writes out the expected
shape of every `metadata` row in the table above — exact keys, exact types, exact enum members,
numeric ranges read from the producer's own constants — and
`assertBuiltForCloudMetadataEndpoint($response, 'METHOD /uri')` checks one of them. Anything
outside the enumerated shape fails: an unknown key, a missing one, a wrong root structure, a
near-miss enum member, an out-of-range or non-finite number, a `health` value the producer
cannot emit. A route name it has not enumerated fails too. The package's own suite drives every
row, both `POST /bfc/subjects/offboard` shapes included.

**It certifies this package's endpoints and nothing else, and there is deliberately no way to
hand it a shape of your own.** An earlier revision of this release shipped a general,
app-extensible conformance instrument and claimed it certified "any metadata endpoint". It
could not, and the reason is structural rather than a defect that could be patched: **if the
consuming app supplies the schema, the app decides what counts as free text.** It picks the
field names and the permitted `enum` members, so runtime prose can be declared a bounded
identifier or a permitted member and pass. Four rounds of narrowing that schema language closed
four escapes and left that one untouched, because closing a type-name set does not establish
value *provenance*. The general instrument is withdrawn and deferred as its own decision; a
consuming app converting its endpoints should write explicit expected-shape assertions for
them, exactly as this package does for its own.

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
  "bfc_version": "0.6.0",
  "api_version": 2,
  "capabilities": ["tokens", "ownership", "onboarding", "webhooks", "credentials", "console-keys", "console-vitals", "app-action-audit-emit"],
  "claimed": true
}
```

`capabilities` is an open set — ignore unknown entries. `claimed` says whether an owner control
plane holds this instance.

**Every entry, and what each one is a claim about.** With `api_version` fixed at 2, this array plus
`bfc_version` is what a consumer feature-detects on, so an entry the contract never explains is a
name nobody can act on. The four original entries — **`tokens`**, **`ownership`**, **`onboarding`**
and **`webhooks`** — are UNCONDITIONAL: every install of the package reports all four, whatever it
is configured to serve. They name the package's four original feature families, and they are not
predicates about this deployment. One of them reads like one and is not: **`tokens` does not say the
legacy credential API is mounted.** That surface is gated on `built-for-cloud.credential_api.enabled`
(default `false`) and **no capability reports it** — an instance reporting `tokens` may answer `404`
to every route under [the legacy credential API](#the-legacy-credential-api-api_tokens-store). The
entries below are the ones that do carry a predicate, and each states it.

`console-keys` means this instance serves the countersigning-key surfaces below: the optional
claim-time key exchange and `POST /bfc/console/re-key`. It deliberately does **not** say
`console` — key custody is not the Console, and a control plane that read `console` as "this
deployment can be entered" would be reading a promise this capability does not make. The delegated
guard, the enter endpoint and the delegated-actor table all DO exist as of this release, each
advertised under its own name below; `console-keys` says nothing about any of them, and an instance
can report it while reporting none of them.

`console-vitals` means this instance serves [`GET /bfc/console/vitals`](#get-bfcconsolevitals).
It is named for the one surface it serves, not for the dashboard that reads it: the fleet
dashboard is the vendor's, and nothing in this release renders anything.

`console-guard` means this deployment has the Console ENABLED and therefore carries the
delegated-session machinery: the `bfc-console` guard, the `bfc_delegated_actors` table and the
re-entry `401`. It is absent when `built-for-cloud.console.enabled` is off, which is the
default, because the capability describes this deployment and not the package.

`console-chrome-assets` means this deployment serves the console chrome's machinery: the `bfc::`
view namespace carrying the single package layout, and the re-entry interceptor at
[`GET /bfc/console/chrome.js`](#get-bfcconsolechromejs). The name is deliberately about the ASSETS
— whether any page of the application wears the chrome is that application's own decision, made by
whichever of its templates extends the layout, and no package capability can report that. It rides
the chrome route's own predicate, so the capability and the route can never disagree. See
[the console chrome](#the-console-chrome).

`app-action-audit-emit` means this deployment **records** app-action audit events: the
`bfc_app_action_events` table, its transactional outbox, and the emission point an app calls. The
verb is deliberate — see [the app-action audit stream](#the-app-action-audit-stream) — because
**this release provides no read transport for that stream**, and a capability named
`app-action-audit` would read as one. It is unconditional, unlike the three Console capabilities
that carry a predicate — `console-guard`, `console-enter` and `console-chrome-assets`: what it names
is schema and an emission point every install carries whether or not the Console is enabled. Whether the DOOR emits is what `console-enter` already says.

`console-enter` means this deployment serves
[`POST /bfc/console/enter`](#post-bfcconsoleenter) — it is the entry that finally says an
operator can be handed here. Its condition is **stricter** than `console-guard`'s: the Console
must be enabled AND the reserved `bfc-console` guard must resolve to this package's own driver.
An app that defined its own `bfc-console` guard keeps it, and the package mounts no door in
front of somebody else's guard — so that deployment reports `console-guard` and not
`console-enter`. The capability and the route ride one predicate, so they can never disagree.
See [Console — what has landed](#console--what-has-landed-and-what-is-still-reserved).

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
- **500** — `{"message": "..."}` — a database fault, and on this route most plausibly a
  **deadlock or lock-wait timeout**: the filing transaction takes a row lock on the ownership
  record to prove the deployment is claimed, so a concurrent writer holding that row can time
  this one out. Nothing was written — the transaction rolled back — and retrying is safe.
  Deliberately not a `409`: an earlier revision caught every database exception and reported it
  as a key-state conflict, which sent operators looking for a key that was never filed. A lock
  timeout is a fault, and says so.

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

## Console vitals

### GET /bfc/console/vitals

*Operator credential whose abilities are **exactly** `metadata:read`* — rate-limited
(`bfc-vitals`), classified `metadata`, audited as a `sensitive_read`. The ops-vitals read
behind the vendor's fleet dashboard (Console PRD D9).

**The credential is the point of this route, so read the gate carefully.** Console PRD D16
describes the dashboard credential as least-privilege, read-audited and **unable to touch
content-classified or mutating surfaces**, and forbids using the ownership/admin credential for
any dashboard read path. That is EXCLUSIVITY, not membership, and this route enforces it as
three separate conditions:

1. **The presented bytes are not ALSO something else.** Before anything resolves, the bearer is
   compared against the configured `FALLBACK_TOKEN` and against the legacy `api_tokens` store;
   a match is a `401`. This is not belt-and-braces: the `bfc` guard has no path to either store,
   so neither can authenticate here — but set `FALLBACK_TOKEN` to the plaintext of a real
   dashboard credential (or file the same bytes as a legacy admin token) and the dashboard read
   succeeds while the same bytes stay admin-equivalent on the legacy surfaces, which is exactly
   the "unable to touch mutating surfaces" clause failing. Every legacy row counts, revoked
   included: the question is not whether those bytes can act elsewhere *today*.

   The refusal is byte-identical to any other `401` and writes nothing. The code paths are **not
   time-equalised** — a fallback collision returns before any query, a legacy one after a single
   `exists()`, an ordinary unknown bearer continues into store resolution — and that is accepted
   rather than closed: reading the difference requires already holding the bearer, and anyone
   holding it can present it on a legacy surface and learn the same fact directly.
2. **The credential holds `metadata:read`** — and the app's own declaration authorizes it for
   that ability. Unlike every operator verb route, this one is not mounted behind the operator
   gate, because that gate grants a break-glass credential whatever ability a route names; a
   route mounted there could not have enforced D16 at all.
3. **Its abilities are exactly `{metadata:read}` and nothing more.** A credential holding both
   `metadata:read` and `credential:admin` would read the dashboard AND mutate every operator
   surface; it is refused here. Inability has to be a property of the credential, because the
   credential is what the vendor holds and what an attacker steals.
4. **Its subject is an `operator`.** The ability vocabulary is an operator vocabulary; an
   application- or user-subject credential carrying the ability is refused.

All four are enforced by ONE gate. There is no `bfc.ability` layer in front of it: that
middleware enforces a strict subset of the above, so it never changed an answer, while its own
denial audit drained the delivery outbox — reintroducing on the refusal path the amplification
this route is hardened against.

Nothing else opens it. Not an admin `api_tokens` token — the `bfc` guard authenticates the
unified credential store and has no path to the legacy store, so a legacy admin secret is a
`401` here. Not `FALLBACK_TOKEN`, for the same structural reason.

**What this does NOT do:** it does not stop such a credential being MINTED. A combined
credential can still be issued and still operates every other surface it names; what it cannot
do is read the dashboard. Constraining issuance is a declared mint-ceiling concern
(`ConstrainsMintedCredentials`) with its own consequences for credentials already in the
field.

**Request** — no body. One optional header:

- `BFC-Contract-Version` — the `api_version` the caller believes this app speaks. Absent means
  no expectation was stated. A value that is not exactly this app's major does **not** refuse
  the request: the response reports this app's real `api_version` with `health: "degraded"`, so
  a dashboard can render the skew. D9 is explicit that displaying skew is the dashboard's job,
  and a caller cannot do that with an error.

**200**

```json
{
  "version": 1,
  "api_version": 2,
  "bfc_version": "0.6.0",
  "app_version": "1.4.2",
  "health": "ok",
  "deployed_at": "2026-08-29T09:14:00+00:00",
  "deploy_age_seconds": 5820,
  "queue": {
    "pending": 3,
    "reserved": 1,
    "failed": 0,
    "oldest_pending_age_seconds": 41
  },
  "headline": {"value": 128, "label": "active-sessions", "unit": "count"}
}
```

- `version` — this payload's own shape version, independent of `api_version`. It bumps when a
  field here is removed, renamed or retyped.
- `api_version`, `bfc_version` — the same two discriminators
  [`GET /bfc/meta`](#get-bfcmeta) reports, so a dashboard needs one request per app, not two.
- `app_version` — the application's own release, **echoed only when it is semver-shaped**, else
  `null` with `health: "degraded"`. The value is operator-authored config, and this endpoint is
  `metadata`-classified: it forwards a bounded version or nothing. (This is precisely why
  `GET /bfc/meta`, whose `product` is unbounded, is classified `content`.)
- `health` — `"ok"` or `"degraded"`. `"down"` exists in the shared vocabulary
  (`ArtisanBuild\BuiltForCloud\Vitals\Health`) for the dashboard, which needs a value for an
  app that did not answer at all — and **this endpoint never returns it**: a served `200` is
  itself proof of reachability, so there is no state it could observe that `"down"` would
  describe. `Health::fromDegradation` takes a boolean, so the range is structurally the first
  two, and this endpoint's enumerated expected shape admits only those two as well.
- `deployed_at` / `deploy_age_seconds` — when this deployment last shipped, and its age in
  seconds, both `null` when the app declares no deploy time. The age is signed: a `deployed_at`
  in the future reports a negative age rather than a clamped zero, because clock skew between
  the app and the vendor is something an operator should see rather than something this
  endpoint should hide. An age outside ±`VitalsPayload::MAX_AGE_SECONDS` (a century) is
  reported as `null` with `degraded` health rather than clamped — a clamped age is a wrong
  number presented as a right one. The same bound applies to
  `queue.oldest_pending_age_seconds`.
- `queue` — backlog integers, **every one nullable, and `null` never means zero.** It means
  this endpoint did not obtain the number, for one of two reasons the payload does not
  distinguish and `health` does: the driver does not report it (only the `database` queue
  driver exposes the pending/reserved split and an enqueue time to the package — every other
  driver reports `pending` from the connection's own size and nulls the rest, and health stays
  `"ok"`, since nothing failed), or the read FAILED, which degrades.

  **These numbers are a cached snapshot**, refreshed no more than once per
  `built-for-cloud.vitals.queue_cache_seconds` (15 by default; 0 disables caching) in the
  steady state. A value can therefore be up to that many seconds stale, which is the trade for
  not putting a queue query on every poll of a route the vendor polls continuously. The
  snapshot carries its own health, so a poll served from cache after a failed read still
  reports `degraded`, and it is keyed by deployment and queue configuration so instances
  sharing a cache prefix cannot serve each other's backlogs.

  **`oldest_pending_age_seconds` is not stale in the same way.** The snapshot caches the oldest
  pending job's enqueue TIMESTAMP and the age is derived per request, so the one number here
  whose entire meaning is that it moves keeps moving inside a window. The counts do not.

  **Caching requires a deployment identifier that is UNIQUE within the shared cache namespace**
  — `built-for-cloud.vitals.deployment_id`, falling back to
  `built-for-cloud.cloud.application`. With neither set the snapshot is **not cached at all** and
  every poll reads directly. That is deliberate: the key is a digest of the identifier plus the
  complete resolved queue connection config, and without one, two apps sharing a cache prefix
  would compute the same key and be served each other's backlog as honest local data — a silent
  cross-deployment leak into a vendor dashboard, which is worse than slow vitals. A product name
  and an environment are not identities and are not used as ones.

  Unique, not merely stable: two instances configured with the SAME identifier, environment and
  queue configuration still share a key. For replicas of one logical deployment reading one
  queue that is correct and intended — they have the same backlog. For two different deployments
  it is the collision this requirement exists to prevent, so give them different identifiers.

  Two further limits, stated because an unstated one reads as covered. The cache is
  read-through, not a lock: concurrent misses on a cold key each run the read, so the bound is
  on the steady state rather than on every burst. And it bounds how OFTEN the read happens, not
  how long one read may take — there is no portable wall-clock deadline across the queue drivers
  Laravel supports, so a genuinely hung dependency hangs the requests that miss the cache rather
  than every request.
- `headline` — the app's ONE headline stat, or `null`. `value` is a number, `unit` is
  `count` | `seconds` | `bytes` | `percent` | `null`, and **`label` is a case from a BACKED ENUM
  the app declares** in its own repo (D15) — by implementing
  `ArtisanBuild\BuiltForCloud\Contracts\DeclaresHeadlineStat` and setting its
  `HEADLINE_VOCABULARY` **constant** to an enum implementing
  `ArtisanBuild\BuiltForCloud\Vitals\HeadlineLabel`.

  Both halves of that are the enforcement, not a convention. D15 requires a vocabulary "defined
  in the app's repo at conversion time, never runtime data". A class constant must be a
  constant expression, so WHICH vocabulary applies is fixed when the file is parsed and cannot
  be selected from a request, a row or a tenant; and the enum's case set is fixed at compile
  time, so WHAT is in it cannot be assembled at runtime. `Tag::pluck('slug')->all()` satisfies
  neither half — which it would have, as a list of strings returned by a method, and any
  user-authored slug that happened to look identifier-shaped would have reached the vendor.

  The package ships no vocabulary: an app that declares none reports `"headline": null` rather
  than a fabricated stat. Each of the following **refuses** the headline — the field drops to
  `null` and `health` degrades: a case from an enum this app did not declare, a
  `HEADLINE_VOCABULARY` that is not an enum at all, a vocabulary with more than 64 cases or
  with a case whose backing value is not a bounded identifier, a value that is non-finite or
  beyond `VitalsPayload::MAX_HEADLINE_MAGNITUDE`, and a stat reported alongside no declared
  vocabulary at all (a contradiction in the app's own declaration).

  What remains the app's own code review, and nothing a package can decide: whether the
  declared vocabulary is a *good* one.

**This route never reports a dependency failure as an error** (D9). An unreachable queue, an
unparseable declared deploy time, a refused `app_version`, a refused headline and a stated
contract-version disagreement all produce a `200` carrying every field that could be filled and
`health: "degraded"`. A vitals endpoint that answers `500` when the queue is down tells a fleet
dashboard nothing about the app it most needs to describe.

**The one thing that can fail this route is the audit append**, and that is deliberate.
`metadata:read` is read-audited (D16), so a vendor read this deployment cannot record is one it
**must not serve**: every success writes one `sensitive_read` lifecycle event inside a
transaction, before the payload is assembled, and not best-effort. When that append fails the
route answers `500` and serves nothing.

No D9 exception is claimed for this, because D9 grants none. D9 says an unreachable or stale
app renders as an honest degraded row rather than breaking the dashboard — and an app answering
`500` **is** unreachable from the dashboard's side, so it renders as exactly that row. D9 is
working there, not being suspended. What D9 governs on this route is the payload's contents,
covered in the paragraph above.

The event carries the acting credential as an `operator_integration` actor, the credential id,
and a fixed note naming the route. It carries **no request or response body, no presented
secret and no credential material**. It is not "ids only": like every row in this instance-side
stream it also records this instance's configured product name, cloud application name and
environment, which are operator-authored strings. That stream is internal to the deployment and
is not a `metadata`-classified vendor surface.

The append deliberately does **not** drain the delivery outbox. A drain walks every claimable
row and may send mail; hanging one off a route polled up to sixty times a minute per credential
would make a dashboard poll a database and mail amplifier. The outbox row is still written in
the same transaction and is delivered by the next drain (`bfc:outbox:drain`, or the next
mutating request).

- **401** — no credential, an unknown one, an expired or revoked one, an offboarded principal's,
  a legacy `api_tokens` secret, `FALLBACK_TOKEN`, or a bearer whose bytes are ALSO the
  configured fallback token or a row in the legacy `api_tokens` store. All indistinguishable
  from one another, and **none of them is audited** — this route is reachable without a
  credential, and auditing anonymous refusals would hand a stranger a database-write amplifier
  on the one branch they can reach. (An earlier revision said the audit stream kept the
  distinction. It does not; that claim was stronger than the code.)
- **403** — a live unified-store credential that does not hold `metadata:read`, `credential:admin`
  included. Audited as `denied_action`.
- **429** — beyond the `bfc-vitals` limits: 60/minute per presented credential and
  300/minute per IP, applied **before** the gates, so refused attempts are bounded too.
  Note that co-located readers SHARE the IP bucket — two vendor credentials polling from one
  egress address draw on the same 300 — which is why that bound is five times the per-credential
  one rather than equal to it. The per-credential bucket is the primary bound; the IP bucket
  bounds noise from one address, and against 256-bit secrets it was never what made them
  unguessable.

---

## Console entry

The door. Everything above in the `/bfc/console/*` namespace is operator- or vendor-facing
machinery; this is the one surface a **browser** posts to, and the only way a delegated
operator session begins.

It exists only on a deployment that reports the `console-enter` capability — the Console
enabled, and the reserved `bfc-console` guard resolving to this package's own driver. Elsewhere
the path is a `404`, never a refusal.

*Pinned by* `tests/ConsoleEnterSurfaceTest.php` ("the door is mounted by default in a console
enabled app" and "routes off unmounts the door like every other package route"),
`tests/ConsoleDisabledTest.php` ("it mounts no enter door and advertises none") and
`tests/ConsoleEnterForeignGuardTest.php` ("an app that owns the guard owns entry too").

### POST /bfc/console/enter

Unauthenticated by construction: **this is the authentication event.** What stands in for a
gate is the issuer's Ed25519 signature over a PASETO `v4.public` assertion, the per-deployment
audience, the 60–120 second TTL and the single-use burn.

**The carrier is POST, and GET is not routed at all** — `405`, not a redirect. A GET assertion
is a live credential in the customer's own server and CDN logs, in browser history, and in the
`Referer` of the very next request the entered page makes.

*Pinned by* `tests/ConsoleEnterTest.php` ("does not route GET at the enter path, so an assertion
can never ride a query string").

**Request** (`application/x-www-form-urlencoded`, the shape an auto-submitting form posts):

```
assertion=v4.public.<base64url payload>.<base64url footer>
state=<base64url of {"return_to": "/orders?tab=open"}>
```

- `assertion` — the signed handoff. Required, ≤ 4096 bytes.
- `state` — the **signed handoff state**. Required, ≤ 4096 bytes, unpadded base64url of a JSON
  object. The only member this deployment reads is `return_to`; unknown members are ignored, so
  an issuer may grow the payload without a contract break. The assertion's `state` claim carries
  the lower-case hex **sha256 of these exact bytes**, which is what makes the state signed: it
  is checked before a single byte is decoded, and a state that does not hash to the claim is
  refused.

**303** — entry succeeded. `Location` is the **relative** `return_to`, emitted verbatim and
never resolved against the request's `Host`, so a spoofed header cannot turn a validated in-app
path into an absolute URL somewhere else. `Set-Cookie` carries the delegated session; from here
the operator is authenticated to routes the `bfc-console` guard governs, under D7's clocks.

*Pinned by* `tests/ConsoleEnterTest.php` ("mints a delegated session from a valid handoff and
lands on the requested relative path" and "carries the handoff its own role and agency into the
session, not the row's").

**403 — one uniform refusal, for every reason.**

```json
{"version": 1, "error": "console_entry_refused"}
```

Every failure answers with that body and that status: an expired assertion, one minted for
another deployment, a bad signature, an unknown key, a replayed mint, a tampered or absent
state, a return path this deployment will not honour, and an actor this deployment has
contained. **Nothing in the response distinguishes them.** The reason is recorded in the audit
stream as a `denied_action` event with the actor typed (`credential_holder`) and a bounded
reason code in the note — never returned to the caller.

**The refusal is not served unless it was recorded.** If the audit write cannot commit, the
request answers `500` rather than the ordinary `403`: D13 says verification failures are
audited, and a promise that lapses during an audit-store outage — precisely when someone is
probing — is worth less than none, because it is the one an operator believed. The availability
trade is real and stated: a deployment whose database is unwritable cannot refuse an entry with
a `403`. It also cannot complete one, so nothing is lost that was otherwise available, and no
caller can reach this branch on purpose.

*Pinned by* `tests/ConsoleEnterTest.php` ("answers a replayed, a wrong-deployment and an expired
assertion with byte-identical responses", "says nothing about the reason in the body it hands
back", "types the actor on every refusal, and names the mint only when it verified", "records
every refusal it serves, one row per refused entry" and "does not serve a refusal it could not
record").

**The responses are byte-identical. The TIMING is not, and that is a stated non-goal.** Two
channels survive:

- a refusal decided **before** the signature check (an unknown, pending or retired key id)
  returns measurably sooner than one decided after it, so key state stays distinguishable;
- a **replay** is measurably **slower** than a bad signature, a wrong audience or an expired
  token, because it is the only refusal that reaches the state binding, the shadow-actor upsert
  and a contended unique insert before it fails. A holder of a stolen assertion can therefore
  infer whether it has already been redeemed.

Neither is padded. Constant-time padding on a page-load path would cost real latency to hide
facts a prober largely supplies itself, and what makes a stolen or forged token worthless is the
per-deployment audience binding and the single-use burn, not the shape of the clock.

**429** — beyond 30 requests per minute per IP, applied **before** everything else on the route,
so refused attempts are bounded too and a `429` still says `429`. One bound and no global
ceiling, both deliberate: this surface is pre-authentication and carries no stable caller
identity that is not attacker-chosen (a second bucket on the mint id or key id would refresh
itself for free), and a bucket every caller shares would be a lockout lever on the **only** way
an operator gets in.

**What the endpoint guarantees**

- **Single use.** The assertion's `jti` is burned in the SAME transaction that opens the
  session, as an INSERT against a unique index rather than a read-then-write. A second
  presentation is refused **because the mint is spent**, not because something later noticed it.
  The two directions both hold: a redemption that fails does not spend the mint, and a burn that
  loses the race takes the redemption with it.

  *Pinned by* `tests/ConsoleEnterTest.php` ("refuses a genuine second presentation of the same
  assertion, because the mint id is spent", "rolls the burn back with the redemption, so the two
  commit or fail together", "keys the burn on a unique index, which is what makes it atomic" and
  "length-delimits the burn key, so two different issuer and mint pairs cannot hash alike").

  **One refusal deliberately does NOT spend the mint.** A contained (offboarded) actor's entry
  is refused inside the burn's own transaction, so the burn rolls back with it and that
  assertion stays presentable until its TTL runs out — every presentation refused, every one
  audited as `actor_deactivated`. Spending it would make the second attempt audit as `replayed`,
  which asserts the token was already *redeemed*; it was not, and an operator reading an
  offboarded human's attempts to get back in would draw exactly the wrong conclusion. The burn
  table records mints this deployment redeemed; the audit stream records presentations, and it
  records all of them. The exposure is bounded by the 60–120 second TTL and by the rate limiter,
  and no session is produced on any attempt.

  *Pinned by* `tests/ConsoleEnterTest.php` ("leaves a contained actor's mint unspent, so every attempt audits as containment").

  **What the suite does not exercise, said plainly: a genuine CONCURRENT double presentation.**
  sqlite serializes writers in-process, so the tests above drive the sequential replay and the
  shared-transaction property the race rests on — not the interleaving itself. A mutation-debt
  row records it, and a two-connection race on a driver with real row locking is what would
  close it.
- **The return path cannot be substituted.** It is not a request field; it rides inside the
  vendor's signature, and it must additionally be a same-origin **relative** path in every
  percent-decoded form — absolute, protocol-relative, backslash, encoded-slash, double-encoded
  and control-character forms are all refused, whatever the issuer signed — and inside the
  deployment's `built-for-cloud.console.return_path_allowlist`, when it configures one. An empty
  allowlist is the default and means "any path in this app"; the relative check is what closes
  open redirect.

  **A `.` or `..` PATH SEGMENT is refused outright, in every decoded form**, and that rule is
  about who normalizes. `/admin/../billing` is legitimately relative, so every other check passes
  — and the *browser* resolves it to `/billing` before this app sees it, which would bypass a
  configured landing restriction with a value nothing had rejected. `/admin/%2e%2e/billing` and
  `/admin/%252e%252e/billing` are the same defect one and two layers down. A dot *inside* a
  segment is untouched: `/reports..csv` is an ordinary path. The allowlist is then matched
  against the fully **decoded** path, so `/%61dmin/users` and `/admin/users` cannot be answered
  differently; the redirect still emits what the issuer signed, verbatim.

  **The path is established ONCE, before anything is decoded**, and that ordering is what makes
  the rule hold. Query and fragment are split off the *raw* value; everything before the first
  literal `?` or `#` is the path, for good. A revision that split them off each *decoded* form
  was bypassed by `/admin%3F/%2e%2e/billing`: it carries no literal `?`, so the raw path is the
  whole string and looks clean, and decoding invents a `?` behind which the traversal hid — the
  check saw `/admin` while the browser, which treats `%3F` as an ordinary path character,
  resolved the `%2e%2e` and landed on `/billing`. `%23` did the same with a fragment.

  **The configured prefixes go through the same door.** A prefix is canonicalized before it is
  compared, and one that is not itself a safe in-app path matches *nothing* rather than being
  trimmed into something: a configured `//` used to `rtrim()` to the empty string, which was the
  wildcard branch, so it silently allowed every path. Only a literal `/` is the wildcard now.

  *Pinned by* `tests/ConsoleEnterTest.php` ("refuses a return path that is not a safe
  same-origin relative path, whatever the mint signed", "refuses a return path carrying a
  traversal segment in any decoded form, allowlist or no allowlist", "leaves a dot inside a
  segment alone, because that is an ordinary path", "matches the allowlist against the fully
  decoded path, not the raw one", "establishes the path once, so a query string cannot appear
  out of a decoding round", "honours a configured return-path allowlist, at a segment boundary",
  "refuses an allowlist prefix that is not itself a safe in-app path, rather than widening on
  it", "treats a literal root prefix as the wildcard it looks like" and "canonicalizes the
  configured prefixes the same way it canonicalizes the path").
- **No CSRF token, and that is not an oversight.** The handoff is a cross-site POST from the
  issuer's page, and a `SameSite=Lax` session cookie — Laravel's default — is not sent with one,
  so the app has no session with that browser and no token it could have planted. The signed
  state is what replaces it.

  *Pinned by* `tests/PersonalSurfaceWebGroupTest.php` ("the console door starts a session
  without csrf validation" and "only the personal surface and the console browser routes ride
  the session stack").

- **The presented credential is marked sensitive, and then removed.** Every frame in the package
  that can hold a console assertion — a string named for a token, and the `Request` that carries
  the submitted form — declares PHP's `#[SensitiveParameter]`. More importantly, the assertion is
  **taken out of the request object** as soon as it has been read and before anything that can
  throw runs, because a rich error reporter serializes request *input* alongside a trace
  regardless of which frames hold what, and no attribute touches that.

  **The claim is narrower than "no frame leaks the credential", deliberately.** The `Request`
  travels through the entire framework pipeline — routing, middleware, the controller dispatcher
  — and every one of those frames holds it; they are vendor frames and this package cannot
  annotate them, which is equally true of every bearer token a Laravel application receives. So
  does `ParagonIE\Paseto`, which receives the token itself and carries it in the *previous*
  exception's trace on a cryptographic refusal — kept as the only operator diagnostic for one,
  and never reaching a response. What **is** enforced: no frame this package declares carries the
  credential unmarked, and the object those vendor frames hold no longer carries it. What is
  **not** reachable: the raw request body if something has already buffered it (the documented
  carrier is a form POST, where nothing does), and any credential held in a shape the scan's two
  rules do not name.

  The scan itself covers filename-derived classes, enums and interfaces under `src/`; it does
  **not** cover package functions, anonymous classes or standalone traits, which PHP can also make
  a frame from. Such a frame is caught by reviewing the diff that adds it, not by this suite, and
  a debt row names it.

  *Pinned by* `tests/AssertionSecrecyTest.php` ("marks every frame in this package that holds
  console assertion bytes", "names an unmarked assertion frame when the walk meets one", "names
  the shapes it cannot reach, so the claim beside it stays true" and "takes the presented
  assertion out of the request before any validation runs").

**What it does NOT guarantee, stated rather than implied.** The signed state closes open
redirect and stops a state being moved between mints. It does **not** close forced login: an
attacker who holds a legitimately-minted assertion for their **own** issuer identity can
auto-submit it in a victim's browser, leaving that browser entered as the attacker. No state
parameter closes that here, because every state such an attacker needs is one the issuer minted
for them, and the classic defence — a state the relying party planted in the caller's session —
requires a request that carries the app's cookie, which the cross-site POST is not. What bounds
it is the 60–120 second TTL and the burn: the window is short, the token is spent, and the
session carries the **attacker's** audited identity, so nothing done under it is attributed to
the victim. The residue is that a victim may act inside an app under an identity they did not
choose.

*Pinned by* `tests/ConsoleEnterTest.php` ("refuses an entry whose state was tampered with after
the mint signed it", "refuses an entry that presents no state at all", "refuses a mint that
signed no state, whatever state is presented" and "refuses a state lifted from a different
mint").

**A successful entry writes no event to the credential lifecycle stream.** That stream is
credential-scoped. A successful entry is audited on the
[app-action stream](#the-app-action-audit-stream) instead — one `console-entered` event, typed as
the delegated actor that was admitted, written inside the same transaction as the burn and the
redemption. It fails **closed**: an entry that cannot be recorded is not served, and one whose
transaction rolls back leaves no event. What a successful entry also leaves is the shadow-actor
row's refreshed `last_handoff_*` copy and its `updated_at`. Verification FAILURES are audited in
full on the credential stream, which is what D13 requires.

**What that event attests, and what it does not.** It says the REDEMPTION COMMITTED: the mint was
spent and the delegated principal was written into the request's session, in one transaction with
the event. It does **not** say the operator ended up with a usable session. The guard writes the
session in memory and Laravel's `StartSession` persists it to the session store after the
controller returns — after this transaction has committed — so a session-store failure in that
window leaves a permanent event for an entry whose session never became durable, and no rollback
can reach back through a committed transaction to undo it. The fail-closed property runs one way
only, and this is the sentence that says so rather than leaving a reader to infer the symmetry.

*Pinned by* `tests/ConsoleEnterAuditTest.php` ("records one app-action event for a successful entry, through the real door", "records no entry event when the entry transaction rolls back" and "writes nothing to the credential audit stream on a successful entry").

**Storage.** One row per redeemed mint in `bfc_console_assertion_burns`, keyed on a digest of
issuer + `jti`. It holds no secret — a `jti` is a mint identifier, worthless without the signed
token that carried it — and it is the one table in this package that is **pruned**: a row is
useful only until the assertion it names expires, and the endpoint drops expired rows after each
successful entry. The margin points one way on purpose: a row dropped while its assertion could
still be presented would un-spend a mint.

*Pinned by* `tests/ConsoleEnterTest.php` ("sits exactly on the prune boundary: one second inside keeps a burn row, one second past drops it").

---

## The console chrome

**READ THIS SECTION WITH ONE DISTINCTION IN MIND.** Everything here about the SERVER — the routes,
the middleware, the rendered HTML, the escaping, the 401 shape — is executed by this package's test
suite. Everything about the BROWSER is not. The interceptor's own logic is executed (in node,
against a stand-in), but every behaviour it asks a browser for is **read from a standard and has
never been watched happening**, and each such statement below is marked **"Specified, not
observed."** That label is not a hedge and not a softening: it tells you which sentences someone
has checked by running them and which are a careful reading of a specification.

Why it is marked rather than fixed: a package with no application shell cannot execute a browser,
so for these claims a citation is the ceiling. The list of every one of them, with the concrete
check that would settle it, is at
`~/Herd/brain/projects/built-for-cloud/pr5-browser-observable-claims.md`, and the first app
conversion is where a real browser exists to run them.

Console PRD D11 (one layout) and D7 (re-entry). This section describes what the PACKAGE serves;
whether any page of a consuming application wears the chrome is that application's own decision,
made by whichever of its templates extends the layout. `GET /bfc/meta` `capabilities` gains
`console-chrome-assets` on a deployment serving these, and the name is deliberately about the
ASSETS: no package capability can report that an app's pages render them.

### One layout, branching internally

The package ships **exactly one** layout, `bfc::layout`, in a `bfc::` view namespace registered
unconditionally (a view namespace mounts nothing — it is a name an application has to reach for
— so it is not one of the selectable surface families). It is publishable as
`built-for-cloud-views`; publishing does not create a second layout, because Laravel's namespaced
finder prefers the published copy for the SAME view name.

**Layout selection is never conditional.** There is no "console layout" to switch to. What
differs between a local login and a delegated console session is what the one file renders
inside itself, driven by the ONE resolved acting principal (D14) — the same value the request
acts as and the audit stream attributes to.

- A **local** (non-delegated) authenticated session renders **zero** chrome: no attribution bar,
  no operator identity, and no interceptor script on the page.
- A **delegated** session renders the attribution D4 promises — the operator, the agency they
  act for when their handoff named one, the trusted issuer's host, and this session's role from
  the two-value `admin`/`member` vocabulary.

**Display values are bounded again at render time, and refused rather than truncated.** The
assertion verifier already bounds `display_name` and `on_behalf_of` to 120 characters and
rejects control characters, at the door. The chrome applies the same rule a second time, because
the claims a request acts under are read from the SESSION and anything able to write the session
store can write a claim that never passed a verifier. A value that is over-long, carries a
control character, or is not valid UTF-8 is treated as no value at all: the operator renders as
`Delegated operator` and the agency is omitted. **Bounded is not sanitized** — a short, printable
hostile string is a legal claim — so every display sink is an escaped Blade echo, in an element
body or a double-quoted attribute, never in a script, a style, a URL or an unquoted attribute.

**The residue, named:** the bound is on SHAPE and the escaping is on SYNTAX. Neither is a
statement about TRUTH. A well-formed name that is simply not this operator's renders exactly as
a correct one would; what makes the claim trustworthy is the vendor's signature at the door.

*Pinned by* `tests/ConsoleChromeTest.php` ("renders one and the same layout file for a local
session and a delegated one", "renders zero console chrome for a local authenticated session",
"renders the delegated attribution the operator entered with", "follows the resolved acting
principal, not the delegated guard the route does not name", "renders a hostile display name,
agency and issuer inert", "proves the escaping assertion can fail against an unescaped sink" and
"refuses a display claim that is over-long, control-bearing or invalid UTF-8 rather than
truncating it").

### GET /bfc/console/chrome.js

The chrome's re-entry interceptor, served from the application's own origin. Mounted under the
same condition as [the door](#post-bfcconsoleenter): the Console enabled AND the reserved
`bfc-console` guard resolving to this package's own driver.

**Request.** No body, no parameters. A browser `<script src>` fetch carrying the app's session
cookie.

**Gate.** Both halves of D14's seam, in this order: `bfc.console` (the structured re-entry 401)
and then Laravel's own `auth:bfc-console` (which makes the console guard the guard of the
request). The chrome is a delegated surface end to end, so its one asset route answers on the
same terms as the page that loads it. This is scoping rather than confidentiality — the script
is not secret — and what it buys is that every chrome route answers by one rule instead of a
list of exceptions.

**Response.** `200` with `Content-Type: text/javascript; charset=utf-8`,
`Cache-Control: private, no-store`, `X-Content-Type-Options: nosniff` and a content `ETag`. The
`no-store` is deliberate: a response whose availability depends on a session cookie must never
enter a shared cache, and the cost is a re-fetch per page load of a few hundred static bytes.
*The headers are executed — the assertion reads them off the real response. That a browser or an
intermediary HONOURS `no-store` is specified, not observed.*

**Refusals.** No delegated session — absent, capped or invalidated — answers with the same
structured `401` every other console surface does: header `BFC-Console-Reentry: 1` and the body
documented under [delegated session clocks](#console--what-has-landed-and-what-is-still-reserved).
A deployment that mounts no package routes, or whose `bfc-console` guard is its own, answers
`404`.

**The throttle is INSIDE the gate on this route, and every other route in this contract puts it
outside.** That inversion is forced by the framework rather than chosen. Laravel sorts a route's
middleware by its priority map, in which `AuthenticatesRequests` outranks `ThrottleRequests`, so
a throttle listed in FRONT of `auth:bfc-console` makes Laravel hoist the auth middleware above
everything that follows it — `bfc.console` included — and a request with no delegated session
then meets the framework's generic `AuthenticationException` instead of the structured 401. That
would kill re-entry. The cost, stated: the pre-gate path is not rate-limited by this route. What
a refused fetch costs is a session read and a guard read, the same as any page in the host
application.

*Pinned by* `tests/ConsoleChromeRouteTest.php` ("requires both halves of the delegated seam on
every registered chrome route", "runs the re-entry answer in front of the guard scoping, after
Laravel has sorted the stack", "names a route whose throttle hoists the guard scoping in front
of the re-entry answer" and "serves the interceptor to a delegated session and the structured
401 to nobody").

### What the interceptor does

It wraps `fetch` and `XMLHttpRequest` and watches for the re-entry answer.

**The first check is that the response is SAME-ORIGIN with the console page**, compared as scheme
plus authority against the response's own URL (`response.url` for fetch, `responseURL` for XHR).
The wrapper sees every response the page makes, third-party ones included, so without that check
any CORS-readable endpoint that exposes `BFC-Console-Reentry` through
`Access-Control-Expose-Headers` could answer `401` with a `reentry_url` of its choosing and send
an administrator's top-level window there — a phishing primitive on the exact path operators are
trained to follow. A response whose URL cannot be read (an opaque `no-cors` response, or a
document that cannot report its own origin) is **ignored entirely**: not acted on, and not
reported either, because the script cannot establish it is looking at its own application's
answer.

**The residue of that check, stated:** a redirected response reports its FINAL URL and is judged
on where it landed; and a same-origin PROXY the application itself operates is
indistinguishable from the application — if an app forwards a third party's bytes under its own
origin, an origin comparison cannot see through it.

*Specified, not observed:* that an opaque response carries an empty `url` and that a redirected
one reports its final URL are read from the Fetch standard. The proxy statement is about origins
and holds whatever a browser does.

**And it introduced one new limitation, disclosed rather than absorbed.** A document with no
readable EFFECTIVE origin can never verify any response, so the interceptor cannot function there
at all. It says so at install time (see the causes below) and then does not install, rather than
sitting quietly inert. That is a frame sandboxed with `allow-scripts` and **without**
`allow-same-origin`, or a runtime that does not expose `window.origin`.

The check reads **`window.origin`**, which is the document's effective origin — not
`location.origin`, which is derived from the URL and still reports a perfectly good origin inside
a sandboxed frame. An earlier revision of this package read `location.origin`, so this gate could
never fire in the one case it was written for. There is deliberately no fallback: a runtime
without `window.origin` gets no interceptor and is told so.

`about:blank` is **not** in this set as a rule — a blank document normally inherits its creator's
origin. An earlier revision of this sentence listed it flatly and that was too broad.

*Specified, not observed:* that `window.origin` is `"null"` in a sandboxed frame while
`location.origin` is not, and that the two agree in an ordinary document.

Only then does it read the status and the header — **branching on the header, never on the
status alone**, so an application's own `401` is left entirely alone.

- With the documented envelope in the body (`version` of `1` and `error` of
  `console_reentry_required`) and a `reentry_url`, it performs a **top-level** navigation:
  `window.top.location`, with `return_to` carried across as a percent-encoded query parameter.
  Never the frame the capped request came from — re-entry means leaving this app, and doing it
  inside an iframe would either be refused by the issuer's framing policy or leave the outer
  document on a dead session.
- With **no** `reentry_url` — which is what the server emits when the deployment has configured
  none — it **invents nothing**. It navigates nowhere, marks the chrome element
  `data-bfc-console-reentry="unavailable"`, replaces its text with a notice, and dispatches
  `bfc:console-reentry-unavailable` on `document` so the host application can respond in its own
  voice. A `reentry_url` whose scheme is not `http(s)`, a body that is not the documented
  envelope, and a `window.top` that cannot be reached at all, all take the same path.
- It **never swallows** the response. The wrapped `fetch` resolves with the original response
  object (the body is read from a `clone()`), and the XHR wrapper only ADDS a listener, so the
  caller's own handlers still run and still see the `401`.

**IT NEVER FAILS SILENTLY EITHER, and that is one rule rather than three exceptions.** Every path
on which the interceptor cannot complete a re-entry ends the same way — the chrome element marked
`data-bfc-console-reentry="unavailable"` and `bfc:console-reentry-unavailable` dispatched — with
`detail.cause` naming which of exactly three things happened:

| `detail.cause` | what happened | is the delegated session over? |
|---|---|---|
| `origin_unverifiable` | this document reports an opaque origin, so no response can be verified as the application's. Said once at install time; the interceptor then does not install | **no** — so the chrome is marked but its attribution text is left alone |
| `no_destination` | re-entry is required and the payload names nowhere to go: no `reentry_url`, a scheme this script refuses, an envelope it does not recognise, or an unreachable `window.top` | yes |
| `navigation_refused` | a destination was found and the **browser refused the navigation**, throwing out of `Location.assign` | yes |

On `origin_unverifiable` the operator's attribution is still TRUE — their session is alive — so
the bar keeps saying who they are. Replacing D4's attribution with a warning about a capability
this document lacks would trade a correct statement for a notice.

*Specified, not observed:* what is executed is that the script announces each cause and which one
it picks. WHEN a browser puts it in `origin_unverifiable` or `navigation_refused` — the sandbox
and refusal behaviour — is read from a standard.

### The `navigation_refused` guard rests on an unverified premise

This one is called out on its own rather than left in the table, because it is the sharpest case
in this section and because it concerns a guard added specifically to stop a silent failure.

**The whole path assumes that a browser refusing a top-level navigation RAISES out of
`Location.assign`.** That is what the `try` catches, and it is what produces the
`navigation_refused` announcement. It is read from the specification. Nobody has watched a browser
do it.

**If a refusal is silent in practice, the `try` catches nothing** — no cause is announced, no
event fires, and the operator sits on a dead page believing re-entry is under way. **That is
precisely the defect the guard was added to close.** Read it as a guard whose premise is
unverified, not as a guarantee that a refused re-entry is always reported.

What settles it: load a console page inside `<iframe sandbox="allow-scripts allow-same-origin">`,
let a request receive the capped 401, and observe whether
`bfc:console-reentry-unavailable` fires with `cause: "navigation_refused"` or nothing happens at
all. Until somebody does that, this paragraph is the honest statement of the guard's strength.

### Automatic re-entry is a full-page reload, and unsaved work goes with it

This is D7's stated cost and it is said here rather than left to be discovered. **When the
interceptor re-enters, it performs a top-level navigation, so any unsaved client-side state on
the page — a half-written form, an in-flight component's local state, an unsent draft — is
lost.** At the two-hour assertion cap an operator sees exactly one full-page reload; with a live
session at the issuer they are not logged out, but the reload still happens. "The caller still
receives its `401`" does not preserve anything once navigation has begun.

The package will not decide for an application what to do about that, but it does give it the
moment. **Two DOM events on `document`, and they are a public surface:**

| event | when | `detail` |
|---|---|---|
| `bfc:console-reentry` | synchronously, immediately **before** the navigation | `{reason, return_to, cause: null}` |
| `bfc:console-reentry-unavailable` | when re-entry cannot be completed | `{reason, return_to, cause}` |

`detail.reason` is the `reason` enum from the 401 body (or `null` when the body could not be
read); `detail.return_to` is the relative path the server chose; `detail.cause` is one of the
three values in the table above, and is `null` on the departure event.

**The ordering is the point and it is pinned as an ordering**, not as two facts that happen to
both be true: the departure event is dispatched, and only then is the navigation performed. When
the browser refuses that navigation, an `unavailable` event follows the departure one — so a
listener that saved a draft is also told the page is not going anywhere.

*Executed:* that the script dispatches before it calls `assign()`, asserted as a sequence in one
ordered channel. *Specified, not observed:* that a browser runs every listener to completion
before the navigation takes effect, and that a synchronous `localStorage` write survives it. A
listener that saves over the network has no such guarantee under either reading.

**Neither event is cancelable, and `bfc:console-reentry` is deliberately not.** A listener runs
synchronously, so a `localStorage` write completes before the page starts leaving; a network save
does not. Cancelling was considered and rejected: the delegated session is already dead
server-side, so suppressing the navigation grants no authority and buys nothing — it only strands
the operator on a page whose every request fails, turning D7's honest reload into a silent dead
end.

**It is a convenience and not an enforcement.** Revocation is enforced server-side, inside the
guard, on every route: a browser with this script blocked, disabled or simply not loaded still
cannot act with a dead session — it sits on a page whose requests all fail. That ordering is
what the amended D7 chose: revocation truth never depends on the browser.

*Pinned by* `tests/ConsoleReentryInterceptorTest.php` ("ignores a cross-origin response carrying
the re-entry header", "ignores a response whose own url it cannot read", "refuses to navigate on
a body that is not this contract envelope", "navigates the top-level window through the issuer,
preserving the return path", "navigates the top window rather than the frame the capped request
came from", "announces the navigation before performing it, so an app can persist unsaved state",
"announces every path on which it cannot complete a re-entry, naming the cause", "degrades
honestly when the deployment has configured no re-entry url", "refuses a re-entry url whose
scheme is not http or https", "degrades honestly when the top window cannot be reached at all",
"hands the capped response back to its caller rather than swallowing it", "performs the same
re-entry for a capped XMLHttpRequest" and "ignores an ordinary 401 that is not a console
re-entry").

### Content Security Policy

**Every statement in this subsection about how a browser ENFORCES a policy is specified, not
observed.** What is executed is what the package EMITS — the assertion below inspects the rendered
response — and nothing more. No page has been served under a real `script-src` and watched. Three
successive corrections to this subsection each replaced one confident spec claim with another, so
what changed is the kind of claim it makes, not another attempt at a more careful sentence.

**What the package emits is a single same-origin external `<script src>` with no nonce, no inline
script and no inline style anywhere on the page.** It is served from a route rather than inlined
precisely so that a consuming app never has to add `'unsafe-inline'` to `script-src` to make a
dependency's chrome work — a package that forces that on an app has handed it a downgrade. What
your policy has to say about that tag depends on which KIND of policy you run, and the two
answers are different.

*Pinned by* `tests/ConsoleChromeTest.php` ("renders the interceptor as an external script with no
inline script anywhere on the page").

**Host-allowlist policies — `script-src 'self'` is normally sufficient.** A policy naming
`'self'` (or an origin that covers this app) admits the tag as it stands. This covers most
deployments and it is the case the package is designed around.

**With one qualification, because `script-src` is not always the directive that decides.** If
your policy also sets `script-src-elem`, THAT directive governs `<script src>` elements and
`script-src` is not consulted for them at all — so `script-src 'self'; script-src-elem 'none'`,
or any `script-src-elem` that does not cover this origin, blocks the interceptor however
permissive `script-src` looks. Check the narrowest directive that applies to script ELEMENTS,
not the fallback. *Specified, not observed.*

**Nonce-only and `'strict-dynamic'` policies — `'self'` is NOT enough, and the tag will not load
without help.** Two separate reasons, and an earlier revision of this section got both wrong:

- Under `script-src 'nonce-…'` with no host source, nothing is allowed except what carries the
  nonce. The package's tag carries none, so it is blocked.
- Under any policy containing `'strict-dynamic'`, CSP Level 3 says host-source and scheme-source
  expressions — `'self'` included — **are ignored** for script loading, and only a nonce or hash
  admits a parser-inserted script. Adding `'self'` alongside `'strict-dynamic'` therefore does
  not help: the tag is still blocked, and the interceptor silently does not exist while capped
  XHRs sit on a dead page. *Specified, not observed* — as is the browser asymmetry immediately
  below.

  Worse, this fails *asymmetrically across browsers*: a CSP2-era browser ignores the
  unrecognised `'strict-dynamic'` keyword and honours `'self'`, so a policy carrying both loads
  the script in old browsers and blocks it in new ones. Test on a browser that implements CSP3.

**Two supported remedies, and pick whichever fits your policy:**

1. **Publish the views and attach your own nonce.**
   `php artisan vendor:publish --tag=built-for-cloud-views` puts `layout.blade.php` and
   `chrome.blade.php` in `resources/views/vendor/bfc`, where you can add
   `nonce="{{ $yourNonce }}"` to the `<script>` tag. Publishing does **not** create a second
   layout: Laravel's namespaced finder prefers the published copy for the same view name, so
   `bfc::layout` still names exactly one template — yours.
2. **Load it from an already-trusted script.** Under `'strict-dynamic'`, a script injected by a
   trusted script inherits that trust, which is what the keyword exists for. From your own
   nonce-carrying bundle:
   `const s = document.createElement('script'); s.src = '/bfc/console/chrome.js'; document.head.append(s);`
   In that case remove the package's own tag by publishing the chrome partial and deleting it,
   or the browser will simply block the duplicate.

**The package will not guess a nonce for you and will not emit an inline tag.** There is no
config key for a nonce here, deliberately: a nonce has to come from the same request that set the
header, Laravel has no framework-wide nonce accessor to read it from, and a package inventing one
would be a package deciding the shape of an app's CSP.

The rest of what the chrome needs is deliberately small, so that no other directive has to be
widened:

| directive | why |
|---|---|
| `script-src` | the interceptor tag, and nothing else is loaded — see the two cases above |
| `connect-src` | untouched — the interceptor wraps calls the app was already making and issues none of its own |
| `style-src` | untouched — the chrome ships no stylesheet and no inline `style` attribute |
| `img-src` | untouched — the chrome loads no images |
| `frame-ancestors` | your own choice; the interceptor's top-level navigation degrades honestly when it is framed cross-origin, rather than navigating the frame |

**Which directives govern the top-level navigation — corrected twice now, so here is the whole
of it.** `form-action` does **not** apply: it restricts form submissions, not a script-initiated
`location.assign()`. `navigate-to` would have applied, but it was dropped from CSP Level 3 and
never shipped in any browser, so it governs nothing today.

**What DOES apply is sandboxing, and it comes in two forms — one of which is a CSP directive.**
An earlier revision of this paragraph asserted that no CSP directive stands between this script
and the issuer, and that sandboxing "is not CSP". Both were wrong:

- the **`sandbox` iframe attribute**, when this page is framed without `allow-top-navigation`; and
- the **CSP `sandbox` directive**, which applies the same HTML sandboxing flags from a response
  header. `Content-Security-Policy: script-src 'self'; sandbox allow-scripts allow-same-origin`
  is a coherent policy under which the interceptor **loads and its navigation is denied** — the
  script runs, finds a destination, and the browser refuses the assignment.

If you send a CSP `sandbox` directive, include **`allow-top-navigation`** — the full token — or
accept that automatic re-entry cannot happen on that page.

**`allow-top-navigation-by-user-activation` is NOT a substitute here, and an earlier revision of
this sentence implied it was.** That token permits a top navigation only under transient user
activation, and a re-entry triggered by a BACKGROUND Livewire or XHR response has none: the
operator did not click anything to cause it. It may work when the capped request happens to follow
a click closely enough to still be within an activation window, which makes it worse than useless
as a recommendation — it would work in testing and fail in the case the feature exists for.
*Specified, not observed.*

**When the browser refuses BY THROWING, the interceptor says so rather than failing silently.**
The call is guarded, and the script marks the chrome element and dispatches
`bfc:console-reentry-unavailable` with `detail.cause` of `navigation_refused`. That
`Location.assign` throws on a refused top navigation is *specified, not observed* — see
[the named entry above](#the-navigation_refused-guard-rests-on-an-unverified-premise), which
states what follows if it does not.

**The residue, and it is narrow only if the premise holds:** a refusal the browser declines to
raise — reported only to the developer console — cannot be caught, so that case remains invisible
to the script. *Specified, not observed:* which refusals raise and which do not. If none of them
raise, this residue is the whole behaviour rather than an edge of it.
The operator is then left on a page whose requests all fail, which is where they would have been
had the script never loaded. Revocation is unaffected either way: it is enforced server-side, in
the guard, on every route.

---

## The app-action audit stream

Console PRD D17. A **new** append-only stream recording what principals DO in a converted app —
separate from the credential lifecycle stream, which stays credential-work only and is **not**
extended by this release.

### There is no read transport for this stream

**This release provides no way to read the app-action stream over HTTP.** There is no endpoint,
no listing, no export, and nothing in `capabilities` that grants one. The rows exist in the
consuming app's own database and are reachable only by that app's own code. A read surface —
`metadata`-classified, ability-gated — is a later deliverable and is named nowhere in this
contract as something you can call today. This sentence is here because a stream described in
detail and never said to be unreadable reads exactly like one you can query.

`GET /bfc/meta` advertises `app-action-audit-emit`, and the verb is the point: this deployment
**records** app-action events. It does not say they can be fetched.

### Storage

For each successful emission, one row in `bfc_app_action_events` and one row in
`bfc_app_action_outbox`, written in the transaction **already open on the caller's connection**. An
emission attempted outside a transaction is refused rather than opening one of its own — the
emission point never opens a transaction of its own, because one it opened would commit
independently of the caller's.

**The two rows are always atomic with each other. Whether they are atomic with the ACTION is the
calling application's to arrange**, and this is the sentence to read before relying on the stream.
All the emission point can check is that *a* transaction is open; nothing available to it can tell
whether the business write happened in that same one. An app that commits its invoice update, opens
a second transaction and only then records gets two rows that are atomic with nothing.

**What a consuming app must do to get the guarantee: perform the action and the emission inside ONE
transaction it opened itself.** Do that and a rolled-back action takes both rows with it, so nothing
is ever recorded about something that did not happen — the stream is transactional, or it is
fiction. This package's own emitter is written that way: `POST /bfc/console/enter` writes the entry
and its event in one transaction, and serves no entry it could not record.
*Pinned by* `tests/ConsoleEnterAuditTest.php` ("records no entry event when the entry transaction
rolls back" and "does not serve an entry it could not record").

**`bfc_app_action_outbox` is a dedup ledger, not an operational outbox.** The table is
named for the outbox PATTERN D17 names, and the pattern is what the write side does; the delivery
half does not exist. **No drainer ships for this stream in this release**, because no consumer
exists to deliver to — nothing drains it, nothing marks it, nothing reads it — and the
delivery-bookkeeping columns the credential outbox carries (`attempts`, `claimed_at`,
`claim_token`, `delivered_at`, `delivered_recipients`, `last_error`) are deliberately absent
rather than present and unwritten. It is also not the replayable history: the EVENT table is the
one a future consumer would be built against — it carries every emission the package makes, and the
package prunes none of them. And it is not an
ORDERED hand-off — the only ordering it carries is a nullable `created_at` at one-second
resolution, which cannot sequence two rows written in the same second.

What it does give is dedup, durably. `dedup_key` is UNIQUE, and that index is what makes **one
event per CALLER-IDENTIFIED action** a database property of what the emission point writes: a
second emission of the same logical action fails the insert and takes the transaction — the action
included — with it. `event_id` is unique too, so "one ledger row per event" is a database property
as well.

**Caller-identified is a condition, and it is the whole of the difference.** The emission point
hashes a natural key the CALLER supplies — its own name for this action: an invoice id, a mint
digest — into `dedup_key`. **An emission that supplies none is keyed to the new event's own id, so
it collides with nothing.** For such a call the package still guarantees one event row and one
ledger row, and guarantees nothing across calls. An app that wants a duplicate refused has to name
the action.

**The emission point stores a sha256 digest in `dedup_key`, never a caller's string.** It is a
hash over a
length-delimited encoding of the action's vocabulary, the action's name and the caller's own
natural key. Two reasons, and both matter to a consumer reading this schema later: a caller's
string written verbatim into a wide column would be an **app-content channel** into a stream
whose entire premise is that no app content enters it, and an app could pass a request value
straight in; and namespacing by vocabulary and action removes the global collision domain in
which two unrelated apps choosing the same natural key would silently suppress each other's
events.

The model additionally requires lowercase-hex digest SHAPE on the writes that fire `creating`. **The
column itself enforces only 64 characters and uniqueness**, so a direct write can store sixty-four
`z`s — and no check anywhere can tell a real digest from any other 64 hex characters, because the
natural key it would need to recompute one is deliberately not stored.

**And the ledger is append-only exactly as strongly as the event it dedupes** — model guards, the
enumerated bulk-operation refusals, and the same database triggers. That is not symmetry for its
own sake: a unique index only rejects a duplicate while the row it collides with still EXISTS, so
a deletable ledger row would let the duplicate this stream promises to refuse be re-admitted by
deleting the evidence of the first one.

**Storage is unbounded.** One event row and one ledger row per emission, and **nothing in this
package ever prunes either** — see [Retention](#retention) — and the cost is stated here rather
than discovered later. An app deleting its own rows is outside what the package can see, so
"complete" is not a property this contract claims of either table.

The event columns, all of them:

| column | shape |
|---|---|
| `id` | uuid; `HasUuids` generates it and the model does not make it fillable, so no `create()` through the model can supply one |
| `action` | the backing value of a case from the app's own compile-time action enum, a bounded identifier |
| `action_vocabulary` | the enum class that case came from, so two apps' identical slugs stay distinguishable |
| `reason` | one member of the closed vocabulary below |
| `actor_type` | `local_user`, `api_token` or `delegated_actor` |
| `actor_ref` | the principal's identifier; for a delegated actor the TYPE-QUALIFIED `bfc-console:{id}` form |
| `on_behalf_of` | the agency a delegated operator acts for (D4), or null; never present for the other two actor types |
| `occurred_at`, `created_at` | timestamps |

**No column is designated for arbitrary app content.** The schema carries no `note` and nothing of
that kind, and THAT absence is structural. It is not the same as prose being impossible: the
emission point writes bounded enums and identifiers throughout, except the delegated agency display
string — `on_behalf_of`, which D4 requires and which intentionally IS display text — while the
VARCHAR columns above can physically hold prose through the direct writes described below.

**WHAT THESE COLUMNS CONTAIN IS A GUARANTEE ABOUT WHAT THE PACKAGE WRITES, NOT ABOUT THE TABLE.**
Read the table above as a description of the rows the package's emission point produces, because
that is what it is. `AppActionEvent` is a public Eloquent model in the consuming app's own
database: `insert()`, `saveQuietly()`, `withoutEvents()`, a raw `DB::table(...)` write and any
Eloquent builder spelling that forwards through `__call()` all reach these tables without firing
a model event. **An app holding the model can write its own database directly, and the package
neither prevents nor detects that.** Three revisions of this section claimed otherwise, each by
enumerating one more spelling the previous one had missed; an enumeration of a framework's surface
does not terminate, so the claim is narrowed instead of the enumeration extended.

The package does keep two tripwires, and they are worth having because they catch the ordinary
mistake — a consuming app reaching for `create()` because the emission point was not obvious. The
model refuses, on `creating`, an action that is not a bounded-identifier case of a real declared
vocabulary, a `delegated_actor` named by a bare id, an `on_behalf_of` on any other actor type, and
a write with no transaction open; the models' shared Eloquent builder refuses an enumerated set of
bulk mutation spellings. **Neither is a boundary and no guarantee here depends on either being
complete.** A write that satisfies both still gets **no ledger row** — one cannot be written from
`creating`, because the event id it would reference is not inserted yet — so one event per
caller-identified action is likewise a property of the emission point and of nothing else.

**And `on_behalf_of` is caller-supplied on every path, this package's included.** On the package's
own two paths it originates as an issuer-minted claim, bounded to 120 characters and rejected for
control characters by the assertion verifier: `POST /bfc/console/enter` passes the claims of the
session its redemption has just begun, and every other emission passes the request's one resolved
acting principal. Nothing downstream of those re-checks it, and a consuming app calling the actor
factory itself supplies whatever it likes. What IS enforced: the emission point can carry an agency
only through a delegated actor, and the model's `creating` hook refuses the other combinations on
the writes that fire it. **The table constrains neither column against the other** — a raw insert
can store an agency beside a `local_user`. **Escape it at every sink.**

### The actor vocabulary

The three principals D17 names, and it is a **separate** vocabulary from the credential stream's
`actor_type`. The two sets are disjoint on purpose: the credential stream has no delegated actor
and never will, and an app action is never performed by a CLI operator or a credential holder. A
shared enum would hand a reader of either stream members that stream cannot produce.

- `local_user` — the host application's own authenticated human, named by the app's own primary key.
- `api_token` — a credential acting on its own behalf, named by its opaque credential id.
- `delegated_actor` — a delegated human admitted through the Console door, named by the
  type-qualified `bfc-console:{id}` form and never the bare integer. `bfc_delegated_actors` is an
  ordinary auto-increment table in the same id space `users` occupies, so a bare `7` would read as
  user 7. This is the only actor type that carries `on_behalf_of`.

Attribution, on emissions the package makes during a request, comes from the **one** acting
principal it resolves per request (D14) — not from asking a guard, `Auth::` or the request a
second time. On a route guarded by the app's own guard while a delegated session is also live, the
acting principal is the local user, and that is what the event names. `POST /bfc/console/enter` is
the deliberate exception and passes the admitted actor directly, because the request's acting
principal was resolved before the delegated session existed.

### The reason vocabulary

Bounded, closed, and shipped by the package: an app cannot add a member. It is **exactly the five
app-action reasons** `console_entry`, `requested`, `scheduled`, `remediation`, `offboarding`
(closed set). It is deliberately coarse — the ACTION carries the specificity, and a reason
vocabulary that grew a case whenever one did not quite fit would be free text with extra steps.

### Retention

**App-action events are never pruned by this package.** This is attribution history, the same
decision already taken for the shadow-actor row: nothing here deletes a row, there is no prune
command, no scheduled sweep and no retention setting. The storage cost is therefore unbounded and
grows with the app's activity forever.

**Append-only has three tripwires, and none of them is a boundary.** Model events on `updating`
and `deleting` cover INSTANCE operations (`$row->update()`, `$row->delete()`). Bulk operations fire
no model events at all, so they are refused by the models' shared Eloquent builder — an enumerated
set covering `update`, `delete`, `truncate`, `upsert`, the increment/decrement family and the
event-free insert spellings. Database triggers abort raw row-level UPDATE and DELETE on sqlite,
mysql/mariadb and pgsql.

**The residue, named rather than claimed away**, because each layer has a real edge. Raw
`TRUNCATE TABLE` is DDL and no row trigger sees it. A raw INSERT — `DB::table(...)` or
`Model::query()->insert(...)`, which fires no model events — skips the model layer, and the
triggers guard UPDATE and DELETE, not INSERT. `deleteQuietly()` and `withoutEvents()` mute the
model layer outright. The builder's refusal list is a fixed enumeration of method names, and a
spelling not on it forwards straight through `__call()`. A driver this package writes no triggers
for (sqlsrv) has the model and builder layers and nothing beneath them. A connection with schema
access can DROP the triggers; direct file access to a SQLite database rewrites anything. TRUNCATE
and DROP enforcement, where an operator wants it, is a **database-privilege** matter — revoke DDL
from the app's connection — not something a model guard can give. **Append-only here is a strong
convention with three tripwires under it, not a cryptographic property: an app, or a compromised
instance, can tamper with its own history, and this package will neither prevent nor detect it.**

*Pinned by* `tests/AppActionAuditTest.php` ("rejects update and delete on an app-action event at the model layer", "rejects update and delete on a ledger row at the model layer", "refuses every enumerated bulk mutation on the app-action stream, on both models", "rejects truncate on the app-action stream, on both the static and the query-builder paths", "rejects raw update and delete on the app-action table at the database layer on sqlite", "rejects raw update and delete on the ledger table at the database layer on sqlite", "finds no enumerated deletion spelling against the app-action stream anywhere in src", "keeps the two audit vocabularies disjoint, so neither stream can hand a reader the other's actor type", "leaves neither the event nor its ledger row behind when the action rolls back", "refuses a second emission of the same logical action, and takes the transaction with it", "refuses a second ledger row for one event", "stores a digest rather than the caller's natural key", "refuses a direct model write that carries runtime prose as its action", "refuses a direct model write that names a delegated actor by a bare id", "refuses a direct model write that fabricates an agency for a local user" and "leaves the credential stream's shape untouched").

*Pinned by* `tests/RecorderTransactionGuardTest.php` ("refuses to record an app action outside a database transaction").

*Pinned by* `tests/HttpContractDocTest.php` ("the documented app action reason vocabulary matches the code").

---

## Console — what has landed, and what is still RESERVED

The vendor-side Console lands in stages. This section says exactly which of its reserved names
are now real and which are still only names, so a consumer never has to guess. **Nothing in the
"Landed" list changes any documented request or response shape, so `api_version` does not
move**: what it adds is a guard, two tables, a middleware and one browser route whose success
is a redirect. This section deliberately contains no `### METHOD /path` route headings — the
mechanical route-completeness check covers live routes only, and the routes named here are
documented in their own sections above.

### Landed

- **The Console is OFF unless a deployment enables it.** `built-for-cloud.console.enabled`
  gates everything below and defaults to `false`. Installing or upgrading the package changes
  nothing for an app that has not opted in — no new guard, and no change to how the package's
  session gates behave. `GET /bfc/meta` `capabilities` gains `console-guard` **only while that
  flag is on**, because the capability describes this deployment rather than the package.
- **Guard name `bfc-console`** — with the Console enabled, the delegated-session guard EXISTS
  and is registered **by the package itself**: a consuming app adds nothing to its `auth.php`.
  It is a session guard over the delegated-actor provider, and it is a SECOND guard alongside
  the `bfc` credential driver, which is unchanged. An app that has already defined a
  `bfc-console` guard of its own keeps it; the package never overwrites one. The provider name
  `bfc-console-actors` is RESERVED: with the Console **enabled**, an app that has defined it as
  something else, without defining its own guard, fails boot loudly rather than having the
  delegated guard built on its user table. With the Console **disabled** that collision is
  ignored entirely — a deployment that never asked for the Console cannot be stopped from
  booting by it.
- **Only `redeem()` mints a delegated session through this package, and it takes the SIGNED
  ASSERTION BYTES.** `ConsoleGuard::redeem()` verifies the token itself — signature, issuer,
  audience, TTL bound and clocks — inside the same call that writes the session. No public
  method accepts an already-built assertion OBJECT, and none logs a delegated actor in on
  request; `Assertion::fromVerifiedClaims()` is public and is documented as not being proof of
  provenance, so an operation taking one would have accepted a forged claim set. The guard is
  also a plain `Guard`, deliberately not a `StatefulGuard`: `attempt`, `once`, `loginUsingId`,
  `onceUsingId` and `viaRemember` do not exist on it, and its user provider answers null/false
  to every credential-shaped question for every input. "No password, no login path" is a
  property of the types, not a set of methods that refuse.
  **Two scans enforce this, and they cover the two shapes the escape has actually taken.** A
  FILE scan requires exactly one file under `src/` to be able to write a delegated session key,
  and that file's writer to be private. A PUBLIC-SURFACE scan requires `ConsoleGuard`'s public
  API to be exactly a known set, so a new public method cannot quietly call that private writer
  while every file assertion stays green. Both are driven over fixtures carrying the offence, so
  both are proven able to fail.

  **What they do not enforce**, because the alternative is an absolute nobody can hold: PHP
  cannot express "no future public method may call this private method" as a language
  guarantee. These are tripwires — they make the change impossible to introduce *silently*, not
  impossible to introduce. Uncovered specifically: a **novel write form** (the scanner
  recognises a fixed textual list of instance mutators — `->put(`, `->replace(`, `->merge(`,
  `->push(`, `->flash(`, `->now(`, `->flashInput(` — not all PHP or Laravel write forms); a key
  **assembled at runtime**; **reflection** into the private writer; anything **outside `src/`**,
  which is the session-store boundary below; and a change to `redeem()`'s **own body**, which
  the token tests cover instead.

  One residue deserves naming rather than a category, because it is the one the public-surface
  scan cannot reach: **an already-enumerated public method could be modified to call the private
  writer.** `actor()`, `setUser()` or `logout()` could be edited to call `beginSession()`, and
  both scans would stay green — the file set is unchanged, and so is the set of public method
  names. The scans enumerate which files can write and which methods exist; neither reads what
  an existing method does. Reviewing a diff that touches one of those methods is the control,
  and it is a human one.

  *Pinned by* `tests/ConsoleSessionWriterScanTest.php` ("has exactly one file in src/ that can
  write a delegated session key"; "keeps the one writer unreachable from outside the guard";
  "has exactly the public surface it is meant to have on the one class that can write";
  "collects and names a differently-named writer when the walk meets one"; "names an unremarked
  public method, and a removed one"), `tests/ConsoleRedemptionTest.php` ("exposes no way to log
  a delegated actor in without signed bytes"; "refuses a token whose claims were rewritten to
  claim the admin role") and `tests/ConsoleDelegatedActorTest.php` ("refuses every credential
  lookup unconditionally, not merely the ones that do not match"; "has no credential-shaped
  entry point on the guard at all").

  The one public seam the `Guard` contract forces is `setUser()`, which Laravel's `actingAs()`
  uses. It sets an in-memory principal for the current request and writes **nothing** to the
  session, and the guard additionally requires that the session itself names the principal —
  `SessionGuard::user()` returns whatever `setUser()` was given without consulting the session,
  so without that cross-check a caller could combine `setUser()` with hand-written claims and
  act as a delegated admin with no signature anywhere. Nothing else in the package writes
  delegated session state: the write lives inside the verifying operation, privately.

  **The residue, named rather than glossed.** Any code that can write the session store can
  write the four claim keys and the guard's own login key, and the result is indistinguishable
  from a redeemed session. That is irreducible — it is what this package's own test suite does
  to reach states a real redemption cannot produce — and it is not a credential or a login
  path, which is what §4.3 governs. The guarantee that is made and held is narrower and exact:
  **no package API assembles a delegated session without verified assertion bytes.**
  *Pinned by* `tests/ConsoleSessionWriterScanTest.php` — the enumeration above is what makes this
  a package-wide statement rather than a claim about the classes someone remembered to name.

  **A failed redemption cannot hand back a usable delegated session.** Laravel writes and
  regenerates the session before it dispatches its `Login` event, so a host application's
  listener that throws would otherwise leave a session already carrying the delegated identifier
  while the redemption reported failure; the operation compensates — the session is destroyed —
  before the failure propagates. If the compensation *itself* fails (the session store is
  unreachable), the **original** failure is still what surfaces, and the compensation failure is
  reported to the application's exception handler rather than replacing it or being dropped.

  Stated exactly, because the two halves differ:

  - **Guaranteed:** the **regenerated session id this redemption hands back** cannot rehydrate a
    delegated identity, in either double-failure case — the compensation's in-memory flush
    precedes the store I/O that fails, and that id names a record which was never written
    (nothing is persisted mid-request; the store is written once, at the end).

  - **Not guaranteed:** a record under the **prior** id may survive, **carrying whatever
    identity it already held — including a delegated one.** A redemption can begin from an
    already-delegated session (an operator re-entering the console), and with the store
    unavailable nothing destroys that record, so a concurrent request or a replay of the prior
    cookie still authenticates as whoever it already held. The failed redemption grants nothing
    new; it fails to revoke something already live. No ordering fixes this: destroying the prior
    record requires the store, and the store is what is unavailable.

  *Pinned by* `tests/ConsoleRedemptionTest.php` ("leaves no usable session when a Login listener
  throws during redemption"; "surfaces the original failure, not the compensation failure, when
  the session store is unreachable"; "leaves a later request unauthenticated when the store
  recovers before the response is saved"; "leaves a later request unauthenticated when the store
  is still down at save time"; and "leaves a PRE-EXISTING delegated record alive under its own id
  when the store fails at teardown", which asserts the residue itself).

  **Remember-me:** this guard never queues a recaller cookie. Laravel still *checks* for one
  when a session carries no identifier, so that branch is reachable; it is fail-closed because
  the delegated-actor provider's `retrieveByToken()` returns null for every input, so no
  principal is ever produced from a cookie.
- **Table name `bfc_delegated_actors`** — the delegated-actor (shadow actor) table EXISTS. It
  is **not** a `users` table: no password column, no remember-token column, no login path, and
  no credential can resolve to one — the `bfc-console:` identifier namespace is RESERVED and is
  refused before any credential's bound `user_id` reaches a user provider. A delegated
  principal's identity is **type-qualified** (`bfc-console:{id}`) so it can never collide with a
  `users` id, and the identifier suffix must be a canonical positive decimal. Actor identity is
  the **digest of a length-delimited issuer+subject encoding**, not a collated comparison of two
  text columns, so two subjects differing only in case are two humans on every database.
  Rows are never pruned — they are the referent of delegated audit attribution.
- **Per-mint claims are SESSION-bound.** The role, display name and `on_behalf_of` a request
  acts under are the ones that request's own handoff wrote into its session. The actor row
  keeps a `last_handoff_*` copy for operator listings and audit context only: a second handoff
  for the same human never changes the role of an already-live session.
- **Dual-session precedence.** ENFORCED, and enforced by the framework's own scoping rather
  than by a package-owned repoint. A delegated route carries Laravel's `auth:bfc-console`, so
  the console guard is the guard OF THAT REQUEST: `$request->user()`, `Auth::user()`,
  `Auth::id()`, `Gate` and every policy return the delegated actor, and the package's resolver
  returns the same object. On such a route, with a local `web` session simultaneously live,
  **the delegated guard wins — for the acting principal and for all UI/attribution branching —
  never a union of the two.**

  **What `auth:bfc-console` does to global state, stated exactly.** It is Laravel's own
  `Authenticate` middleware, and it calls `AuthManager::shouldUse()` → `setDefaultDriver()` →
  a write to `config('auth.defaults.guard')` — precisely what `auth:web` and `auth:api` do in
  every Laravel application. This package makes no such write itself (it never calls
  `shouldUse()` and never sets that key), but the write happens, and it is process-global for
  the life of the config repository. It does not leak between requests on either runtime this
  package supports, though they get there differently:

  - **PHP-FPM** — *not* because each request gets a fresh process; an FPM worker ordinarily
    serves many requests, which is what `pm.max_requests` bounds. It is PHP's shared-nothing
    execution model: at request shutdown all userland state is destroyed — container and config
    repository included — and the next request re-reads `auth.defaults.guard` from the
    application's config. The OS process persists; nothing written into PHP memory does.
  - **Octane**, which *does* reuse userland state and therefore needs an explicit mechanism: it
    installs a per-request clone of the config repository via
    `Laravel\Octane\Listeners\CreateConfigurationSandbox`, which runs on every
    `RequestReceived`.

  Note explicitly that Octane's `FlushAuthenticationState` is **not** what closes this — it
  forgets the resolved guards and the `auth.driver` instance and never touches config — so do
  not re-derive the guarantee from that listener.

  **The runtime assumption:** any runtime that reuses a container across requests **without
  sandboxing the config repository** leaves the default guard pointed at `bfc-console` for
  every later request in that process, and a request touching no Console route would resolve
  its principal through the delegated guard. That is the condition under which this becomes a
  real privilege leak; it is a property of the host runtime and cannot be prevented from inside
  a guard.
  *Pinned by* `tests/ConsoleGuardScopingTest.php`, which models the property rather than invoking
  Octane (no dependency here): "would resolve a non-console route through the delegated guard on a
  runtime that never sandboxes config" — asserting the resolved PRINCIPAL, since a refusal reports
  the same guard name — plus "does not leak into the next request when the config repository is
  cloned per request, the way Octane clones it" and "leaves auth.defaults.guard pointed at the
  console guard, and forgetting guards does not put it back".

  A **REFUSED** delegated session (capped, unreadable claims, contained actor) is TERMINAL on
  every route: the request resolves no principal at all and no package surface falls back to
  the local user, whose session the guard has invalidated anyway.
  The package's own gates read one resolved value, and the two directions are deliberately
  asymmetric — **admission is exact, refusal may be broad**:
  - `bfc.admin` ADMITS a delegated operator whose own handoff carried `role=admin`, but only
    on a route the console guard actually governs, so the principal it authorizes is the
    principal everything behind it acts as. A delegated `member` does not pass; a delegated
    session on a route the console guard does NOT govern is refused rather than resolved to
    the local user's `is_admin`; a local user still passes on that attribute as before.
  - `bfc.auth` and the personal-credentials surface (`/bfc/me/credentials`) REFUSE a delegated
    session with a `403`, whichever guard the route names, rather than falling through to the
    local session user. A delegated actor has no personal credentials in this app. On a
    REFUSED console session they answer `401` and `403` respectively, and never resolve the
    local user.
  - The token gates (`bfc.token.admin`, `bfc.credential.admin`, `bfc.ability`) are unchanged:
    they never consult a session principal.
  **This is an AMENDMENT to the v3.1 matrix invariant SEC-V3-10, not an additive slot-in**, and it
  is recorded as one deliberately rather than left to read as an accident. SEC-V3-10 shipped as a
  token-vs-session rule over a SINGLE `built-for-cloud.credentials.session_guard` name; the Console
  makes the matrix session-vs-session as well, so a reader of the old statement would conclude the
  matrix has one session guard in it when after this release it has two. The full amendment, cell by
  cell and including the cells that did NOT change, is in `release-notes/unified-store-guard.md`.
  *Pinned by* `tests/CredentialPrecedenceTest.php`, which runs the whole precedence matrix with both
  session guards configured ("still rejects mismatched simultaneous principals with the delegated
  guard configured", "does not turn a delegated session into a false mismatch on a token route" and
  "still rejects a mismatched local principal when the session guard is the local one" — the last
  being the shipped configuration, so the delegated exclusion cannot be read as having weakened the
  rule it sits beside).

- **Delegated session clocks.** A delegated session is bounded by Laravel's own sliding idle
  window AND by an absolute assertion-age cap of 120 minutes, measured from the assertion's
  issued-at. The cap is enforced **inside the guard**, so it holds on every route including
  ones that mount no Console middleware: a capped, orphaned or unreadable delegated session is
  invalidated server-side the first time anything reads the guard. A route carrying the
  package's `bfc.console` middleware answers such a request with a `401` carrying the header
  `BFC-Console-Reentry: 1` and a body of
  `{"version": 1, "error": "console_reentry_required", "reason": "<enum>", "reentry_url":
  "<absolute>", "return_to": "<relative path>"}`, where `reason` is one of `assertion_age_cap`,
  `session_invalidated`, `not_authenticated`, and `reentry_url` is **omitted entirely** when the
  app has configured none. `return_to` is validated as a same-origin relative path in every
  percent-decoded form. This is an ERROR body; the metadata/content classification does not
  apply to it.
- **The chrome is served, and it is ONE layout.** The `bfc::` view namespace, the single
  `bfc::layout`, and [`GET /bfc/console/chrome.js`](#get-bfcconsolechromejs) — the XHR re-entry
  interceptor — are all live on a deployment reporting `console-chrome-assets`. The layout
  branches INTERNALLY on the resolved acting principal: a local login renders zero chrome, a
  delegated session renders the full attribution, and there is no second layout to select. The
  capability names the ASSETS and not the pages: whether an application's own templates extend
  the layout is that application's decision and nothing here can report it. Full contract,
  including the render-time bounds on display claims, the escaping, the interceptor's honest
  degradation when no `reentry_url` is configured, and the CSP guidance, is in
  [its own section](#the-console-chrome).
- **The door is open.** [`POST /bfc/console/enter`](#post-bfcconsoleenter) is a live route on a
  deployment reporting `console-enter`, and it is the only way a delegated session begins over
  HTTP. It calls `ConsoleGuard::redeem()` — the one operation that mints one — rather than
  writing session state of its own, so the package-wide writer scan still names exactly one
  file. Its full contract, including the single-use burn, the signed handoff state, the uniform
  refusal and the forced-login residue the signed state does **not** close, is in
  [that route's own section](#post-bfcconsoleenter).

### Still RESERVED (not implemented)

Nothing in the `/bfc/console/*` namespace is a reserved name any more: `re-key`, `vitals`,
`enter` and `chrome.js` are all live routes, documented above. The app-action audit stream's
SCHEMA and EMISSION have landed ([above](#the-app-action-audit-stream)); its **read transport
has not**, and is not a name this contract offers. The chrome and its single layout have landed
([above](#the-console-chrome)). Everything else Console-related — the switcher and its roster,
the fleet dashboard — remains held behind the Console PRD's decision D6, and **no roster claim
exists in the assertion vocabulary**, so there is nothing of that kind for the chrome to render
yet.
