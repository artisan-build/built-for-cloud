# The Built for Cloud HTTP contract

This is the versioned public contract of every HTTP surface the `built-for-cloud` package mounts,
written for a consumer with **no PHP**: plain HTTP + JSON. Scalpels consumes exactly this contract;
so can a customer's own control plane, an internal app in any language, or a shell script. Any PHP
client the ecosystem ships is a convenience — **this document, not any client library, is the
contract** (GATE-3).

Every route below is verified mechanically: a package test enumerates the registered routes and
asserts each appears here, and that every route this document names is real. A route heading has
the form `### METHOD /path`.

There is no mounting switch: every Built for Cloud app serves this **entire HTTP surface**, loaded
from the package's `routes/web.php` (the browser pages) and `routes/api.php` (the bearer, claim and
operator routes). No route is individually configurable and no route moves behind a configurable
prefix.

## Platform requirements

Named here because this contract is written for a consumer with no PHP, and a platform requirement
you cannot see is one you cannot plan for.

**A host serving this contract needs 64-bit PHP `^8.3` with the `gmp` extension (`ext-gmp`).** The
constraint is the package's own and is stated as it is declared: `^8.3` admits 8.3 and 8.4 and
**excludes PHP 9**, which this package does not claim to support. The other two halves come from the
assertion cryptography, and neither is optional:

- **`ext-gmp`** arrives with `paragonie/paseto`, which is what verifies the PASETO `v4.public`
  assertion delegated MCP authentication is gated on, and which declares
  the extension itself.
- **64-bit** is declared by `paragonie/sodium_compat` as `php-64bit`. A 32-bit PHP build cannot
  install this package even with `gmp` present.

Both requirements are **unconditional** — they are dependencies of the package, not of any one
surface — so a deployment that never serves a delegated assertion carries them too.

These are the requirements. **How Composer enforces them — at install, at runtime, or in a `vendor/`
directory built on one host and copied to another — is Composer's to document, not this contract's:**
see [Composer's `platform-check` configuration](https://getcomposer.org/doc/06-config.md#platform-check).
An earlier revision of this section paraphrased that behaviour and was wrong about it twice, which is
why the paraphrase is gone rather than corrected.

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
  below) — the package release, for feature detection at finer grain than the major, alongside the
  `capabilities` array. Every place this document spells that release, in an example or in running
  text, has to spell the same one; the previous wording here claimed the example was the only such
  place, and the changelog below spelled it three more times.

**What is checked is the form, not what a reader sees.** The check is a text scan over this file:
it reads a release-window declaration spelled exactly that way and outside an HTML comment, and it takes no
position on how any renderer displays it. A declaration written some other way — entity-encoded,
inside a fenced block, inside raw HTML — is not one it recognises, in either direction. **If you
are relying on knowing whether a release window is open, read this section rather than trusting
that the check would have caught its absence.** What is compared against it is this document's own
`bfc_version`, spelled bare or under that exact key; a version given under any other key is not
compared to anything, and neither is a version spelled in a release note.
*Pinned by* `tests/HttpContractDocTest.php` ("the documented release and the constant differ only
where the document declares it", "names a version pair that drifted one that is undeclared and a
declaration left behind", "refuses a release window inside a comment a duplicate one and one that
goes backwards", "refuses a decoy release window and one outside the versioning section" and "finds
the versioning section past a commented a repeated and a fenced heading").

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

### Opt-in contract-major admission

Consumers may attach the middleware alias `bfc.contract-major` to their own product or provider
routes whose wire follows this contract. Existing package routes are not subject to this gate. An
admitted request carries exactly one `BFC-Contract-Version` header whose value is the canonical
unsigned decimal `2`; the header selects no guard, credential, purpose, audience, installation,
role, ability, retry policy, or authority. `X-BfC-Client-Id` remains advisory metadata.

Admission refusals are JSON with `Cache-Control: no-store`, no `Retry-After`, no reflected input,
and the following closed `error` vocabulary. Clients branch on `error`.

| Condition | Status | Exact JSON |
| --- | ---: | --- |
| Header absent | 400 | `{"error":"missing_contract_major","supported_contract_major":2}` |
| Duplicate or non-canonical header | 400 | `{"error":"malformed_contract_major","supported_contract_major":2}` |
| Canonical integer other than `2` | 426 | `{"error":"unsupported_contract_major","supported_contract_major":2}` |

### Changelog

**v0.17.0.** Console entry is retired: `POST /bfc/console/enter` and
`GET /bfc/console/chrome.js` are removed, along with the Console session guard and the
`BUILT_FOR_CLOUD_CONSOLE_ENABLED` / `BUILT_FOR_CLOUD_CONSOLE_REENTRY_URL` configuration (and the
`built-for-cloud.console.return_path_allowlist` config key, which existed only to narrow the
door's landing paths), together with the `console-guard`, `console-enter` and
`console-chrome-assets` capabilities, which reported exactly that machinery. Delegated MCP
authentication (`mcp-delegated`) is unchanged and keeps the delegated actor record
(`bfc_delegated_actors`), `BUILT_FOR_CLOUD_CONSOLE_ISSUER` / `_AUDIENCE`, the assertion verifier
and the console keyring. `GET /bfc/console/vitals` is unchanged. No migration runs; existing
`bfc_delegated_actors` rows are untouched.

**P1 managed enrolment (shipped).** New owner-credential-authenticated
routes provision a pristine installation into managed mode, rotate its stored managed-auth client
secret, and disconnect it through the existing exit-transition machinery. `GET /bfc/meta` gains the
`managed-enrolment` capability. The client secret is delivered only in requests, encrypted at rest,
and never returned. `api_version` remains 2 because these are new routes and one new open-set
capability member.

**api_version 2** (bfc **0.17.0**, this release). All changes since version 1, in one inventory.
Additive unless marked otherwise.

**Everything the Console adds through this release is additive or a documented removal, so `api_version` stays 2. What carries the
signal is `bfc_version` 0.17.0 plus the `capabilities` entries** — `console-keys`,
`console-key-retire`, `console-vitals`,
`app-action-audit-emit`, `mcp-serve` and `mcp-delegated`. (The `console-guard`, `console-enter`
and `console-chrome-assets` entries this list once named were RETIRED in v0.17.0 with the
machinery they advertised — see [Retired in v0.17.0](#retired-in-v0170).)

**What "additive" covers here, stated as what actually shipped rather than as one paradigm case**,
because a reader applying rule 1 to their own change needs the real list:

- **New routes** — the paradigm additive case rule 1 names, and most of the Console is this.
- **New OPTIONAL request fields on existing routes** — `console_key` on the ownership claim and the
  onboarding exchange, `console_key_authority` on the onboarding issue. A request that omits them
  behaves exactly as it did before.
- **Conditionally additive response fields**, and this list is derived from the diff rather than
  from memory: the ownership claim and the onboarding exchange carry `console_key` only when the
  request supplied one, and `POST /bfc/onboarding/issue` carries `console_key_authority: true` only
  when authority was granted. In every case an envelope that asked for nothing is unchanged,
  response keys included, so a consumer pinned to the pre-Console shape sees identical keys.
- **Machinery that is not a route at all** — the `bfc-console` guard, the delegated-actor table and
  the app-action emission point serve no new wire shape and change none.
- **Owner transition recovery** — an Owner may abandon a guided transition before local commit,
  releasing the installation's active transition slot so preparation can restart from fresh authority data.

- **Request-scoped delegated MCP authentication ships.** `AuthenticateMcp` accepts either a
  unified bearer credential or a purpose-bound Console assertion, burns assertions before dispatch,
  and publishes their delegated actor for that request without writing a session. `GET /bfc/meta`
  gains conditional `mcp-serve` / `mcp-delegated` capabilities and the additive `endpoints` object.
  MCP tools gain the `metadata | content` classification attribute and a reusable delegated-tool
  conformance assertion. The assertion verifier gains the optional `purpose` claim; the MCP door
  requires `mcp` now, while Console entry temporarily treats absence as `console-entry`. That
  legacy tolerance is scheduled for removal in the next minor.

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

- New unified-store verb routes: `GET /bfc/credentials`, `POST /bfc/credentials`,
  `DELETE /bfc/credentials/{id}`.
- Unified credentials now carry a required protocol `purpose`, exposed in every summary row and
  copied unchanged by rotation. Generic minting enforces the kind/subject/purpose matrix documented
  below. The upgrade migration does not guess a purpose for existing rows: it retires every one as
  a visible tombstone with `purpose: null`, and operators must re-mint replacement credentials.
- Persisted abilities are now closed over the documented `OperatorAbility` vocabulary. Claim scopes
  such as `consume` and `onboard` are wire vocabulary, not stored abilities, and unknown ability
  input is rejected before a credential, audit event, or delivery is created.
- The package now owns one reserved installation signing root, provisioned only by the local
  `bfc:signing-root:provision --local` command and consumed in-process through `SigningRootMac`.
  It has no HTTP creation, listing, or mutation surface; its direct-active rotation is
  make-before-break and exports no root material.
- New `capabilities` entry `app-action-audit-emit`, and the app-action audit stream's schema and
  emission (Console PRD D17). Additive: no request or response shape changes, and the stream has
  no read transport — see [the app-action audit stream](#the-app-action-audit-stream).
- New `capabilities` entry `console-chrome-assets` and one new route,
  `GET /bfc/console/chrome.js` — the console chrome's re-entry
  interceptor, plus the `bfc::` view namespace carrying the single package layout (Console PRD
  D11/D7). Additive: no existing request or response shape changes, and the capability names
  what this deployment SERVES, never that any page of the application renders it. (The chrome
  and its route were retired in v0.17.0 — see
  [Retired in v0.17.0](#retired-in-v0170).)
- New rotation route (PRD 1.7): `POST /bfc/credentials/{id}/rotate` — rotate-by-id on the unified
  store. Summary rows gained the nullable `rotated_at` field (rotation provenance). A row
  already superseded by rotation never mints again (the lineage never forks): with a live
  successor, re-invoking the rotate route performs the retirement-only **cutover completion**
  (a `200` with `completed_cutover: true` and no secret), except while an hmac successor awaits
  activation or a bound asymmetric successor awaits public-key enrollment; without one it refuses. The
  onboarding exchange sweep spares rows in rotation grace when they have the shape rotation
  actually leaves (the stamp plus a grace-bounded expiry), and `rotated_at` is not
  mass-assignable, so the exemption cannot be forged.
- New personal-credentials routes (PRD 1.17): `GET /bfc/me/credentials`,
  `POST /bfc/me/credentials` and `DELETE /bfc/me/credentials/{id}` — the session-authenticated
  self-service front to the same unified-store verbs, whose subject is derived server-side from
  the authenticated session and never from request input (SEC-V3-07), whose ABILITIES come from
  an application-declared self-service policy and never from the requesting user, and whose
  mutations are CSRF-protected browser routes. Additive: no existing route, request or response
  shape changes.
- New installation-credentials routes: `GET /bfc/installation/credentials`,
  `POST /bfc/installation/credentials`, `POST /bfc/installation/credentials/{id}/rotate` and
  `DELETE /bfc/installation/credentials/{id}` — the session-authenticated browser surface for
  installation-owned credentials. Additive: no existing route, request or response shape changes.
- `GET /bfc/meta` `capabilities` gained `credentials`, and — with the console key surfaces
  below — `console-keys`.
- `POST /bfc/onboarding/issue` requires `ttl_seconds` (bounds below) and accepts nullable
  `email`; the claim surfaces speak the claim-contract error enum documented here.
- The standalone human lifecycle replaces operator/open-code invitation transport with addressed
  Owner/Admin issuance, package mail, and package-owned acceptance under the local authority gate.

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

- **Bound asymmetric signing enrollment ships additively.** A server-owned
  `BoundCredentialScope` can mint an installation-owned pending asymmetric signing credential,
  and the new public `POST /bfc/asymmetric-enrollments/{application}` route accepts its code plus
  one canonicalizable RSA public key. The client retains the private key; the package stores and
  returns no private material. Exact-scope, model-free verification-key lookup and bound-only
  enrollment-time rotation cutover ship with it. Generic unbound asymmetric enrollment and its UI
  choices are unchanged.

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
  both keys verify during the overlap. Retirement is the separate, later operation that finishes
  it, and it now has an operator path of its own: new route
  `POST /bfc/console/keys/{key_id}/retire` under the SAME `console:key:write` ability and the
  same operator write limits, with `bfc:console:retire-key --local` as its CLI transport, and a
  new `capabilities` entry `console-key-retire`. Retiring the LAST key that still verifies ends
  delegated entry and is refused (`409`) unless the request confirms it. The lifecycle stream's
  `delivered` / `activated` / `revoked` / `denied_action` events now also carry console-key
  events (`credential_id` null, the key id in the note). No
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
  [Console — what has landed, what has been RETIRED](#console--what-has-landed-what-has-been-retired-and-what-is-still-reserved).

- **The Console's enter endpoint ships (Console PRD D12/D13).** All additive, and `api_version`
  stays 2: no documented request or response shape changes. New route
  `POST /bfc/console/enter`, classified `content`, mounted only on a
  deployment that has the Console enabled AND whose `bfc-console` guard is this
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

- **Public routes** are unauthenticated but rate-limited per IP: `bfc-public` (60/min) and
  `bfc-claim` (10/min), returning `429` beyond the limit.
- **Operator-route refusals are NOT uniform, deliberately.** Missing, unknown, expired and
  revoked bearers all answer `401` with one body; a bearer that authenticates but lacks the
  route's ability answers `403`. The split is safe because a caller reaching the `403` has
  already proved it holds a live credential, so nothing about credential existence leaks — and
  it is useful, because "wrong ability" and "bad token" need different fixes. The exceptions are
  the two console key-custody verbs — [`POST /bfc/console/re-key`](#post-bfcconsolere-key) and
  [`POST /bfc/console/keys/{key_id}/retire`](#post-bfcconsolekeyskey_idretire) — where what the
  split would reveal is worth more to an attacker than the diagnostic is to an operator; each
  answers one uniform `403` to every pre-authorization failure alike.
- **Operator routes** (the `/bfc/credentials`, `/bfc/subjects`, ownership release,
  onboarding issue, and client-observation verbs) accept a unified-store `operator` credential,
  authorized **per verb family**
  (GATE-3.7 least privilege). The ability vocabulary: `credential:read` (the listing — an
  audited sensitive read), `credential:mint` (credential minting), `credential:rotate`
  (rotate + the hmac activate cutover, same family), `credential:revoke`, `subject:offboard`,
  `ownership:release` (release or cancel an ownership transfer, deliberately separate from
  credential and subject lifecycle authority),
  `audit:read` (vocabulary now; the first audit-read surface will enforce it), and
  `console:key:write` (write this deployment's console key ring — file a countersigning key with
  [`POST /bfc/console/re-key`](#post-bfcconsolere-key), retire one with
  [`POST /bfc/console/keys/{key_id}/retire`](#post-bfcconsolekeyskey_idretire); its own name, and deliberately not the
  `credential:rotate` family, so no already-issued credential gained the power to install a
  delegated-admin trust root on upgrade — **note the declared-mint-ceiling caveat below if your
  app implements one**). The MCP
  pair `mcp:read` / `mcp:admin` is the per-tool vocabulary consuming apps wire in front of
  each MCP tool (read vs destructive administration — distinct grants, checked exact-match;
  no operator ability implies either). `metadata:read` is the Console dashboard's read ability
  ([`GET /bfc/console/vitals`](#get-bfcconsolevitals)) and the ONE name in this vocabulary the
  break-glass below cannot reach. That route's own gate also requires an operator subject and an abilities list EXACTLY equal to
  `{metadata:read}`. There is **no wildcard**; a credential with no abilities can do nothing. The
  one admin-equivalent name is **`credential:admin`** — the explicit break-glass, expanding
  to exactly the eight operator abilities `credential:read`, `credential:mint`,
  `credential:rotate`, `credential:revoke`, `subject:offboard`, `ownership:release`, `audit:read` and
  `console:key:write` (never the MCP pair); it is what
  `bfc:install:operator-credential` mints, and holding that literal name in the abilities
  list is how a break-glass credential is marked. The operator gate enforces that exact
  `OperatorAbility::adminEquivalent()` set; an enum ability outside it is not inherited. The MCP
  pair and `metadata:read` are outside the expansion.

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
  - Either console key-custody verb — the re-key or the retirement — presented with an operator
    credential the app can still mint **that does not carry `credential:admin`**, answers the
    uniform **403** described above, whose body is constant and says nothing about why. That
    opacity is deliberate on those routes and it is not going to distinguish this case from a
    stolen bearer, so an operator who has not read this paragraph will read it as "my credential
    is wrong" rather than "my declaration is short a name".

    The `credential:admin` exception is real and is a third way out: a ceiling written before
    this release may well permit the break-glass name, and an operator credential carrying it
    is both mintable under that ceiling and sufficient for this route because
    `console:key:write` is explicitly in the bounded admin-equivalent set. Check the
    declaration's `grantableAbilities()` before concluding the route is unreachable.

  **Two paths work meanwhile, neither of which needs a deploy:**

  1. the unified owner credential from [`POST /bfc/ownership/claim`](#post-bfcownershipclaim),
     or any other operator credential holding `credential:admin`; or
  2. the CLI transports, `bfc:console:re-key --local` and `bfc:console:retire-key --local`,
     whose authority is host access and which consult no ability at all.

  **The fix** is to add `console:key:write` to the declaration's `grantableAbilities()` for the
  operator subject and redeploy. Do that deliberately: it is the grant of a
  delegated-admin trust root, which is exactly what a declared ceiling exists to make someone
  decide rather than inherit.
- **Operator rate limits:** write and expensive operator verbs (mint, rotate, activate,
  revoke, offboard) are limited per operator credential + IP (`bfc-operator-write`,
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
| `POST /bfc/asymmetric-enrollments/{application}` | `metadata` | a bounded credential id and the fixed `RS256` algorithm; no key or code is returned |
| `POST /bfc/device-authorizations` | `content` | single reveal of device and user codes plus the browser session cookie |
| `GET /bfc/device` | `content` | package HTML containing declared profile identity and the test/client-created user code |
| `POST /bfc/device` | `content` | package HTML reporting the browser-bound decision outcome |
| `POST /bfc/device/token` | `content` | single reveal of the exact-bound bearer credential |
| `GET /bfc/loopback/authorize` | `content` | package HTML containing declared profile identity and exact callback authority |
| `POST /bfc/loopback/authorize` | `content` | redirect carrying the one-time authorization code and original state |
| `POST /bfc/loopback/token` | `content` | single reveal of the exact-bound bearer credential |
| `POST /bfc/hmac-cutovers/activate` | `content` | exact scope references plus ids, timestamps and emergency flag; no key material |
| `POST /bfc/hmac-cutovers/status` | `content` | exact scope references plus ids, timestamps and emergency flag; no key material |
| `POST /bfc/onboarding/verify` | `content` | carries the free-text credential name |
| `POST /bfc/managed/enrolment` | `metadata` | bounded mode, generation counters, request id and server timestamp; the request secret is never returned |
| `POST /bfc/managed/enrolment/client-secret` | `metadata` | bounded generation counters and server timestamp; the replacement secret is never returned |
| `POST /bfc/managed/enrolment/disconnect` | `metadata` | bounded mode, resulting generation, request id and server timestamp |
| `GET /bfc/managed/login` | `content` | redirect carrying an opaque one-time browser state, plus the initiating session cookie |
| `GET /bfc/managed/callback` | `content` | redirect plus a newly established authenticated session cookie |
| `GET /bfc/assets/{path}` | `content` | static package-shipped stylesheet, font and image bytes rather than a bounded-scalar JSON shape, so conservatively not offered as vendor-safe metadata |
| `GET /bfc/ui` | `content` | package-owned HTML containing configured manifest identity and local account navigation |
| `GET /bfc/login` | `content` | package-owned HTML login form |
| `POST /bfc/login` | `content` | redirect plus a newly established session cookie |
| `POST /bfc/logout` | `metadata` | redirect after session invalidation |
| `POST /bfc/ui/logout` | `metadata` | mode-neutral redirect after local session invalidation |
| `GET /bfc/forgot-password` | `content` | package-owned HTML recovery form |
| `POST /bfc/forgot-password` | `metadata` | redirect with a fixed non-enumerating status |
| `GET /bfc/reset-password/{token}` | `content` | stateless encrypted-cookie handoff carrying the one-time request token |
| `GET /bfc/reset-password` | `content` | package-owned HTML reset form containing the handed-off request token |
| `POST /bfc/reset-password` | `metadata` | redirect after a successful reset |
| `GET /bfc/invitations/{token}` | `content` | stateless encrypted-cookie handoff carrying the one-time invitation token |
| `GET /bfc/invitations/accept` | `content` | package-owned HTML acceptance form containing the handed-off invitation token |
| `POST /bfc/invitations/accept` | `content` | redirect plus a newly established session cookie |
| `GET /bfc/members` | `content` | package-owned HTML containing user and invitation data |
| `POST /bfc/members/invitations` | `metadata` | redirect after package notification dispatch |
| `PUT /bfc/members/{user}/role` | `metadata` | redirect after role update |
| `DELETE /bfc/members/{user}` | `metadata` | redirect after account containment |
| `GET /bfc/transitions/{direction}/prepare` | `content` | package-owned HTML describing a complete adoption or exit proposal |
| `POST /bfc/transitions/{direction}/prepare` | `metadata` | redirect after preparing and persisting a default proposal |
| `GET /bfc/transitions/proposals/{transition}` | `content` | package-owned HTML containing authority-roster and local-identity data |
| `PUT /bfc/transitions/proposals/{transition}` | `metadata` | redirect after replacing the persisted proposal mapping |
| `POST /bfc/transitions/proposals/{transition}/abandon` | `metadata` | redirect after abandoning a pre-commit transition and releasing its active slot |
| `POST /bfc/transitions/proposals/{transition}/complete` | `metadata` | redirect after resuming the transition through commit and acknowledgment |
| `GET /bfc/me/sessions` | `content` | package-owned HTML containing caller-owned session metadata |
| `DELETE /bfc/me/sessions/others` | `metadata` | redirect after caller-owned session deletion |
| `DELETE /bfc/me/sessions/{session}` | `metadata` | redirect after one caller-owned session deletion |
| `GET /bfc/client-observations` | `content` | client-claimed free-text identities |
| `GET /bfc/credentials` | `content` | summary rows carry free-text names and subject refs |
| `POST /bfc/credentials` | `content` | the `delivery` single reveal, plus free-text name/subject fields |
| `DELETE /bfc/credentials/{id}` | `metadata` | empty `204` body |
| `POST /bfc/credentials/{id}/rotate` | `content` | the `delivery` single reveal, plus summary rows |
| `POST /bfc/credentials/{id}/activate` | `content` | no secret ever — but the summary row carries free-text names and subject refs |
| `GET /bfc/me/credentials` | `content` | the caller's own summary rows carry free-text names and subject refs, plus the declaration's field lists |
| `POST /bfc/me/credentials` | `content` | the `delivery` single reveal, plus free-text name/subject fields |
| `DELETE /bfc/me/credentials/{id}` | `metadata` | empty `204` body |
| `GET /bfc/ui/credentials/personal` | `content` | package-owned HTML containing the caller's own credential summaries and declared fields |
| `POST /bfc/ui/credentials/personal` | `content` | package-owned HTML containing the `delivery` single reveal and free-text credential fields |
| `POST /bfc/ui/credentials/personal/{id}/rotate` | `content` | package-owned HTML containing the `delivery` single reveal and credential summaries |
| `DELETE /bfc/ui/credentials/personal/{id}` | `content` | redirect after caller-owned credential revocation |
| `GET /bfc/installation/credentials` | `content` | installation-owned summary rows carry free-text names and subject refs |
| `POST /bfc/installation/credentials` | `content` | the `delivery` single reveal, plus free-text name/subject fields |
| `POST /bfc/installation/credentials/{id}/rotate` | `content` | the `delivery` single reveal, plus a summary row carrying free-text names and subject refs |
| `DELETE /bfc/installation/credentials/{id}` | `metadata` | empty `204` body |
| `GET /bfc/ui/credentials/installation` | `content` | package-owned HTML containing installation-owned credential summaries and declared fields |
| `POST /bfc/ui/credentials/installation` | `content` | package-owned HTML containing the `delivery` single reveal and free-text credential fields |
| `POST /bfc/ui/credentials/installation/{id}/rotate` | `content` | package-owned HTML containing the `delivery` single reveal and credential summaries |
| `DELETE /bfc/ui/credentials/installation/{id}` | `content` | redirect after installation-owned credential revocation |
| `POST /bfc/console/re-key` | `metadata` | key ids from a bounded charset, a fixed status enum and a timestamp — no free text, and never any key material |
| `POST /bfc/console/keys/{key_id}/retire` | `metadata` | a key id from a bounded charset, a fixed status enum, a boolean and a timestamp — no free text, and never any key material |
| `GET /bfc/console/vitals` | `metadata` | bounded integers, a fixed health enum, a semver-validated `app_version`, a timestamp, and a headline label drawn from the app's declared vocabulary — no free text anywhere, and deliberately no `product` |
| `POST /bfc/subjects/offboard` | `metadata` | `{"offboarded": true, "fully_contained": bool}` / `{"accepted": true, "fully_contained": bool}` — bounded booleans only |

Vendor-side reads of `metadata`-classified endpoints are governed by the `metadata:read`
ability family. One route enforces it today —
[`GET /bfc/console/vitals`](#get-bfcconsolevitals) — and it is the least-privilege,
read-audited credential the Console dashboard uses. **A `metadata` classification is not by
itself an access grant:** the other rows in this table keep the gates they already had, and
`metadata:read` opens exactly the routes that name it.

**The column describes the success body and nothing else.** Error responses
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

MCP tools use the same two-value boundary through
`#[ToolClassification(Classification::Metadata)]` or
`#[ToolClassification(Classification::Content)]`. A tool using the
`AdvertisesToolClassification` trait on its `Laravel\Mcp\Server\Tool` advertises
the value in `tools/list` as `_meta.classification`; an undeclared tool serializes conservatively
as `content`, but is still non-conforming because the declaration itself is required. A product
may advertise `mcp-delegated` only when every registered tool carries one of Laravel MCP's
`#[IsReadOnly]`, `#[IsDestructive]`, or `#[IsIdempotent]` attributes and an explicit
`ToolClassification`, and its suite runs
`ContractAssertions::assertBuiltForCloudMcpDelegatedTools()` against the server. The assertion
checks registered tools eligible under that test's application state and verifies wire
propagation. It does not inspect unregistered or currently ineligible tools, response bodies,
implementations, or whether an annotation truthfully describes behavior.

---

## Metadata

### GET /bfc/meta

Public (`bfc-public` throttle). Identifies the instance.

**200**

```json
{
  "product": "Sink",
  "bfc_version": "0.17.0",
  "api_version": 2,
  "capabilities": ["tokens", "ownership", "onboarding", "webhooks", "credentials", "console-keys", "console-key-retire", "console-vitals", "app-action-audit-emit", "mcp-serve", "mcp-delegated"],
  "claimed": true,
  "endpoints": {"mcp": "/mcp"}
}
```

`capabilities` is an open set — ignore unknown entries. `claimed` says whether an owner control
plane holds this instance.

**Every entry, and what each one is a claim about.** With `api_version` fixed at 2, this array plus
`bfc_version` is what a consumer feature-detects on, so an entry the contract never explains is a
name nobody can act on. The four original entries — **`tokens`**, **`ownership`**, **`onboarding`**
and **`webhooks`** — are UNCONDITIONAL: every install of the package reports all four, whatever it
is configured to serve. They name the package's four original feature families, and they are not
predicates about this deployment. **`tokens` is a historical family name retained for wire
stability; it names the credential family now served solely by the unified store.** The entries
below are the ones that do carry a predicate, and each states it.

`console-keys` means this instance serves the countersigning-key DELIVERY surfaces below: the
optional claim-time key exchange and `POST /bfc/console/re-key`. It deliberately does **not** say
`console` — key custody is not the Console, and a control plane that read `console` as "this
deployment can be entered" would be reading a promise this capability does not make (the
delegated-entry door it might once have imagined was retired in v0.17.0). The delegated-actor
table does exist, retained for delegated MCP authentication; `console-keys` says nothing about
it, and an instance can report it while serving no delegated surface at all.

`console-key-retire` means this instance serves
[`POST /bfc/console/keys/{key_id}/retire`](#post-bfcconsolekeyskey_idretire), the operator path
that stops this deployment trusting a filed key. It is unconditional, like `console-keys`, and it
is a **separate name** rather than something `console-keys` was widened to include. Widening would
have said nothing a consumer could act on: `console-keys` is reported by every deployment serving
the delivery surfaces, releases that shipped no retire verb at all included, so a control plane
reading it cannot tell whether the verb it wants to call is there. This name can only be read one
way.

`console-vitals` means this instance serves [`GET /bfc/console/vitals`](#get-bfcconsolevitals).
It is named for the one surface it serves, not for the dashboard that reads it: the fleet
dashboard is the vendor's, and nothing in this release renders anything.

`app-action-audit-emit` means this deployment **records** app-action audit events: the
`bfc_app_action_events` table, its transactional outbox, and the emission point an app calls. The
verb is deliberate — see [the app-action audit stream](#the-app-action-audit-stream) — because
**this release provides no read transport for that stream**, and a capability named
`app-action-audit` would read as one. It is unconditional, like `console-keys`: what it names
is schema and an emission point every install carries.

`mcp-serve` means this deployment declares a rooted MCP endpoint path in
`built-for-cloud.mcp.path`; the same predicate adds `endpoints.mcp`, so the capability and the
path it promises cannot disagree. `endpoints` is an additive open object: feature-detect its
members, ignore unknown names, and never depend on key order. It is absent when no endpoint is
declared.

`mcp-delegated` is strictly stronger, and its two promises ride different predicates because the
package can observe one and only declare the other. The endpoint is declared,
`built-for-cloud.mcp.delegated` is true, and the route Laravel would actually DISPATCH for the MCP
POST at the declared path — matched by verb and domain the way the real transport is — carries
`AuthenticateMcp` in its effective pipeline, with middleware groups expanded, aliases resolved and
`withoutMiddleware` exclusions honoured. That establishes ONE direction: when the capability is
advertised, the dispatched route is guarded — a guarded GET decoy, a route on another deployment's
domain, or a guard declared and then excluded cannot earn it. What escapes the check: a
domain-qualified MCP route whose host differs from the one the metadata request arrived on reads as
unguarded, so the capability is UNDERSTATED there — withheld, never falsely granted — and a
fallback route at the path is the 404 handler, not the transport. Whether the product runs the
delegated-tool conformance assertion in its own suite is a product declaration the package cannot
observe and does not pretend to check: whether the
advertised tools are annotated and classified is the application's own decision, made by its own
test suite, and no package capability can see that. A deployment may report `mcp-serve` alone when
it accepts registry bearers but not delegated assertions. The package does not mount an MCP server.

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
  reveal of both secrets. The owner token authenticates a unified-store `operator` credential
  holding `credential:admin` with no expiry; `ownership.owner_credential_id` is the sole link to
  that row. Ownership transfer, not a clock, ends its life. A claim that
  carried `console_key`
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

*Unified operator credential with `ownership:release`, or `credential:admin` break-glass.* Begin a make-before-break ownership transfer: mints a fresh one-time ownership
claim code for the successor. The current owner token keeps working until the successor claims.

- **201** — `{"ownership_claim_code": "..."}` — the single reveal.
- **409** — `{"message": "ownership is not claimed"}`.

### POST /bfc/ownership/cancel-transfer

*Unified operator credential with `ownership:release`, or `credential:admin` break-glass.* Cancel a pending transfer (consumes the outstanding claim code).

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

*Unified operator credential with `credential:mint`, or `credential:admin` break-glass.* Mint a claim code.

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

Every newly exchanged durable lands in a unified `credentials` row. Each code records that row
through `durable_credential_id`, and make-before-break revokes the previously linked credential
before minting its replacement.

Bound asymmetric enrollment codes are not generic claim codes. Both this route and
`POST /bfc/claim` refuse a code linked to a protocol-bound asymmetric credential before burning
it or changing its pending row. Complete it only through the asymmetric enrollment route below.

A protocol-bound HMAC originator code has only the bound exchange branch; `POST /bfc/claim`
refuses it before burn. Its first successful exchange always burns the code and returns exactly
`signing_key`, `credential_id`, `app_purpose`, `subject_type`, `subject_ref`, `installation_ref`,
`application_ref`, `audience`, `algorithm`, `credential_expires_at`, `delivery_generation`,
`delivery_fingerprint`, `predecessor_credential_id`, `source_status`, `delivered_at` and
`transfer_expires_at`. The key is 64 lowercase hexadecimal characters and is the single reveal;
algorithm is fixed `hmac-sha256`, fingerprint is 16 lowercase hexadecimal characters, source
status is `pending`, ids are UUIDs, and dates are RFC 3339. Credential expiry and predecessor id
are nullable. Transfer expiry is no later than 60 seconds after delivery. A lost response is
recovered only through bound `reissuePendingDelivery`, which abandons the pending successor and
issues fresh material; it never re-delivers the same key.

### POST /bfc/asymmetric-enrollments/{application}

Public (`bfc-claim` throttle). Complete one protocol-bound asymmetric signing enrollment. The
`application` path value is only a lookup hint: the host's
`ResolvesAsymmetricEnrollmentScope::resolve(Request $request, string $application)` implementation
derives the expected `BoundCredentialScope` from server-owned state. The package default resolver
returns `null`, so an unconfigured endpoint fails closed. No caller-authored purpose, subject,
installation, application, audience or algorithm is accepted. The route mounts no authentication,
session or CSRF middleware.

The closed JSON object has exactly these two string fields:

```json
{
  "enrollment_code": "64 lowercase hexadecimal characters",
  "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
}
```

The raw request body is limited to 24 KiB and is rejected before controller validation or key
construction; the `public_key` value is limited to 16 KiB before OpenSSL. The key must contain
exactly one inline `BEGIN PUBLIC KEY` / `END PUBLIC KEY` SubjectPublicKeyInfo block. File paths,
URLs, PKCS#1 `RSA PUBLIC KEY`, certificates, extra blocks or payload, malformed base64, private and
encrypted-private markers, EC/Ed25519 keys, and RSA keys below 2048 or above 8192 bits are refused.
Transport-only outer ASCII whitespace and CRLF are tolerated. Accepted material is re-exported as
canonical SPKI with LF line endings and one terminal LF; the algorithm is fixed to `RS256` and is
never request-selected.

- **201** with `Cache-Control: no-store` and exactly
  `{"credential_id":"<id>","algorithm":"RS256"}`. The code is consumed and the pending row
  becomes active atomically with its canonical public key and `exchanged` / `activated` audit
  events. For a routine bound rotation, the predecessor enters its never-extended one-hour grace
  in that same transaction.
- **422** `{"message":"..."}` for malformed or non-canonicalizable input. No key, code, audit or
  lifecycle state is partially written.
- **404** `{"message":"This asymmetric enrollment is unavailable."}` for the default resolver,
  a missing, reused, expired or mismatched code/scope, a dead or wrong-shaped row, or a lost
  concurrent claim. The response deliberately does not distinguish these cases.
- **500** `{"message":"The server hit an unexpected error. It is safe to retry."}` for an
  unexpected failure. Logs contain the exception class only. Nothing commits on this response.

The client-safe flow needs no server package in the monitored client host: generate an RSA keypair
locally with OpenSSL, retain the private key locally, and send only the public SPKI plus code over
HTTPS. The route never deliberately persists, echoes or logs the submitted code or key and rejects
private-key markers. `artisan-build/bfc-client` has no enrollment helper in this release; a client
may call this frozen wire directly without installing `artisan-build/built-for-cloud`.

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

## Package assets

### GET /bfc/assets/{path}

Serves the default layout's compiled stylesheet (`bfc.css`), its bundled fonts
(`fonts/{name}.woff2`) and images (`img/{name}.webp`) from the installed package, so an application renders the current release's
styles without rebuilding or publishing anything. `{path}` admits only those names; anything else,
including any path that leaves the package's `resources/dist` directory, is a 404. Unauthenticated
and unthrottled: the response is static, and `Cache-Control: public, max-age=31536000, immutable`
lets the browser keep it, with the layout's `?v=` content hash changing whenever the file does.
Mounted in every app, like the rest of the package routes.
*Pinned by* `PackageAssetsTest` (the stylesheet, every bundled font and the wordmark are served
with an immutable cache; missing names, other extensions and traversal attempts are 404s).

---

## Authenticated package UI

### GET /bfc/ui

Renders the package-owned authenticated home through `bfc::layout` for an active local Owner,
Admin, or Member under either valid authority mode. An unauthenticated request is redirected to
the authority mode's real login route with a validated same-origin relative intended path.
Invalid authority and delegated console principals refuse. Manifest identity and structural
navigation come from published package configuration; affordance flags affect presentation,
not route mounting or action authority.

### POST /bfc/ui/logout

Invalidates the current local browser session and regenerates its CSRF token under either
authority mode. The next protected request refuses through the current mode's login path;
managed mode does not claim or attempt upstream-provider logout.

---

## Standalone human lifecycle

Every route in this section runs through the package's standalone-authority predicate. The two
bearer handoff GETs use the stateless stacks documented below; clean pages and all other standalone
routes use the ordinary Laravel web session stack. Managed authority returns `404` before local
credentials, membership writes, session writes, or mail delivery. All mutating routes are CSRF
protected.

### GET /bfc/login

Renders the package login screen through `bfc::layout`. An optional `intended` value is retained
only when it is a validated same-origin relative path.

### POST /bfc/login

Authenticates an active canonical Owner, Admin, or Member with a non-null password through the
normal `web` guard, regenerates the session identifier, and updates `last_authenticated_at`.
Failures are generic and rate-limited; remember-me is unsupported.

### POST /bfc/logout

Requires the local session, invalidates it whole, regenerates CSRF, and redirects to
`bfc.login`.

### GET /bfc/forgot-password

Renders the non-enumerating package recovery request screen.

### POST /bfc/forgot-password

Always returns the same public result. Eligible verified standalone users receive a synchronous
package notification through the configured mail driver; generated or unusable addresses do not.
Only a SHA-256 token digest is stored, one latest record per email.

### GET /bfc/reset-password/{token}

Validates the path token and eligible reset state without starting a session, sets a short-lived,
path-scoped encrypted handoff cookie, and redirects with `Referrer-Policy: no-referrer` to the clean
reset URL. The route excludes `StartSession` and its subclasses at dispatch time. Hosts must not put
session middleware in the global HTTP kernel, which executes outside route-level exclusions and is
not a supported package configuration.

### GET /bfc/reset-password

Validates the reset handoff cookie on Laravel's ordinary browser/session stack and renders the
package reset form. The raw token appears only in the required hidden form field and is accepted
only by the following POST.

### POST /bfc/reset-password

Consumes an unexpired latest token once, stores a framework password hash, advances the account's
session version, and removes all enumerable database sessions and reset records. Role, status,
and provenance are not request fields and are not changed.

### GET /bfc/invitations/{token}

Validates the path token and addressed pending invitation without starting a session, sets a
short-lived, path-scoped encrypted handoff cookie, and redirects with
`Referrer-Policy: no-referrer` to the clean acceptance URL. It carries the same dispatch-time
`StartSession` exclusion and unsupported global-kernel boundary as the reset handoff.

### GET /bfc/invitations/accept

Validates the invitation handoff cookie on Laravel's ordinary browser/session stack and renders the
addressed invitation ceremony through the package layout. The raw token appears only in the
required hidden form field.

### POST /bfc/invitations/accept

Atomically burns an addressed pending token and creates one active canonical user with the
invitation's server-fixed Member or Admin role and verified addressed email. It starts a normal
web session with a regenerated identifier. Request role, email, status, provenance, and off-site
redirect values have no authority.

### GET /bfc/members

Lists canonical users and pending addressed invitations. All roles may authenticate; management
actions below enforce their fixed role boundary again inside the write transaction.

### POST /bfc/members/invitations

Owner or Admin may invite a Member; only Owner may invite an Admin. Owner invitations, unaddressed
codes, duplicate user addresses, and duplicate pending addresses refuse. This browser action is the
supported invitation-issuance surface; there is no operator route or invitation command.

### PUT /bfc/members/{user}/role

Owner alone promotes Member to Admin or demotes Admin to Member. Owner targets and unknown or
inactive target roles refuse after the target is locked.

### DELETE /bfc/members/{user}

Owner or Admin deactivates a Member; Owner alone deactivates an Admin. The stable user row remains,
while reset records, sessions, pending invitations, and user-bound credentials are invalidated.
Installation credentials are not selected by this operation.

### GET /bfc/transitions/{direction}/prepare

Owner alone may review the preparation step for an `adopt` or `exit` transition. This step explains
and starts preparation; the resulting proposal page lists every current local user and pending
invitation. The optional `ui.managed_transitions` flag controls only whether preparation and correction
controls are rendered; direct requests retain all authorization and proposal validation.

### POST /bfc/transitions/{direction}/prepare

Owner alone may prepare a transition in the direction permitted by the current authority mode. The
package records the authority snapshot, retrieves the complete authority roster, and persists a
complete default proposal before redirecting to its review page.

### GET /bfc/transitions/proposals/{transition}

Owner alone may review a proposal from `prepared` through the durable completion states. Adoption
presents authority roles as fixed while allowing local match, commit timing, and final-email corrections.
Exit presents every roster subject, local user, and pending invitation while allowing standalone role,
match, disposition, and final-email corrections where those fields apply.
An unmatched local user absent from the exit roster defaults to `exclude` only when its freshness state
is exactly `managed_membership_status=removed`, `status=inactive`, a non-null `deactivated_at`, and a null
password. `exclude` applies its existing deactivation effects: the row remains retained, becomes inactive,
receives a deactivation timestamp, and has its password and remember token cleared. A never-listed unmatched
local user still defaults to `retain_local` and remains active.

### PUT /bfc/transitions/proposals/{transition}

Owner alone may replace a proposal's complete mapping while it remains editable. The package rejects
missing or duplicate identities, illegal direction-specific dispositions, adoption role changes, and
duplicate projected final emails. It locks and rechecks the Owner before replacing the stored mapping;
staging revalidates the mapping against the current local identities before sending the exact persisted
mapping to T3.

### POST /bfc/transitions/proposals/{transition}/complete

Owner alone may resume a persisted proposal through staging, local commit, and acknowledgment. Retries
continue from the transition's durable status rather than blindly replaying a mutating authority leg.

### POST /bfc/transitions/proposals/{transition}/abandon

Owner alone may abandon a transition in `prepared`, `rostered`, `proposed`, `staging`, or `staged`
state. The package sends the persisted idempotent abandon request to the authority, marks the local
attempt abandoned, and releases the installation's active transition slot so a fresh preparation can begin.

### GET /bfc/me/sessions

For the database session driver, lists only rows whose `user_id` is the authenticated account and
marks the current session structurally. Other drivers render an explicit unavailable state rather
than claiming enumeration.

### DELETE /bfc/me/sessions/others

After current-password confirmation, deletes only the caller's other database sessions.

### DELETE /bfc/me/sessions/{session}

After current-password confirmation, deletes one non-current session only when it belongs to the
caller. Foreign, current, and absent identifiers do not produce revocation success.

---

## Authority-driven managed enrolment

These machine routes are authenticated by the **current owner credential** returned once by
[`POST /bfc/ownership/claim`](#post-bfcownershipclaim). A different live operator credential,
including another credential carrying `credential:admin`, is not the current owner credential and
cannot use them. Missing, unknown, expired or revoked bearer credentials answer `401`; an
authenticated non-owner credential answers `403`. All three routes carry the operator-write rate
limit before authentication and return `Cache-Control: no-store`.

The attacker boundary is a party without the owner token, plus a replayed or forged enrolment
request. Deliberately hostile host configuration is outside the boundary. Every mutation compares
the request's expected counters and immutable connection binding against locked stored state. A
stale request cannot roll back a newer enrolment, client-secret rotation or disconnect.

The five connection facts are `issuer`, `connection_id`, `organization_id`, `installation_id` and
`authority_base_url`. Identifiers are non-empty bounded strings. `issuer` is an absolute HTTPS URI;
`authority_base_url` is an HTTPS origin with no path other than `/`, query, fragment or userinfo.
`managed_client_secret` is a non-empty bounded bearer secret. Unknown request fields are refused.

The managed client secret is encrypted before commit under Laravel's current `APP_KEY`; the row
stores ciphertext, the content-addressed key version, and a domain-separated SHA-256 digest used
only to compare a retry without decrypting it. Reads select that exact version from `APP_KEY` plus
`APP_PREVIOUS_KEYS` and fail closed when it is absent or unreadable — they do not scan other keys or
fall back to the environment when ciphertext exists. The managed secret participates in the
package's staged APP_KEY rewrap procedure before an old key is removed.
`BUILT_FOR_CLOUD_MANAGED_CLIENT_SECRET` remains only as a compatibility fallback when no persisted
secret exists, because the Owner-driven `adopt` transition still needs its pre-P1 provisioning path.
Persisted enrolment state always takes precedence. **Contract residue:** that environment seam is
named follow-up work — package issue
[#150](https://github.com/artisan-build/built-for-cloud/issues/150), which blocks nothing in P1 —
to deliver the secret through the adopt transition's own staged/acknowledged path and then delete
the seam rather than guard it.

Every `409` on these three routes carries a bounded `error` code (with a human `message`) drawn
from ONE shared vocabulary — the same word means the same thing on every route — and the
disconnect `409`s additionally carry the same code as `reason`, so an operator surface can classify
a refusal without parsing prose: `owner_not_accessible` (disconnect only: no exactly-one active
local Owner who can authenticate or receive recovery would remain), `transition_in_progress`,
`binding_conflict`, `stale_generation`, `not_managed` (rotation/disconnect), `already_managed`
(enrolment), `not_pristine` (enrolment), and `key_cutover_in_progress` (a staged APP_KEY rewrap
holds the writer barrier; retry once `bfc:hmac:rewrap` verifies zero old-version rows).

*Pinned by* `ManagedClientSecretStoreTest` (version-selected decrypt, wrong-version refusal,
APP_PREVIOUS_KEYS read and rewrap) and `ManagedAuthConnectionTest` (persisted-over-environment
precedence, unreadable persisted state refuses without fallback, environment used only when no
ciphertext exists). These tests enumerate the package's current store and configuration reads; they
do not establish anything about direct host database writes, container rebinding or future read
paths not added to their inventory.

### POST /bfc/managed/enrolment

Enrol a **pristine** claimed installation. Pristine means standalone mode, no local users or pending
invitations, no active managed transition, no existing connection facts, and the exact
`expected_generation`. A non-pristine standalone app must use the Owner-driven `adopt` transition.

**Request**

```json
{
  "enrolment_id": "018f...",
  "expected_generation": 1,
  "issuer": "https://scalpels.example",
  "connection_id": "connection-id",
  "organization_id": "organization-id",
  "installation_id": "installation-id",
  "authority_base_url": "https://scalpels.example",
  "managed_client_secret": "single-delivery bearer secret",
  "client_secret_generation": 1
}
```

`enrolment_id` is a caller-generated UUID. `client_secret_generation` MUST be `1`. In one locked
database transaction the package validates pristine state, encrypts the secret, writes all five
facts and the server timestamp, then changes `standalone/N` to `managed/N+1`. The database trigger's
rule is the wire rule: every mode change strictly increments generation. A fresh install therefore
lands at `managed/2`, and the authority records the returned value before allowing handoffs.

- **201** — first commit:
  `{"enrolment_id":"...","mode":"managed","generation":2,"client_secret_generation":1,"enrolled_at":"2026-09-21T20:00:00Z"}`.
- **200** — an exact retry of the same `enrolment_id` and same non-secret fields after a committed
  response was lost. The digest of the presented secret is compared against the RETAINED LEDGER's
  commit-time digest — the frozen digest of the request that actually committed — so the original
  exact request remains replayable even after later rotations replaced the live secret, and the
  route returns the same committed state without rewriting it. A changed secret (or any changed
  non-secret field) under the known UUID is `binding_conflict`, as is a committed outcome whose
  connection the authority has since left.
- **409** — `already_managed`, `not_pristine`, `transition_in_progress`, `stale_generation`,
  `binding_conflict`, `key_cutover_in_progress`, or reuse of an `enrolment_id` with different
  non-secret fields.
- **422** — malformed or out-of-bounds input. Validation responses never reflect the secret.

### POST /bfc/managed/enrolment/client-secret

Make-before-break rotation of the bearer the app uses for outbound managed-auth calls. The authority
must keep the old secret valid until this call succeeds, then activate the new secret on its side.
Authority generation does not change.

**Request**

```json
{
  "rotation_id": "018f...",
  "issuer": "https://scalpels.example",
  "connection_id": "connection-id",
  "installation_id": "installation-id",
  "expected_generation": 2,
  "expected_client_secret_generation": 1,
  "managed_client_secret": "replacement bearer secret"
}
```

- **200** — first commit or an exact retry (the same retained-ledger commit-time digest rule as
  enrolment):
  `{"rotation_id":"...","mode":"managed","generation":2,"client_secret_generation":2,"rotated_at":"2026-09-21T20:05:00Z"}`.
- **409** — `not_managed`, `transition_in_progress`, `binding_conflict`, `stale_generation`, or
  `key_cutover_in_progress` (a staged APP_KEY rewrap holds the writer barrier while the persisted
  row still carries an old key version).
- **422** — malformed or out-of-bounds input. The replacement secret is never echoed, logged or
  placed in an audit note.

Here and on disconnect, the immutable operational binding is the triple `issuer`, `connection_id`,
`installation_id`; `organization_id` and `authority_base_url` are connection attributes, not the
identity key. All three identity members are compared under the authority-row lock.

### POST /bfc/managed/enrolment/disconnect

**Request**

```json
{
  "disconnect_id": "018f...",
  "issuer": "https://scalpels.example",
  "connection_id": "connection-id",
  "installation_id": "installation-id",
  "expected_generation": 2
}
```

The package resumes or drives the existing managed `exit` transition for this exact binding. It
does not duplicate the exit cleanup: that path invalidates every session and user-bound credential,
consumes reset state and outstanding managed handoffs, advances session versions, PRESERVES local
passwords (the standalone owner logs in with hers; only `adopt` nulls them, when the authority
replaces local auth on the way in), and applies the accessible-Owner recovery guard before local
commit, WITH THE AUTHORITY ROSTER IN HAND: the disconnect drives the exit path — prepare, roster
fetch, default mapping, staging — and the guard refuses on the mapped result. On an app managed
from birth nobody has a local password or locally verified email, so the roster's verification of
the Owner's contact address is the deciding fact. An unreachable-Owner refusal
(`owner_not_accessible`) rolls the commit back — the authority row is untouched — and DURABLY
ABANDONS the transition row through the same legs the documented Owner abandon route walks
(state check plus keyed abandon, both sides), so no ACTIVE transition remains; the exact retry —
typically after the operator repaired the Owner's reachability — prepares a fresh transition under
the same `disconnect_id`. If the abandonment legs are themselves unreachable, the disconnect stays
durably in flight (202) and the pre-commit Owner abandon route remains the remedy.
After authority acknowledgement it clears the persisted managed secret and five connection facts.
The mode change is `managed/N` to `standalone/N+1`; the response carries the committed generation.

- **200** — first completion or an exact completed retry:
  `{"disconnect_id":"...","status":"completed","mode":"standalone","generation":3,"disconnected_at":"2026-09-21T20:10:00Z"}`.
- **202** — this exact disconnect is durably in flight. The bounded response carries
  `disconnect_id`, `status: "pending"`, `transition_id`, current `mode`, current `generation`, and
  `phase` — the transition row's durable position, one of `prepared`, `staged`, `committed`, or
  `acknowledging` (an acknowledgement whose outcome is unknown lands `acknowledging`, never a
  stale `committed`). An exact retry resumes it.
- **409** — `not_managed`, `binding_conflict`, `stale_generation`, `transition_in_progress` (a
  different transition is active), `owner_not_accessible`, or `key_cutover_in_progress`. Every
  disconnect `409` additionally carries the same code as `reason` — a bounded enum, never free
  text.
- **422** — malformed or out-of-bounds input.

Pending disconnects do not expire automatically. Before local commit, the returned transition id is
reachable by the existing Owner abandon route. After local commit the transition cannot be abandoned:
the app is already standalone, and exact retries continue acknowledgement until the authority
recovers. Until acknowledgement, the five facts and encrypted secret remain stored but are inert in
standalone mode. This can hold the transition slot indefinitely; it is the named recovery residue,
not a success response.

Enrolment, rotation and disconnect idempotency records are retained after disconnect. Re-enrolment
must use a fresh `enrolment_id`; replaying any id from an earlier connection is refused with `409`.

The environment fallback cannot be erased by HTTP. It is inert in standalone mode and is retained
solely for the Owner-driven `adopt` compatibility path; operators removing that legacy configuration
must do so in deployment configuration.

*Pinned by* `ManagedEnrolmentSecretContainmentTest`, which drives canary secrets through validation,
success, retry conflict, rotation and failure while `DetectsSecretLeaks` inventories logger,
exception reporter, database plaintext fields, cache, session, queue/trace and audit sinks. The
instrument covers only those enumerated package sinks and cannot prove containment against hostile
host code or a future sink omitted from the inventory.

## Managed human entry

These browser routes are available only while the installation authority is managed; standalone
authority is refused by the managed-authority gate with Laravel's ordinary 404 response. Both
routes use the ordinary Laravel web session stack and bind `EnsureManagedAuthority` by class.

The trusted connection origin, installation id, connection id, generation, issuer and required
client secret come from the authenticated enrolment above (or the documented legacy `adopt`
fallback). Browser input cannot select or override them. Connection state written by the enrolment
routes is locked, counter-bound and encrypted where secret; direct database tampering by the host is
outside this contract.

### GET /bfc/managed/login

Creates at least 256 bits of opaque state and a nonce in the initiating browser session. The
package stores only SHA-256 digests in its correlation row, bound to the installation, connection
and generation, with an expiry capped at five minutes and shortened by the authority's expiry.
The same opaque value is used as the server-to-server `request_id` and browser `state`.

The package creates the handoff through the configured authority over authenticated HTTPS. It
accepts the returned authorization base URL only when it has the stored connection's exact HTTPS
scheme, host and port, the frozen `/managed-auth/v1/authorize` path, and no query or fragment. The
browser redirect appends the one exact `state` field.

### GET /bfc/managed/callback

Accepts the authority-provided `state` and `code`. The correlation can be claimed once and only by
the initiating browser session; concurrent or replayed claims refuse before exchange. After the
claim, the package exchanges the code with the configured authority over authenticated HTTPS,
enforces its invariant response bindings, and accepts the authority-provided subject. It also
enforces the wire types of the roster and response sequence values. This P3a entry slice does not
persist either required high-water mark, so it does not enforce order regression; P3c adds the
durable per-subject and per-connection marks and their per-dimension apply decisions.

An active, verified response upserts a canonical user by the exact issuer, connection and subject
tuple. A new tuple never adopts an existing row by email; a case-insensitive collision instead uses
a database-arbitrated `+bfc` alias while preserving the authority address as the original contact
email. If an honest alias cannot fit without truncating an existing plus tag, or another integrity
constraint refuses the write, the callback fails closed with the same plain-text `404 Not Found`.
The source-email conflict artifact is best-effort under concurrency: it can miss a conflict when the
other identity is created concurrently with the check, then is re-evaluated and corrected on this
subject's next login. It does not arbitrate email uniqueness or an access decision. On success the
callback regenerates the session and redirects to `/`.

---

### GET /bfc/client-observations

Identities claimed on requests that presented **no valid credential**. Advisory and spoofable by
design — the payload says so itself. Requires a unified operator credential with
`credential:read`, or `credential:admin` break-glass. The fixed route is always registered with
the HTTP surface.

**200** — `{"enabled": bool, "advisory": true, "spoofable": true, "note": "...",
"at_capacity": bool, "max_observations": 100, "observations": [{"client_identity": "...",
"first_seen_at": "...", "last_seen_at": "...", "observation_count": 3}]}`. `observations` is
`[]` while the feature is disabled (`enabled` distinguishes "off" from "on and quiet").

## The unified credential store (`/bfc/credentials`)

The two-transport verbs (PRD 1.0): each of these routes runs the **same action class** as its
`--local` artisan command (`bfc:credential:mint` / `list` / `rotate` / `activate` / `revoke`),
so the two transports cannot diverge. Always mounted, at a fixed path.

**Authentication on these routes** requires a unified-store `operator` credential holding the
route's **verb-family ability**
  (see [Authentication](#authentication)): `credential:read` for the listing,
  `credential:mint` for mint, `credential:rotate` for rotate AND activate,
  `credential:revoke` for revoke — or the explicit admin-equivalent `credential:admin`,
  which is what `bfc:install:operator-credential` mints at install time, so a fresh install
  can manage its credentials with the one secret it was handed. A valid unified credential
without the verb's authority is `403` and the denial is audited. Write verbs ride the
`bfc-operator-write` limiter.

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
32 entries, each at most 128 characters, and every entry must be a backed value from the closed
operator ability vocabulary above. **An empty `abilities` list normalizes to `null`** —
both grant nothing, and summaries always serialize the one canonical shape (`null`).

Summary rows share one shape:

```json
{
  "id": "9d3f...",
  "kind": "bearer",
  "purpose": "consumption",
  "subject_type": "external_consumer",
  "subject_ref": "acme",
  "name": "ci" ,
  "abilities": ["credential:read"],
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

`kind` is `bearer` / `basic` / `asymmetric` / `hmac`; `purpose` is one of
`operator_management`, `dashboard_metadata`, `consumption`, `mcp`, `signing`, `signing_root`,
`enrollment`, or `system_deployment`; `status` is `pending` / `active` /
`expired` / `revoked` (`unknown` reserved). **`unsupported` is the declared-unsupported
discrimination:** a field named there is one the app's declaration says this store structurally
cannot express — it is serialized null *and* listed, so null-and-listed means "unknowable here"
while null-and-not-listed means "absent". Consumers must not render or alert on unsupported
fields. `rotated_at` is rotation provenance: non-null names a row superseded by rotation and its
lineage successor. Depending on kind and binding, the predecessor may still own live signing while
hmac activation or bound asymmetric enrollment is pending, or may be living out its grace window
beside an active replacement. A retired pre-purpose tombstone is the sole nullable-purpose case: it lists with
`purpose: null`, `status: "revoked"`, and its preserved `revoked_at`.

### GET /bfc/credentials

**200** — an array of summary rows, oldest first. Per-row `list_metadata` filtering applies;
`BFC-Presentation-Cadence` is included when a cadence is declared.

### POST /bfc/credentials

Mint a credential for a **subject** — `mint(Subject, MintOptions)`; there is no mint-by-id,
because the row does not exist yet.

**Request:**

```json
{
  "subject_type": "external_consumer",
  "subject_ref": "acme",
  "kind": "bearer",
  "purpose": "consumption",
  "name": "ci",
  "abilities": ["credential:read"],
  "expires_at": null,
  "user_id": null,
  "code_ttl_seconds": null
}
```

`subject_type`, `subject_ref`, and `purpose` are required; everything else is optional. Unknown,
missing, or matrix-invalid purposes are rejected. The generic mint matrix is exact:

| kind | subject type | admitted purpose |
|---|---|---|
| `bearer` / `basic` | `operator` | `operator_management`, `dashboard_metadata` |
| `bearer` / `basic` | `application` | `system_deployment` |
| `bearer` / `basic` | `installation` | `system_deployment`, `consumption`, `mcp` |
| `bearer` / `basic` | `external_consumer`, `user_principal` | `consumption`, `mcp` |
| `hmac` | any ordinary subject admitted by the declaration | `signing` |
| `asymmetric` | any subject admitted by the declaration | `enrollment` |

Generic minting refuses `signing_root` and the reserved
`(installation, bfc:signing-root)` identity. `expires_at` omitted
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
| `enrollment_code` | `enrollment_code` | a claim-primitive code (ttl = `code_ttl_seconds`); the client redeems it by generating its own keypair. The code never carries key material, and the credential row is `pending` until enrollment completes. Generic unbound `purpose: enrollment` codes remain listable and revocable but are not accepted by the bound signing enrollment route |
| `signing_key` | `signing_key`, `key_id`, `delivery_fingerprint` | the reveal-once delivery of a PENDING hmac signing key — the operator-controlled-counterparty path. `key_id` is the (non-secret) row id the signature header will carry; `delivery_fingerprint` (non-secret) names THIS delivery, and the activation verb requires it. The key signs nothing until activated |
| `signing_key_code` | `claim_code` | a claim-primitive code (ttl = `code_ttl_seconds`) whose [exchange](#post-bfconboardingexchange) delivers the PENDING hmac key — and its `delivery_fingerprint` — to an outside counterparty, and **never activates it** (SEC-V3-01) |
| `none` | — | the secret was never ours to hand over |

- **403** — `{"message": "..."}`: the declaration denies `issue` for this subject, the request
  widens abilities or lifetime past a declared ceiling, or sets a declared-unsupported field.
  Identical refusals on the CLI transport.
- **409** — `{"message": "..."}`: an hmac mint while an APP_KEY rewrap is in progress — every
  ciphertext-producing path pauses mid-cutover; retry after `bfc:hmac:rewrap` completes.
- **422** — validation (unknown `subject_type`/`kind`/`purpose`/ability, missing or matrix-invalid
  `purpose`, out-of-bounds `code_ttl_seconds`, …).

Emits an `issued` audit event (ids only, never values) in the mint's own transaction, on both
transports.

### Bound asymmetric PHP APIs

Bound asymmetric signing is intentionally not added to the generic HTTP mint matrix or UI purpose
choices. A reviewed host maps an app adoption purpose such as `reel.application.signing` to package
purpose `signing`, constructs
`BoundCredentialScope(string $appPurpose, Subject $subject, string $installation, string $application, string $audience)`,
and calls `MintCredential` with `MintOptions(kind: Asymmetric, purpose: Signing,
codeTtlSeconds: ..., boundScope: $scope)`. The subject must be installation-owned (`user_id = null`),
and every action re-resolves the configured app-purpose mapping at use time. Scope strings are
non-empty valid UTF-8 without controls and at most 255 bytes; audience additionally matches
`^[^,\\s]{1,255}$`.

Completion is the model-free action:

```php
CompleteAsymmetricEnrollment::__invoke(
    string $enrollmentCode,
    BoundCredentialScope $expectedScope,
    Rs256PublicKey $publicKey,
): EnrolledAsymmetricCredential;
```

Its DTO contains credential id, app purpose, subject, installation, application, audience and
algorithm, never a model or key material. Verification selects through
`AsymmetricVerificationKeys::for(BoundCredentialScope $scope): array`. It returns ordered
`AsymmetricVerificationKey` DTOs containing only credential id, canonical public key and `RS256`,
ordered by `activated_at DESC, created_at DESC, id DESC`. Selection fixes asymmetric/signing,
installation ownership, originator role and RS256, then compares every exact scope and subject
field; pending, revoked, expired, unbound, malformed or null-key rows are invisible. The monitored
client keeps the private key and owns signing; the package API supplies verification keys only.

### Bound HMAC PHP APIs

`HmacCredentialIssuerClient` is mandatory and has exactly three operations:
`claim(BoundCredentialScope, SensitiveString): ClaimedHmacCredential`,
`activate(BoundCredentialScope, ?string $predecessorId, string $replacementId, string
$deliveryFingerprint): IssuerHmacCutoverReceipt`, and `cutoverStatus(BoundCredentialScope,
?string $predecessorId, string $replacementId): IssuerHmacCutoverReceipt`.
`HttpHmacCredentialIssuerClient` fixes those calls to the exchange route and the two protected
routes below, requires HTTPS except loopback HTTP in local/testing, disables redirects, pins the
effective origin, requires exact JSON shapes, and caps responses at 24 KiB. The host supplies TLS
configuration and fresh protected-route authorization headers.

The receiver calls `InstallHmacCredentialFromClaim::__invoke(BoundCredentialScope,
HmacCredentialIssuerClient, string): InstalledHmacCredential`. Under `HmacWriterBarrier`, it
reveals the internal carrier once, fingerprint-checks, encrypts immediately, and atomically writes
the same issuer id as a `verification_copy`, exact binding/lifecycle facts, audit/outbox and durable
predecessor lineage. Exact retries are idempotent; changed collisions refuse without overwrite.
There is no public import route or secret-bearing command option.

Callbacks use `HmacSigner::signBound(BoundCredentialScope, string $body, string $eventType):
string` and `HmacVerifier::verifyBound(BoundCredentialScope, string $header, string $body):
VerifiedHmacCredential`. Signing selects originators only; verification accepts the exact named
originator or verification copy and returns ids, scope and fixed algorithm only, never a model or
secret. Wrong scope, role or lifecycle is rejected before decrypt, replay/rate state or usage.
Existing unbound methods remain source-compatible and cannot select bound rows.

`CutOverImportedHmacCredential` accepts only a direct authenticated receipt for exact durable
lineage, locks both ids lexically, and atomically applies an equal or earlier source deadline with
lifecycle/outbox. `CoordinateImportedHmacCutover::recover()` uses authenticated status after an
issuer-success/receiver-failure split; `CrossStoreCutoverIncomplete` contains ids and authoritative
expiry only. Separate stores are not distributed-atomic and revocation coordination remains the
adopting application's responsibility.

HMAC plaintext is permitted only in the authenticated issuer response, sealed one-reveal carriers,
keyring encrypt/decrypt calls and HMAC computation. `HmacSecretSurfaceInventoryTest` derives direct
recognized production syntax and includes a positive-control fixture that returns, logs,
JSON-encodes, writes and passes plaintext as a process argument. This is honestly lexical, not
whole-program analysis: dynamic calls/aliases, reflection/debugger/memory capture, raw model or
query-builder writes, generated/custom encodings, host code, malicious bindings and consumer code
after reveal are outside its claim.

### Reserved installation signing root (no HTTP surface)

The reserved HMAC row is exactly `purpose: "signing_root"`, subject
`(installation, bfc:signing-root)`, with no abilities. It is created only by
`bfc:signing-root:provision --local`; the command accepts no identity, key-id, secret, or delivery
arguments and returns only the credential id plus fixed no-export text. Generic and installation
management listings exclude it, and generic mint, activation, revoke, offboarding, claim exchange,
and personal minting cannot create, reveal, or mutate it.

`SigningRootMac::mac(string $bytes)` selects the sole current root internally and returns only
`{keyId, lowercaseHexMac}`. `SigningRootMac::verify(string $keyId, string $bytes, string $presentedMac)`
returns only a boolean and accepts the exact named current root or an exact superseded root still in
its one-hour verification grace. Bytes are opaque; the package adds no JSON encoding, timestamp,
nonce, audience, or canonicalization. The wire MAC is exactly 64 lowercase hexadecimal characters.

An unchanged call through the public generic rotation action delegates to the dedicated root
lifecycle. The replacement is direct-active before the source is stamped; new signing therefore has
no gap. Ordinary rotation keeps old verification through the earlier of one hour or its existing
expiry, while emergency rotation ends old verification at transaction cutover. Every root mutation
holds the HMAC writer barrier and the installation authority row lock in one database transaction.
`bfc:hmac:rewrap` includes root ciphertext in its existing decrypt-then-encrypt step and emits only
ids, key versions, counts, and fixed outcome text.

### DELETE /bfc/credentials/{id}

Revoke by id — the precise verb; `pending` enrollments are revocable too, and revoking one also
consumes its outstanding enrollment code.

- **204** — revoked, or already dead (idempotent — one death, one `revoked` audit event).
- **404** — no such id. **403** — `{"message": "..."}` per the declaration's `revoke` verb.

### POST /bfc/credentials/{id}/rotate

Rotate by id — the primary verb (there is no name path over HTTP; `bfc:credential:rotate
--name` is a CLI convenience that refuses on ambiguity). Make-before-break: the replacement is
minted FIRST. The per-kind rules below decide whether predecessor retirement happens immediately
or waits for activation/enrollment.

**Default rotation preserves EXACTLY**: the purpose, the ability set, the subject binding
(`subject_type` / `subject_ref` / `user_id`), the decorative name, and the remaining expiry of
the row it replaces. Bound rotation additionally copies the exact app purpose, installation,
application, audience, algorithm and material role. Rotation accepts no purpose or scope override.
When an old row enters grace, it stays resolvable for at most one hour (its own earlier expiry
wins — rotation never extends any lifetime) and dies at that expiry. No reaper is involved.

**Request:**

```json
{
  "emergency": false,
  "override": false,
  "abilities": null,
  "expires_at": null,
  "code_ttl_seconds": null,
  "reissue_pending_delivery": false
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
otherwise. `reissue_pending_delivery` defaults to false and is legal only on a bound asymmetric
originator whose latest non-abandoned successor is still pending, unused and has an unconsumed
code. It cannot be combined with emergency or override changes.

Per kind:

| kind | rotation semantics |
|---|---|
| `bearer` / `basic` | a fresh secret is minted and delivered once, in this response's `delivery` (same shapes as the mint route) |
| `asymmetric` | a fresh **enrollment code** is delivered against a new `pending` row — the client generates the new keypair itself; no key material ever travels. Legacy unbound rotation retains immediate one-hour grace. A routine bound originator keeps the old row fully active until the replacement completes through the asymmetric enrollment route; completion then atomically starts grace, during which exact-scope lookup returns old and new. `emergency: true` ends the bound predecessor immediately and accepts an outage until enrollment |
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

For a lost bound-asymmetric delivery response, invoke the same route on the predecessor with
`{"reissue_pending_delivery":true,"code_ttl_seconds":...}`. In one transaction it consumes the old
code, revokes the unusable pending successor with the additive audit reason
`delivery_abandoned`, and returns one newly issued pending successor/code. It never redelivers the
abandoned code or key material. This is permitted once in a predecessor lineage: replay or a
different/current/active successor creates nothing, reveals nothing and returns the ordinary
non-revealing `409` refusal. Same-second lineage remains unambiguous because abandoned successors
are excluded rather than ordered by audit timestamp. The CLI spelling is
`bfc:credential:rotate <predecessor-id> --reissue-pending-delivery --code-ttl=<seconds> --local`.

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
  or the successor is an hmac key **still pending activation** (activate it instead), or a bound
  asymmetric successor is **still pending public-key enrollment**, or an hmac rewrap is in
  progress (retry after `bfc:hmac:rewrap` completes). An invalid or replayed bound-delivery
  reissue is the same non-revealing `409`.
- **422** — `{"message": "..."}`: shared input validation (a change without `override`,
  out-of-bounds `code_ttl_seconds`, malformed abilities/expiry/booleans, override options on
  a completion) — identical refusals on the CLI transport.
- **500** — `{"message": "..."}`: the replacement was committed but the old row could not be
  retired. The message names both ids; the old row is STILL LIVE, listed with its `rotated_at`
  stamp. The recovery needs no authority beyond the rotation itself: **invoke this route on
  the stamped row again** — the 200 completion above — or `DELETE /bfc/credentials/{id}`
  where revoke is authorized. **No secret was delivered** — the sealed carrier is discarded —
  so rotate the standing replacement for a fresh delivery, or revoke it by id if unneeded.

### POST /bfc/hmac-cutovers/activate

Protected issuer operation (`credential:rotate`, operator-write throttle). It activates one exact
protocol-bound HMAC originator after the separate receiver has installed the delivered replacement.
The JSON object is closed; unknown fields or wrong types return the same `409` refusal.

```json
{
  "app_purpose": "matte.callback",
  "subject_type": "installation",
  "subject_ref": "server-derived subject reference",
  "installation_ref": "installation reference",
  "application_ref": "application reference",
  "audience": "https://receiver.example",
  "predecessor_credential_id": "UUID or null for first generation",
  "replacement_credential_id": "UUID",
  "delivery_fingerprint": "16 lowercase hexadecimal characters"
}
```

Success is `200` with `Cache-Control: no-store` and the exact receipt shape below. Activation
requires the exact pending originator, scope, source lineage and current delivery fingerprint. For
rotation it starts issuer signing with the replacement and bounds the predecessor to the earlier of
its stored expiry or the ordinary grace deadline. Emergency lineage reports `emergency: true` and
an immediate predecessor deadline. First-generation activation has null predecessor id and expiry.

```json
{
  "predecessor_credential_id": "UUID or null",
  "replacement_credential_id": "UUID",
  "app_purpose": "matte.callback",
  "subject_type": "installation",
  "subject_ref": "server-derived subject reference",
  "installation_ref": "installation reference",
  "application_ref": "application reference",
  "audience": "https://receiver.example",
  "activated_at": "2026-09-15T12:00:00+00:00",
  "predecessor_expires_at": "2026-09-15T13:00:00+00:00 or null",
  "emergency": false
}
```

- **401/403** follow the operator gate. **409** is the uniform
  `{"message":"The HMAC cutover was refused."}` for malformed, unknown, mismatched or unusable
  input. No response carries key material.

### POST /bfc/hmac-cutovers/status

Protected issuer recovery operation (`credential:rotate`, operator-write throttle). It is an
idempotent authenticated read of source cutover state after activation may have committed but the
receiver update failed. The closed request is identical to the activation request except that
`delivery_fingerprint` is absent. Success is the exact same `200` receipt and `Cache-Control:
no-store`; `401`/`403` and the uniform `409` have the same meanings. It cannot activate a pending
replacement. The returned predecessor expiry is the actual stored deadline, so a receiver retry
can preserve or shorten authority but never extend it.

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

## Device and loopback credential authorization

These two transports share one application-declared authorization profile, one transient
`credential_authorizations` lifecycle, and the unified credential store. They differ only in how
the initiating client receives approval: a device client polls with an opaque code, while an
interactive CLI receives a one-time code on an exact HTTP loopback callback and proves PKCE S256.

The consuming application's credential declaration may implement
`DeclaresCredentialAuthorizationProfiles`. Each `CredentialAuthorizationProfile` fixes the app
adoption purpose, exact `BoundCredentialScope` (subject, installation, application and audience),
`personal|installation` ownership, bearer abilities, optional durable expiry, authorization TTL
(60–900 seconds) and initial poll interval (5–30 seconds). `AppPurposeRegistry` maps the adoption
purpose to one protocol purpose. Request input never selects those values, the credential kind,
algorithm, material role or user id. Both exchange routes mint `bearer` / `originator` material.

Use an issued bearer only through `BoundBearerCredentialAuthenticator`, supplying the expected app
purpose so the declaration rebuilds the exact scope server-side. The legacy unbound bearer resolver
deliberately excludes these credentials. A wrong purpose, subject, ownership, installation,
application, audience, ability or malformed binding refuses before declaration authorization,
managed-authority cache/rate participation, usage recording or consumer work.

The browser routes require the package's local, non-delegated authenticated human and the host
application's normal session and CSRF middleware. Ceremony values in that session are package-
encrypted ciphertext; a different browser, even logged in as the same user and holding the displayed
device code, cannot decide the grant. The map holds at most eight live grants. A full map refuses a
new grant and never evicts an existing one. Session regeneration preserves only live ciphertext;
logout, invalidation and terminal decisions remove it.

### POST /bfc/device-authorizations

Session-authenticated and CSRF-protected. JSON accepts exactly `app_purpose` and optional `label`.
The label is trimmed ASCII outer whitespace, valid UTF-8 with no control characters, at most 64
bytes, and is refused rather than truncated. Success is `201`, `Cache-Control: no-store` and
`Pragma: no-cache`, with exactly:

```json
{
  "device_code": "opaque-43-character-value",
  "user_code": "ABCD-EFGH",
  "verification_uri": "https://app.example/bfc/device",
  "expires_in": 600,
  "interval": 5
}
```

There is no public start, complete/code-bearing verification URI, or request-authored scope. Start
is limited to 15/minute by authenticated-user-plus-source-IP.

### GET /bfc/device

Takes no query fields. It renders only this browser's still-live sealed grants, including the
test/client-created user code, purpose, audience, installation, application, ownership consequence
and optional label. An unknown, expired, terminal or foreign-browser grant gets the same unavailable
page. The generic URI keeps the user code out of URLs, referrers, access logs and browser history.

### POST /bfc/device

CSRF-protected form submission with exactly `user_code`, `action=approve|deny` and the displayed
single-use `submission_nonce` (plus the framework CSRF field/header). The submission nonce is bound
to session, user, authorization and exact action. Approval records only `pending -> approved`; it
never mints a credential. Denial is terminal. Decision attempts are limited to 10/minute by
authenticated-user-plus-source-IP.

### POST /bfc/device/token

Public and CSRF-free. Requires `Content-Type: application/json` and exactly one string
`device_code`. Every response is `no-store`. Success is:

```json
{
  "access_token": "revealed-once-bearer",
  "token_type": "Bearer",
  "credential_id": "credential-uuid",
  "app_purpose": "declared.app-purpose"
}
```

`expires_at` is added as RFC 3339 only when policy set a durable expiry. Errors are closed:

| Condition | Status | Exact JSON |
| --- | ---: | --- |
| malformed media/body/fields | 400 | `{"error":"invalid_request"}` |
| unknown/replayed/consumed | 400 | `{"error":"invalid_grant"}` |
| expired | 400 | `{"error":"expired_token"}` |
| denied/withdrawn/removed | 400 | `{"error":"access_denied"}` |
| pending | 400 | `{"error":"authorization_pending"}` |
| too early | 400 | `{"error":"slow_down","interval":N}` |
| authority infrastructure unavailable | 503 | `{"error":"temporarily_unavailable"}` plus `Retry-After: 5` |

The per-grant interval rises by exactly five seconds on early polls, capped at 30. Transport limits
are 120/minute per source IP (IPv6 aggregated to `/64`) and a package-global 6,000/minute cap.
Limiter refusal precedes parsing/lookup and is `429 {"error":"slow_down","interval":N}` with the
same bounded `Retry-After`; it does not change grant cadence or authority cache. The global cap is
an **availability ceiling**, not a security guarantee: a distributed flood can delay every tenant's
exchange until the window rolls, and a short-lived grant can expire while a compliant client waits.

### GET /bfc/loopback/authorize

Session-authenticated and limited by the same 15/minute start budget. It accepts exactly
`app_purpose`, `redirect_uri`, `code_challenge`, `code_challenge_method=S256`, `state` and optional
`label`. State is 32–128 unreserved ASCII characters. The challenge is a 43-character unpadded
base64url SHA-256 value. Duplicate, list-valued or unknown fields refuse before persistence.

The callback must round-trip byte-for-byte as `http://localhost:port`,
the exact IPv4 loopback literal, or `http://[::1]:port`, with explicit port 1024–65535, no userinfo,
fragment, control/backslash, encoded host, parser ambiguity or existing `code`, `error` or `state`
query key. Consent displays the same fixed profile fields as device consent plus the exact callback
host and port. Repeating the exact purpose/callback/challenge/state/label tuple idempotently reuses
its pending intent.

### POST /bfc/loopback/authorize

CSRF-protected form submission with exactly `action=approve|deny` and `submission_nonce` (plus the
framework CSRF field/header), under the 10/minute decision budget. Approval returns `303` to the
exact callback with one-time `code` and exact original `state`; denial returns `error=access_denied`
and that state. Responses are `no-store` with `Referrer-Policy: no-referrer`. There is no pasted-code
fallback. A host CSP containing `form-action 'self'` can block this POST-following redirect; hosts
serving this flow must admit their chosen HTTP loopback origins.

### POST /bfc/loopback/token

Public and CSRF-free. JSON accepts exactly `code`, the byte-identical `redirect_uri`, and an RFC
7636 unreserved `code_verifier` of 43–128 characters. S256, callback equality, current profile and
authority are checked under the authorization row lock. Success has the same bearer shape as the
device token route. Malformed input is `invalid_request`; unknown, wrong callback/verifier, replay
or consumption is `invalid_grant`; expiry, denial and infrastructure failure use the device table
above. The same source and global transport limits apply.

**Disposable client safeguards.** The package's test fixtures include bounded device and loopback
clients. Device proof enters through protected stdin, never argv. The poller waits the greatest of
its current cadence, a returned slow-down interval and `Retry-After`; temporary unavailability uses
a validated 1–30 second header or five seconds. The loopback client binds an eligible random local
port before producing the authorize URL, validates exact callback and state, keeps verifier/state in
memory and exchanges once. Both place only the final bearer in a mode-0600 file under a mode-0700
directory, keep Authorization data off argv, clean temporary material and contain no signing root.

**Honest limits and ownership.** `loopback-local-listener`: local compromise or loopback-port
interception on the approving machine is outside the package boundary. A device code is a bounded
bearer capability for its one approved grant. Lost successful responses cannot be redelivered.
Installation-owned grants and durable credentials do not become personal property of their
initiating approver: removing or changing that approver does not kill them. Fresh connection
inactivity denies a live installation grant but does not revoke an already durable installation
credential; installation-subject removal ends both. Capstan N1 owns replacing its host
models/controllers and composing this wire with its generated installer, fake-crontab behavior and
first domain probe. This package owns safe authorization acquisition and exact-bound use only.

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

- the listing returns only rows whose derived subject **and stored `user_id`** match the caller —
  another local user's rows remain inaccessible even when a declaration maps both users to the
  same subject;
- a mint binds to the session-derived subject, never to a crafted one;
- a revoke acts only inside the caller's own subject and exact stored `user_id`; an id belonging to someone else answers
  **404**, the same answer an id that never existed gets. This is deliberate: a `403` would
  confirm that another user's credential exists, which is a disclosure a `404` does not make.

**Authentication on these routes is the application's session**, not an operator credential or
operator ability. The package mounts them behind its `bfc.auth` gate, which the consuming
application's authenticated human already passes; an unauthenticated request is `401` (or a
redirect to the app's `login` route when it has one and the request does not expect JSON). That
gate is also where an offboarded user's surviving session dies (PRD 1.15), so offboarding a
subject both revokes its credentials and closes this screen to them. Every request rides the
`bfc-personal` limiter (30/min per session principal, 60/min per IP).

**These are BROWSER routes, as is the installation-credentials surface below.** The operator
credential APIs want no session; these three ride the full browser session stack
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

When the declaration explicitly offers `asymmetric`, this same authenticated POST derives
`purpose: "enrollment"`, the `user_principal` subject and the numeric-string `user_id` server-side.
It returns an `enrollment_code` delivery linked to one `pending` row with no public key, secret hash,
or secret ciphertext. This generic personal path is intentionally partial: the package generates
and stores no private key, and the bound signing enrollment route does not accept this unbound
`purpose: enrollment` row. The bounded code and pending row are listable and revocable; revocation
consumes the code so later claim attempts fail. Client-supplied purpose, subject, user, and abilities
fields remain unread.

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

The package also exposes the same personal scope as an HTML settings surface. It uses the same
session-derived subject, `bfc.auth` gate, `bfc-personal` limiter and browser middleware described
above. Issue and rotation responses render the settings page directly so a one-time delivery never
crosses a redirect or enters the session. Each rendered issue and rotation form carries a
server-minted, single-use submission nonce. The server stores only its hash, bound to the session,
authenticated local user, verb and target, and consumes it atomically with the credential mutation.
Responses are `private, no-store`.

### GET /bfc/ui/credentials/personal

Render the caller's credential summaries, declared fields and admitted purpose/kind choices.

### POST /bfc/ui/credentials/personal

Mint for the submitted application purpose and render the single reveal in the response. Success
is **201**; declaration refusals are **403**, invalid input is **422**, and hmac rewrap is **409**.
A missing, expired, consumed, foreign-session, wrong-user, wrong-verb or wrong-target submission
nonce is **409**, with no credential effects and no delivery.

### POST /bfc/ui/credentials/personal/{id}/rotate

Rotate one caller-owned credential and render the single reveal in the response. Success is
**201**, or **200** when completing an interrupted cutover; an id outside the caller's scope is
**404**. The row must still fit the declaration's current self-service kind and ability policy;
otherwise rotation is refused with **403** and no effects. Submission nonce refusals are **409** as
described above.

### DELETE /bfc/ui/credentials/personal/{id}

Revoke one caller-owned credential, then redirect to the personal credential page with **303**.
An id outside the caller's scope is **404**.

## The installation-credentials surface (`/bfc/installation/credentials`)

An authenticated Owner, Admin or Member can manage credentials owned by the
installation rather than by one user. These routes use the host application's browser session
stack, the `bfc-personal` limiter and CSRF validation on mutations. Issuer attribution is audit
data only: every recognized role sees and manages the same installation-owned rows. An unknown
stored role fails closed with **403**.

This surface calls the same unified-store actions described above. Its ownership scope includes
credentials for `application` and `installation` subjects whose `user_id` is null; personal rows
are neither listed nor accepted as rotate/revoke targets. Bearer and basic installation subjects
may carry `system_deployment`, `consumption`, or `mcp`; application subjects remain limited to
`system_deployment`. When the host implements `DeclaresSelfServiceMintPolicy`, its admitted kinds
also constrain the installation HTML and JSON issue and rotation paths. Without that policy, the
installation surfaces retain their existing kind set.

### GET /bfc/installation/credentials

**200** — `{"credentials": [{"…": "a summary row, exactly as on /bfc/credentials"}]}`,
oldest first. The response includes all installation-owned rows and no personal rows.

### POST /bfc/installation/credentials

Mint an installation-owned credential. `subject_type` is required and must be `application` or
`installation`; `subject_ref` and the protocol-valued `purpose` field are required. `purpose` must
be reachable from at least one app purpose in the host's `built-for-cloud.ui.credential_purposes`
list through its configured app-purpose mapping. A supplied purpose outside that displayed list is
refused with **403**, with no row written and no delivery. If the host declares no displayed app
purposes, the HTML surface offers no issue choice and this JSON route refuses every supplied purpose;
omitting `purpose` remains invalid input (**422**) and does not select a default. The optional `kind`,
`name`, `abilities`, `expires_at` and `code_ttl_seconds` fields have the same validation and delivery
semantics as [`POST /bfc/credentials`](#post-bfccredentials). Any supplied `user_id` is not read; the
persisted row is unbound from an individual user.

- **201** — `{"credential": {…}, "delivery": {…}}`, including the single reveal.
- **403** — the role or declaration denies the operation. **409** — hmac rewrap in progress.
- **419** — no valid CSRF token. **422** — invalid subject or credential input.

### POST /bfc/installation/credentials/{id}/rotate

Rotate an installation-owned row by id. Request options, preservation, override, cutover and
delivery behavior match [`POST /bfc/credentials/{id}/rotate`](#post-bfccredentialsidrotate).

- **201** — replacement summary, `superseded_id` and the single-reveal `delivery`.
- **200** — cutover completion, including `completed_cutover: true` and `delivery.shape: "none"`.
- **404** — no installation-owned row with that id; personal-row existence is not disclosed.
- **403**, **409**, **419**, **422** and **500** retain the unified rotate meanings above.

### DELETE /bfc/installation/credentials/{id}

Revoke an installation-owned row by id.

- **204** — revoked, or already dead.
- **404** — no installation-owned row with that id; personal-row existence is not disclosed.
- **403** — the role or declaration denies the operation. **419** — no valid CSRF token.

The installation credential HTML surface uses the same scope and authority policy. Issue and
rotation render the page directly with the single reveal in the immediate POST response. They never
redirect delivery or write secret material to session or flash storage. Every rendered issue and
rotation form carries the shared hash-only, session/user/verb/target-bound, expiring, single-use
submission nonce, consumed in the credential mutation transaction. A missing, expired, consumed,
foreign-session, wrong-user, wrong-verb or wrong-target nonce is **409**, with no credential, audit,
outbox, app-action or onboarding effect and no delivery. Responses are `private, no-store`; GET
responses never reveal secret material.

### GET /bfc/ui/credentials/installation

Render the installation credential summaries and mutation forms with **200**.

### POST /bfc/ui/credentials/installation

Mint and render the single reveal in the immediate response with **201**.

### POST /bfc/ui/credentials/installation/{id}/rotate

Rotate and render the single reveal with **201**, or complete cutover with **200** and no reveal.

### DELETE /bfc/ui/credentials/installation/{id}

Revoke an installation credential, then redirect to the installation page with **303**.

## Subjects — the offboard verb

### POST /bfc/subjects/offboard

*Operator credential holding `subject:offboard`* (its own verb-family
ability — the widest verb, deliberately not granted by `credential:mint` or
`credential:revoke`); the same two-transport rule (`bfc:subject:offboard --local` runs the
identical action). Rate-limited via `bfc-operator-write`.

**Full account containment** (PRD 1.15, SEC-V3-04). Deactivates a subject and, in one
action: revokes EVERY bound credential in EVERY lifecycle state (active, rotation-grace,
and pending — unexchanged enrollments and pending hmac signing keys included); consumes the principal's outstanding
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
exchange documented on the claim envelopes above, and the re-key verb below. One surface stops a
filed key verifying while RETAINING its row, [the retire verb](#post-bfcconsolekeyskey_idretire) —
**no surface in this contract removes a key from the ring.** The retained row is what keeps a
retired key's material permanently unre-filable, because the uniqueness rule below is a rule about
rows that are on the ring. A retirement changes the retired key and **leaves every other key
unchanged** — which is not the same as "every other key keeps verifying", and deliberately not
worded that way: a filed key that is pending, or already retired, goes on doing what it was doing.
*Pinned by* `tests/ConsoleKeyRetirementTest.php` ("retires a filed key over HTTP and stops it
verifying").

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
- **The deployment must already be claimed.** A key names whose delegated assertions this
  deployment verifies, and a deployment with no owner has not decided who that is. `POST
  /bfc/console/re-key` refuses with `409` on an unclaimed instance. The ownership claim is
  exempt by construction: it establishes the owner and files the key in the same transaction,
  in that order.
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

Filing a key installs a standing authority to verify delegated-ADMIN assertions against this
deployment — an assertion mint under it authenticates as a delegated actor on delegated MCP
requests — so each surface answers "who may do this" explicitly:

| surface | authority |
|---|---|
| `POST /bfc/ownership/claim` | the ownership claim code itself. Presenting it already yields an admin owner token in the same response, so naming the console key escalates nothing the holder is not already getting. |
| `POST /bfc/onboarding/exchange` | the code must have been issued with `console_key_authority` (below), and must not have spent it. A routine `scope=consume` code carries none. |
| `POST /bfc/console/re-key` | an operator credential holding **`console:key:write`**, or the `credential:admin` break-glass. `credential:rotate` is **not** sufficient. An app with a declared mint ceiling cannot mint that ability until it names it — see the caveat under [Authentication](#authentication); the owner credential and the CLI verb both work meanwhile. |
| `bfc:console:re-key --local` | **host access.** No credential check — see the CLI paragraph below. |
| `POST /bfc/console/keys/{key_id}/retire` | the same as the re-key: an operator credential holding **`console:key:write`** or the `credential:admin` break-glass. |
| `bfc:console:retire-key --local` | **host access.** No credential check. |

**Retiring is gated the same as filing, and that is a decision.** Ending a signing authority
reads like the more consequential half, and on this ring it is not: whoever can file a key can
activate one of its own, and an assertion minted under it authenticates as a delegated admin on
this deployment's MCP surface, which is more than denying that. A
stricter ability would also have meant no credential already in the field could finish a
rotation without being reissued first — leaving the outgoing key trusted on exactly the
deployments the retire verb exists for.
*Pinned by* `tests/ConsoleKeyRetirementTest.php` ("gates retirement on console:key:write and
refuses every other credential" and "answers one identical refusal to every pre-authorization
failure").

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
working. **Retirement is a separate, later operation** with its own verb,
[`POST /bfc/console/keys/{key_id}/retire`](#post-bfcconsolekeyskey_idretire), performed once every
assertion minted under the outgoing key has expired — which D12 bounds at the deployment's
configured maximum assertion TTL, so the safe wait is short and known. Collapsing activation and
retirement into one call is what turns a rotation into an outage, which is why they are two verbs
and not one flag.

**Retirement is permanent, and nothing brings a key back.** A retired key verifies nothing again;
its bytes cannot be re-filed under a fresh key id (`409`, above); and there is no un-retire verb.
Recovering from a retirement means a freshly generated keypair from the vendor, delivered through
the re-key verb. Plan the order accordingly: file and activate the incoming key, confirm both are
verifying, then retire the outgoing one.
*Pinned by* `tests/ConsoleKeyCustodyTest.php` ("refuses to re-file a retired key's material under
a new key id (AC16)").

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

*Operator credential carrying `console:key:write` or `credential:admin`* — rate-limited as an operator
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

### POST /bfc/console/keys/{key_id}/retire

*Operator credential carrying `console:key:write` or `credential:admin`* — rate-limited as an operator
write (`bfc-operator-write`). Stop trusting one filed key, permanently. This is the second half of
a make-before-break rotation: the re-key files and activates the incoming key and retires nothing,
and this verb ends the outgoing one once every assertion minted under it has expired.

The `kid` rides the path, because the verb acts on a key that already exists — the shape
[`POST /bfc/credentials/{id}/rotate`](#post-bfccredentialsidrotate) uses — where the re-key's flat
body carries a key that does not. A `kid` is bounded to `[A-Za-z0-9._-]`, so it is a path segment
without encoding and can carry no separator.

**Request** — the body is optional. `confirm_last_active_key` is the only field this route
INTERPRETS: `{"confirm_last_active_key": true}`. Anything other than the literal boolean `true` is
read as absence, which is the safe reading; see the last-active-key rule below. Unknown sibling
keys are **ignored, not refused** — compatibility rule 1 runs both ways, so a consumer sending a
field a later release defines is not broken by an older one. Nothing here rejects a body for
carrying more than it needs to.
*Pinned by* `tests/ConsoleKeyRetirementTest.php` ("ignores unknown body fields and reads only the
literal confirmation").

- **200** — `{"console_key_retired": {"key_id": "k1", "status": "retired", "retired_at":
  "2026-08-30T12:00:00+00:00", "newly_retired": true, "active_key_ids": ["k2"]}}`. The key
  verifies nothing from `retired_at` onward. `active_key_ids` is every key id still verifying,
  sorted, and never includes the retired one — an **empty list means nothing verifies and no
  operator can be handed to this deployment** until a fresh key is filed and activated.
- **200 on a repeat** — **this verb is idempotent, and says which call did the work.** Retiring an
  already-retired key answers `200` with `newly_retired: false` and the **original** `retired_at`
  rather than this request's instant. So a client retrying after a dropped connection gets the
  state it asked for and can still tell whether it is what produced it. No second audit event is
  written; one retirement, one event.
- **403** — `{"message": "This request is not permitted to write console countersigning keys."}`
  — **every** pre-authorization failure, byte for byte, exactly as on the re-key verb and for the
  same reason: the `401`/`403` split would tell a caller holding a stolen or stale bearer whether
  it is the credential that can take the deployment. The audit stream keeps the distinction.
- **404** — `{"message": "..."}` — no key with that id is on file. A **malformed** key id answers
  this too: a `kid` outside the documented charset cannot be on the ring, so "that key is not
  here" is both the true answer and the one that keeps unvalidated text out of a second refusal
  path. Nothing was changed.
- **409** — `{"message": "..."}` — **the key named is the last one still verifying, and the
  request did not confirm it.** Retiring it is permitted; arriving at it by accident is what this
  refuses. Nothing was retired. Send `confirm_last_active_key: true` to proceed.
- **429** — beyond the operator write limits.
- **500** — `{"message": "..."}` — a database fault. On a driver that honours the row lock this
  route REQUESTS for the last-active-key decision, a lock-wait timeout is the plausible one, since
  a concurrent retirement holding those rows can time this one out; on a driver that ignores the
  request there is no such wait to time out. Either way the transaction rolled back, nothing was
  written, and retrying is safe.

**What is stable across repeats, precisely.** `key_id`, `status` and `retired_at` are fixed by the
retirement itself and do not move again. **`active_key_ids` is not** — it reports the ring **as of
each response**, so a repeat issued after another key was filed and activated answers a longer list
than the first did. That is the field doing its job rather than drifting: it is what an operator
reads to see what verifies NOW, and a frozen copy of a ring that has since changed would be the
misleading answer.
*Pinned by* `tests/ConsoleKeyRetirementTest.php` ("reports the ring as of each response while the
key id status and retired_at stay fixed").

**Retiring the LAST ACTIVE key: permitted, confirmed, and never by accident.** A deployment with
no key that verifies can verify no assertion, so nobody can be handed to it — and because a
retired key's bytes can never be re-filed, recovery needs a **freshly generated keypair from the
vendor**, not the one just retired. Refusing it outright was the other candidate and was rejected:
a deployment is entitled to stop trusting the vendor's Console, and a surface that refused would
leave no operator path to that at all — which is the gap this verb exists to close, reopened one
key later. So the affirmative confirmation is the whole gate. It bites only where the retirement
would actually end verification: retiring a pending key, or one of two active keys, changes
nothing about whether entry is possible and asks for nothing.
*Pinned by* `tests/ConsoleKeyRetirementTest.php` ("refuses to retire the last key that still
verifies until the request confirms it", "retires the last active key on an explicit confirmation
and says nothing verifies", "asks for no confirmation to retire a pending key or one of two
active keys" and "refuses the second of two sequential retirements once it is the last active
key").

The rule is decided under a row lock this route **requests** over the ring (`SELECT … FOR UPDATE`),
and a request is all it is: what it buys is the DRIVER'S to provide. On one that honours row locks,
two concurrent retirements of the last two active keys cannot each read a ring in which the other
was still verifying. On one that ignores the request, nothing here bounds concurrent retirement at
all. That is a claim about what this route asks the database for — not about what any particular
database then does.

**The audit.** One `revoked` lifecycle event per retirement, in the same transaction as the state
change, with the actor typed and ids only — the key id and what still verifies in the bounded
note, `credential_id` null, and never any key material. It is the same stream the filing half
writes `delivered` and `activated` to, so one rotation reads as one contiguous story; `revoked`
rather than a name of its own because retirement is the only revocation a console key has. A
refused retirement appends `denied_action` naming the reason, and a malformed key id is never
written into a note.
*Pinned by* `tests/ConsoleKeyRetirementTest.php` ("audits one retirement to the lifecycle stream
with the actor typed and no key material", "writes no second audit event when an already-retired
key is retired again", "audits a refused retirement without writing a malformed key id" and
"records nothing when the retirement transaction rolls back").

**The CLI transport** is `bfc:console:retire-key {key_id} --local`, with
`--confirm-last-active-key` where the rule above applies:

```
php artisan bfc:console:retire-key k1 --local
```

It runs the same action and produces the same EFFECT. **It does not have the same authority.**
The command performs no credential check at all: its authority is HOST ACCESS, the same standing
`bfc:console:re-key` and `bfc:create-admin` already have here, and anyone who can run artisan can
write the keyring row through `tinker` anyway. It exits `0` for a retirement and `0` for a repeat
— the state the operator asked for holds either way, and which call produced it is in the printed
line and in `retired_at`, not in the status — and `1` for a refusal.
*Pinned by* `tests/ConsoleKeyRetirementTest.php` ("exits zero for a retirement and for a repeat,
and one for a refusal, on the cli transport").

---

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
four separate conditions:

1. **The credential authenticates through the unified `bfc` guard.** Missing, unknown, expired,
   revoked, offboarded, and non-`dashboard_metadata` credentials all receive the same `401` and
   write no audit event. Purpose is checked before declaration, usage, actor publication, or
   ability inspection.
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

Nothing else opens it. The route authenticates only through the unified credential guard.

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
  "bfc_version": "0.17.0",
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
  or a credential whose purpose is not `dashboard_metadata`.
  All are indistinguishable from one another, and **none of them is audited** — this route is reachable without a
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

## MCP authentication

`AuthenticateMcp` is the plain Laravel middleware alias `bfc.mcp` for an installation-local,
stateless MCP endpoint. The package does not mount that endpoint. A deployment declares the path
it actually mounted with `built-for-cloud.mcp.path` and declares delegated support with
`built-for-cloud.mcp.delegated`; the `mcp-delegated` capability rides that declaration AND the
router-verified fact that `AuthenticateMcp` guards the declared path.

The only carrier is `Authorization: Bearer <credential>`. Dispatch is exclusive by prefix:

- A bearer beginning with `v4.public.` is handled only as a Console assertion. A signature,
  keyring, issuer, audience, clock, TTL, purpose, replay, or containment failure never falls
  through to credential resolution.
- Every other bearer is handled only by `CredentialResolver::resolve()`. It is admitted only for
  purpose `mcp`, except for the bounded operator integration escape
  (`operator_management` + `operator` subject + `credential:admin`). An unknown, expired, revoked,
  or wrong-purpose credential never falls through to assertion verification and reaches no usage,
  client identity, actor publication, or dispatch. When the resolved credential has a non-null
  `user_id`, its package user must still resolve and its current role must pass
  `RolePolicy::canUseProduct()`; an unknown role or an unresolved user receives the same `401`,
  before usage or dispatch. Resolver freshness and offboarding therefore remain the first account
  checks. Ordinary `mcp` credentials publish no admin actor; only the bounded escape publishes
  `bfc.actor_credential_id`.

The optional middleware parameter `bfc.mcp:product` closes that bounded operator escape for a
consumer product endpoint. It still admits purpose-`mcp` credentials and delegated MCP assertions,
but refuses the `operator_management` + `operator` + `credential:admin` compound with the same
reason-free `401`, before usage. Plain `bfc.mcp` deliberately retains the compound for consumers
that use the package's default operator integration behavior. No second alias is registered.

An unbound installation credential (`subject_type=installation`, `purpose=mcp`, `user_id=null`)
runs the immediate downstream pipeline inside `SystemAuthorityContext`. If that pipeline returns a
streamed response, its deferred stream callback runs in a separate system-authority frame. The
context is inactive between those two frames and is released when either normal or streamed work
returns or throws. This is request execution attribution read by `AuditActor`; it grants no ability
or policy permission. It is never activated by this middleware for account-bound credentials,
delegated assertions, or the operator compound.

A deployment whose `built-for-cloud.token_prefix` is configured as `v4.public.` creates a carrier
collision: generated registry tokens would select the assertion path. That is an invalid
deployment configuration, not a fallback code path.

On the assertion path, verification happens first and `purpose` must be exactly `mcp`. The
middleware then commits `DelegatedActor::recordHandoff()` independently so a contained human's
attempt and current claims survive refusal. In the middleware's own database transaction it
inserts the single-use `jti` burn, locks and re-reads that actor, refuses an inactive actor, and
publishes an `ActingPrincipal` on the current request object. Claims come directly from this
verified assertion, never from the actor row's shared `last_handoff_*` fields. No login occurs and
the middleware writes no session key. The resolver's order still applies: the request assertion
outranks a local principal, and identities are
never unioned. The request object is also the scope boundary, so a singleton resolver cannot carry
that principal into the next request.

Every authentication failure answers the same reason-free response, including replay and
containment:

```json
HTTP/1.1 401 Unauthorized
{"message":"Unauthenticated."}
```

**The exercised assertion-refusal BYTES are uniform.** Audience, TTL, purpose, key and signature
failures return the same reason-free `401` JSON body. *Pinned by*
`tests/AuthenticateMcpTest.php` ("uniformly refuses audience ttl purpose key and signature failures
while auditing each reason"). A replay is asserted against the same one-field JSON object. *Pinned by*
`tests/AuthenticateMcpTest.php` ("refuses a replay because its mint is spent and audits the bounded
reason").

**RESIDUE — NOT ESTABLISHED HERE:** response-time uniformity is not tested. A valid, unspent
assertion for the configured deployment is accepted and publishes a request principal; *pinned by*
`tests/AuthenticateMcpTest.php` ("publishes the assertion actor and this handoff claims on the
request"). Audience mismatch is refused by the first citation, and presentation after the mint is
spent is refused by the replay citation. Those controls do not establish that first use of a stolen,
valid, unspent assertion at the deployment it names will be refused.

Assertion-path refusals append `denied_action` to the credential lifecycle stream with one bounded
reason and no presented bytes. The refusal is fail-closed: if that audit transaction cannot commit,
the request answers `500`, not an unaudited `401`. This is the same availability trade as Console
entry; a deployment whose database is unwritable could not commit the assertion burn either.
Credential refusals are not audited here because an application-chosen public MCP route must
not turn anonymous bearer noise into a database-write amplifier.

The middleware removes the credential from the framework request before validation: the
`Authorization` header and the server-bag copies a rich exception reporter serializes alongside a
trace (`HTTP_AUTHORIZATION` and Apache's rewrite copy `REDIRECT_HTTP_AUTHORIZATION`). This prevents
downstream package frames and reporters from serializing it, but does not erase copies made by an
upstream proxy or middleware, web-server access logs that record headers, a raw request buffer
already captured elsewhere, or vendor frames entered before removal. It does not authorize a tool
either: applications still apply their own policy to the assertion role or token.

Consumers can exercise these branches without importing package `User` or `Credential` models by
using `ArtisanBuild\BuiltForCloud\Testing\ContractAssertions` in a database-refreshing feature test
and calling `assertBuiltForCloudMcpProductAdmission()`. The helper mounts random test-only probes
through the application's real `bfc.mcp` and `bfc.mcp:product` middleware, then checks all recognized
account roles, unknown and unresolved accounts with no usage, installation system attribution and
cleanup, and the compound's product/plain split.

A request-scoped delegated actor has no local personal identity. If an application composes
`bfc.mcp` with `bfc.admin`, `bfc.auth`, or `PersonalCredentialSurface`, those local/session-oriented
consumers refuse it through `delegatedSessionPresent()` rather than treating it as a local user.
This is intentional and is a behavior change only on routes that compose those gates with
`AuthenticateMcp`; requests carrying no request assertion retain their prior behavior.

Two further effects on the same composing routes. `EnsureConsoleSession` resolves through the same
shared resolver, so on a route composed with `bfc.mcp` a published request assertion is a delegated
source it can see — its re-entry answer reflects the delegated principal rather than an absent
session. And because the middleware removes `Authorization` — the header and the server-bag copies —
before the pipeline runs, any LATER bearer-reading middleware or bearer-keyed rate limiter on the
same route sees no credential at all. Scrubbing the credential before anything can throw is the
point; anything that still needs the bearer belongs in front of `bfc.mcp`, or keyed on something
other than the credential.

*Pinned by* `tests/AuthenticateMcpTest.php`, `tests/McpProductAdmissionTest.php`,
`tests/ConsoleActingPrincipalTest.php`,
`tests/AuthFoundationTest.php`, and `tests/PersonalCredentialsTest.php`.

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

This sentence is held against what the package's routes REACH, not against how they are spelled.
Every registered route is classified by whether its action can arrive at the event or ledger
tables — through the classes it names in code, transitively, stopping at the one emission door —
so a listing mounted under a name that mentions neither the stream nor auditing is still reported.
What the walk does not cover, as classes rather than as a count: classes outside this package;
names built at runtime, read from config or resolved through a container alias; middleware attached
to a route, and views it renders, neither of which is walked; and closure actions, which have no
class to walk from.
*Pinned by* `tests/AppActionAuditTest.php` ("advertises the app-action emit capability without
promising a way to read the stream", "names a route that reads the app-action stream under a name
that mentions neither", "follows a read one class past the route, and stops at the emission door",
"pins the emission door's public surface, so a verb cannot be ADDED to it unnoticed" and "runs no
read against the stream on either of the emission door's verbs").

### Storage

For each successful emission, one row in `bfc_app_action_events` and one row in
`bfc_app_action_outbox`, written through the audit models' **default Laravel database connection**.
The same-transaction guarantee applies only when the action uses that same connection and is
performed inside the transaction that contains the emission. Two connection names are two
connection instances for this purpose, even when they point at the same physical database.

The recorder neither accepts nor discovers the action's connection. Its transaction guard checks
only the default connection. If the action runs in a transaction on another connection and no
default-connection transaction is open, the emission is refused. If an independent transaction is
already open on the default connection, the recorder writes there and cannot detect the mismatch:
the event and ledger can then commit or roll back independently of the action.

**The two rows are always atomic with each other**, and that is enforced rather than requested: the
pair is written inside a SAVEPOINT within the default-connection transaction, so a failed ledger
insert takes the event row with it before the error reaches the caller. **An app that catches a
recorder failure and commits anyway still cannot end up with an event that has no ledger row.**

**Whether the pair is atomic with the ACTION is the calling application's to arrange**, and this is
the sentence to read before relying on the stream. All the emission point can check is that *a*
transaction is open on the default connection; it cannot tell whether the business write happened
in that transaction or on that connection. An app that commits its invoice update, opens a second
transaction and only then records gets two rows that are atomic with each other and with nothing
else.

**What a consuming app must do to get the guarantee: perform the action and the emission inside ONE
transaction it opened itself, on the default connection used by the audit models.** Do that and a
rolled-back action takes both rows with it, so nothing is ever recorded about something that did
not happen — the stream is transactional, or it is fiction. (Historically the package's own
emitter was the delegated-entry door, retired in v0.17.0, which wrote the entry and its event on
the default connection in one transaction and served no entry it could not record; the
requirement on a consuming app is unchanged.)
*Pinned by* `tests/RecorderTransactionGuardTest.php` ("refuses to record an app action outside a
database transaction" and "refuses a direct model write made outside a transaction").

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
second emission of the same logical action fails the insert and takes the default-connection
transaction — including the action when it meets the same-connection precondition above — with it.
`event_id` is unique too, so "one ledger row per event" is a database property as well.

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
| `actor_ref` | the principal's identifier; for `api_token`, the unified credential id; for a delegated actor, the TYPE-QUALIFIED `bfc-console:{id}` form |
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
own path it originates as an issuer-minted claim, bounded to 120 characters and rejected for
control characters by the assertion verifier: every emission passes the request's one resolved
acting principal. Nothing downstream of that re-checks it, and a consuming app calling the actor
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
- `delegated_actor` — a delegated human admitted through a verified assertion, named by the
  type-qualified `bfc-console:{id}` form and never the bare integer. `bfc_delegated_actors` is an
  ordinary auto-increment table in the same id space `users` occupies, so a bare `7` would read as
  user 7. This is the only actor type that carries `on_behalf_of`.

Attribution, on emissions the package makes during a request, comes from the **one** acting
principal it resolves per request — not from asking a guard, `Auth::` or the request a
second time. On a route guarded by the app's own guard while a delegated principal is also
live on the request, the acting principal is the local user, and that is what the event names.

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

## Console — what has landed, what has been RETIRED, and what is still RESERVED

The vendor-side Console lands in stages, and in v0.17.0 one stage was removed again. This
section says exactly which of its names are real, which were retired, and which are still only
names, so a consumer never has to guess. This section deliberately contains no `### METHOD
/path` route headings — the mechanical route-completeness check covers live routes only, and
the routes named here are documented in their own sections above.

### Landed

- **Console key custody** — [`POST /bfc/console/re-key`](#post-bfcconsolere-key) and
  [`POST /bfc/console/keys/{key_id}/retire`](#post-bfcconsolekeyskey_idretire), plus the
  claim-time key delivery surfaces. Full contract in
  [its own section](#console-key-custody).
- **Table name `bfc_delegated_actors`** — the delegated-actor (shadow actor) table EXISTS and
  is RETAINED for delegated MCP authentication. It is **not** a `users` table: no password
  column, no remember-token column, no login path, and no credential can resolve to one — the
  `bfc-console:` identifier namespace is RESERVED and is refused before any credential's bound
  `user_id` reaches a user provider. A delegated principal's identity is **type-qualified**
  (`bfc-console:{id}`) so it can never collide with a `users` id, and the identifier suffix
  must be a canonical positive decimal. Actor identity is the **digest of a length-delimited
  issuer+subject encoding**, not a collated comparison of two text columns, so two subjects
  differing only in case are two humans on every database. Rows are never pruned — they are
  the referent of delegated audit attribution.
- **Delegated MCP authentication** — the `bfc.mcp` middleware accepts a purpose-bound
  delegated assertion as a bearer, records or refreshes the delegated-actor row, burns the
  mint, and publishes the delegated principal for that one request. Full contract in
  [its own section](#mcp-authentication).
- **Console vitals** — [`GET /bfc/console/vitals`](#get-bfcconsolevitals), the
  `metadata`-classified read behind `metadata:read`. Full contract in
  [its own section](#console-vitals).
- **The app-action audit stream's schema and emission** —
  [above](#the-app-action-audit-stream).

### Retired in v0.17.0

Console entry is retired. The following are REMOVED, not disabled: `POST /bfc/console/enter`,
`GET /bfc/console/chrome.js` and the chrome/layout re-entry machinery, the `bfc-console`
delegated-session guard and its provider, the `bfc.console` middleware alias, the
delegated-SESSION behaviour of the package's session gates, the `console-guard`,
`console-enter` and `console-chrome-assets` capabilities, and the
`BUILT_FOR_CLOUD_CONSOLE_ENABLED` / `BUILT_FOR_CLOUD_CONSOLE_REENTRY_URL` configuration. No
migration runs and existing `bfc_delegated_actors` rows are untouched — the table now serves
delegated MCP authentication only. Managed sign-in is the only door into an app.

### Still RESERVED (not implemented)

Nothing in the `/bfc/console/*` namespace is a reserved name: `re-key`,
`keys/{key_id}/retire` and `vitals` are live routes, documented above. The app-action audit
stream's **read transport** has not landed, and is not a name this contract offers. Everything
else Console-related — the switcher and its roster, the fleet dashboard — remains held behind
the Console PRD's decision D6, and **no roster claim exists in the assertion vocabulary**.
