# The unified credential store and the one guard

This release introduces the framework's unified credential store — the
`credentials` table and `Credential` model — and a Laravel auth guard
(driver `bfc`) that authenticates requests against it. Both coexist with the
legacy `api_tokens` machinery, which is unchanged; apps migrate onto the new
store in later releases.

## The store

Every credential row carries:

- **`kind`** — how it authenticates: `bearer` (Authorization header),
  `basic` (HTTP Basic, the Composer `auth.json` shape — the password half is
  the secret), `asymmetric` (public-key custody), or `hmac`
  (schema-supported now; its crypto ships later).
- **`subject_type` + `subject_ref`** — what one revocation costs, and the
  tenant partition key. Tenancy lives in `subject_ref`. Subject types:
  `application`, `installation`, `user_principal`, `external_consumer`,
  `operator`.
- **`name`** — a decorative, nullable, freely editable, **non-unique**
  label. Renaming a credential changes nothing about authentication or
  identity, and two credentials of the same name coexist and authenticate
  independently. Nothing keys tenancy or authority on a name.
- **`abilities`** — a nullable JSON list of ability strings. Null grants
  nothing.
- **`user_id`** — an optional binding to a host-app user, stored as a
  stringified id (the package does not know your user key type).
- **Secrets at rest are sha256 hashes only** (`secret_hash`). An
  `asymmetric` row stores a `public_key` and a NULL `secret_hash`; the model
  throws if you try to persist secret material on one, and there is no
  column anywhere for private keys.
- **Lifecycle** — `status` (`pending` / `active`), `revoked_at`,
  `expires_at` (nullable; the package never applies a default TTL),
  `last_used_at`.

Bearer and basic secrets are **framework-generated high-entropy values**
hashed sha256 at rest — the package's existing `token_hash` idiom. The
store is not a password store: human-chosen passwords are out of contract,
which is why a fast digest (not bcrypt/argon) is the right hash for these
secrets.

For asymmetric custody, `Credential::activePublicKeysFor($subjectType, $subjectRef)`
returns every active public key enrolled for a subject — the verification
side of a keypair the client generated and keeps. The model enforces
"public keys only": private-key material (PEM private / encrypted-private
markers) is rejected in the `public_key` column on every kind, and an
asymmetric row's public key must actually parse as one
(`openssl_pkey_get_public`). **Known limitation:** these checks live on the
model's `saving` hook — raw query-builder writes bypass them. The model is
the package's enforcement point; every framework code path persists
credentials through it, and consuming apps should too.

## The guard

Register a guard on the `bfc` driver and point routes at it:

```php
// config/auth.php
'guards' => [
    'web' => ['driver' => 'session', 'provider' => 'users'],
    'bfc' => ['driver' => 'bfc', 'provider' => 'users'],
],

// routes
Route::middleware('auth:bfc')->get('/api/thing', ...);
```

`bearer` and `basic` presentations resolve by hash against active,
unrevoked, unexpired, non-pending rows. A valid presentation stamps
`last_used_at`. A user-bound credential resolves your user as the request
principal; an unbound credential is its own principal. Expired, revoked,
pending, unknown and malformed presentations are all the same
indistinguishable 401.

**The guard never accepts `FALLBACK_TOKEN`** (or any other env
pseudo-credential). There is no code path from the `bfc` guard to
`built-for-cloud.fallback_token`; only the legacy `TokenRegistry` retains it
for legacy consumers, until its retirement lands.

## The session/token precedence matrix

The guard ships explicit, tested precedence semantics:

- **Token-guarded routes reject session-only callers.** A logged-in session
  with no credential is 401 on a `bfc`-guarded route.
- **On token routes, the credential principal and its abilities are
  authoritative.** A simultaneously present session neither adds nor widens
  anything.
- **Mismatched simultaneous principals are rejected.** A request carrying
  both a session user and a credential bound to a different user is 401,
  never silently resolved to either.
- **Session routes never consume a bearer implicitly.** A session-guarded
  route authenticates by session; a bearer riding along is ignored and its
  `last_used_at` is not stamped.

### The session-vs-session row: an AMENDMENT to SEC-V3-10

The reserved Console row is now **implemented**, and this is an **amendment
to the v3.1 matrix invariant SEC-V3-10, not an additive slot-in**. SEC-V3-10
shipped as a token-vs-session rule with a **singular**
`built-for-cloud.credentials.session_guard` key whose whole job is rejecting
mismatched principals. The Console makes the matrix **session-vs-session**
as well, and that is a change to the invariant's shape — a reader of the old
statement would conclude the matrix has one session guard in it, and after
this release it has two.

- **On a request carrying both a local `web` session and a delegated
  `bfc-console` session, the delegated guard wins** — for the acting
  principal AND for all UI/attribution branching, never a union, never
  decided by the order two middlewares were listed in.
- That row is **not** decided by the `bfc` credential guard, and it is not
  decided by a package-owned repoint either. It is decided by **the route's
  own guard**: a delegated route carries Laravel's `auth:bfc-console`, which
  makes the console guard the guard of that request, so `$request->user()`,
  `Auth::user()`, `Gate` and `ArtisanBuild\BuiltForCloud\Console\
  ActingPrincipalResolver` all end at the same guard and return the same
  object.

  This package writes no process-global auth state itself — it never
  calls `AuthManager::shouldUse()` and never sets `auth.defaults.guard`
  — but `auth:bfc-console` does, because that is what Laravel's own
  `Authenticate` middleware does for `auth:web` and `auth:api` too:
  `shouldUse()` → `setDefaultDriver()` → a write to
  `config('auth.defaults.guard')`. The write is real and process-global
  for the life of the config repository. It does not survive the request
  on either supported runtime, by two different mechanisms. **PHP-FPM**
  is not process-per-request — a worker serves many, bounded by
  `pm.max_requests` — but PHP tears down all userland state at request
  shutdown, so the container and the config repository are rebuilt and
  `auth.defaults.guard` is re-read from config every time. **Octane**
  does reuse userland state, and installs a per-request clone of the
  config repository instead
  (`Laravel\Octane\Listeners\CreateConfigurationSandbox`, on every
  `RequestReceived`). Octane's `FlushAuthenticationState` is NOT what
  closes it — it only forgets resolved guards — so do not check that
  listener and conclude otherwise.

  **If you run this package on anything else**, the assumption to check
  is precise: a runtime that reuses a container across requests without
  sandboxing config will leave the default guard pointed at
  `bfc-console` after the first delegated request, and later requests on
  ordinary routes will resolve their principal through the delegated
  guard. `tests/ConsoleGuardScopingTest.php` asserts both halves — that
  the leak is real without a config sandbox, and that the clone is what
  closes it.
- **A delegated actor is never the other half of a mismatch.** The
  credential guard compares a credential's `user_id` — a stringified
  host-app user id — against the session principal. A delegated actor's
  identifier is type-qualified (`bfc-console:{id}`) precisely so it can
  never equal one, so comparing them could only ever produce a FALSE
  mismatch. An app that points `credentials.session_guard` at `bfc-console`
  therefore gets "no comparable local principal", not a 401 on every token
  route.
- **No credential resolves a delegated actor.** The `bfc-console:` identifier
  namespace is RESERVED: a credential whose `user_id` sits inside it is
  refused **before any user provider is asked**, because what an ordinary
  Eloquent provider does with `bfc-console:1` over an integer key is
  driver-defined (MySQL coerces toward `0`, PostgreSQL raises), not a lookup
  that safely fails. A returned delegated actor is rejected as well, and the
  resolved principal must emit exactly the identifier the credential stored.
- **Every previously shipped cell is unchanged**, and its tests are
  unchanged: `tests/CredentialPrecedenceTest.php` runs the whole matrix with
  both session guards configured.

### What this changes for a consuming app

**Nothing, unless you enable the Console.** `built-for-cloud.console.enabled`
defaults to `false` and gates the whole feature: the delegated guard is not
registered, the reserved provider name is not claimed, `GET /bfc/meta` does
not advertise `console-guard`, and the gates below behave exactly as they did
before. Upgrading the package cannot change how an app authenticates, and
cannot stop it booting.

With the Console ENABLED, two package gates behave differently once a
delegated session can exist. Both follow from D14's one resolved value, both
are tested, and the two directions are deliberately asymmetric —
**admission is exact, refusal may be broad**:

- **`bfc.admin` now admits a delegated operator whose handoff carried
  `role=admin`** — but only on a route the console guard actually governs
  (one carrying `auth:bfc-console`), so the principal the gate authorizes is
  the principal `$request->user()` returns behind it. Admitting on one
  identity while the request acts as another is the confused deputy, and it
  is the one outcome that must never happen. A delegated `member` is refused;
  a delegated session on a route the console guard does NOT govern is
  refused too, rather than falling back to a local admin's standing. Local
  users are unaffected: the `is_admin` attribute check and the offboarding
  containment check are unchanged.
- **`bfc.auth` now REFUSES a delegated session with a 403** instead of
  falling through to the local session user, whichever guard the route
  names — and so does `PersonalCredentialSurface` itself (it is public API
  an app's own screen may call without the middleware). A delegated actor
  has no personal credentials in this app, and minting or revoking a local
  human's credentials while somebody else is acting is the bug that refusal
  exists to prevent. Refusing more broadly than strictly necessary costs
  only convenience, which is why this direction is allowed to be blunt.

A **refused** delegated session is terminal: `bfc.auth` answers 401,
`bfc.admin` answers 403, and the personal-credentials surface throws — none
of them falls back to the local user.

**Starting and ending a delegated session.** `ConsoleGuard::redeem()` is
the one operation that mints one **through this package**, and it takes
the **signed assertion bytes** and verifies them itself — there is no
method that accepts an assertion object and none that logs a delegated
actor in on request. `setUser()` supplies an unverified in-request
principal and directly persists nothing; note that the inner guard
dispatches `Authenticated` synchronously from it, so a host listener
could persist something of its own, which reduces to the session-writer
boundary named below. It compensates on failure: if anything throws after the session
write begins — a host application's `Login` listener, most plausibly —
the session is destroyed before the failure propagates, because Laravel
writes and regenerates the session *before* it dispatches that event.
If the compensation itself fails (an unreachable session store), the
ORIGINAL failure is still what the caller sees; the compensation failure
goes to the application's exception handler rather than replacing it. A
later request finds no delegated identity even then — the compensation's
in-memory flush precedes the store I/O that failed, and the session id
the browser is handed was regenerated before the failure, naming a record
that was never written. What is not guaranteed in that case is that a
record predating the request is destroyed; it survives under its own id
carrying what it carried before, which is not a delegated identity.
*Pinned by* `tests/ConsoleRedemptionTest.php` — "surfaces the original
failure, not the compensation failure, when the session store is
unreachable", "leaves a later request unauthenticated when the store
recovers before the response is saved", and "…when the store is still
down at save time".

The residue, stated rather than glossed: code that can write the session
store directly can assemble a delegated session, because that is what
writing those keys means. That is not a credential or a login path. The
claim held is narrower and exact — **no package API assembles a
delegated session without verified assertion bytes** — and the guard
additionally requires the session to name the principal, so the public
`setUser()` seam the `Guard` contract forces cannot be combined with
hand-written claims to act as a delegated admin.
*Pinned by* `tests/ConsoleRedemptionTest.php` — "offers no public way to
write a delegated session's claims" and "does not authenticate a
principal handed to setUser, even alongside hand-written claims", whose
positive control pins the residue itself.
`ConsoleGuard::logout()` ends a session without calling the framework's
`SessionGuard::logout()`, deliberately: that method sets a sticky
`loggedOut` flag on a guard the auth manager caches for the life of the
process, which would leave the guard dead for every later request in a
long-lived worker.

**Mounting a console route.** Put `bfc.console` IN FRONT of
`auth:bfc-console`. The framework's middleware is what makes the console
guard that route's guard; `bfc.console` is what turns an absent or refused
session into the structured re-entry 401 (`BFC-Console-Reentry: 1`) that a
chrome interceptor can branch on, rather than a generic `401`. The absolute
assertion-age cap does not depend on either: it lives in the guard, so it
holds on every route that reads it, including ones with no console
middleware at all.

An app that wants its own delegated-guard arrangement can define
`auth.guards.bfc-console` itself; the package then injects nothing. The
provider name `bfc-console-actors` is reserved, and — when the Console is
enabled — an app that has taken it for something else without defining its own
guard fails boot with an explanatory exception rather than getting a delegated
guard backed by its `users` table.

## Abilities middleware

`bfc.ability:<ability>` requires the authenticated credential to hold an
explicit ability, and **fails closed**: null or empty abilities are denied
everything, and registering the middleware without an ability string throws.

```php
Route::middleware(['auth:bfc', 'bfc.ability:credential:read'])->get(...);
```

## Executable app declarations

An app's declaration is a class the framework calls, not metadata. Implement
`ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration`
(`resolveSubject(...)` and `authorize(...)`) and register it via the
`built-for-cloud.credentials.declaration` config key or a container binding.
The guard calls `authorize` on every credentialed request (403 on deny, even
for an otherwise-valid credential), and the abilities middleware calls it
again with the required ability. A credential's `subject_ref` is an input to
that decision, never the check itself. A default declaration ships, so the
package works out of the box.

## Test ergonomics

The `ArtisanBuild\BuiltForCloud\Testing\WithCredentials` trait mints
credential rows whose plaintext lives only in test memory. The returned
carrier is sealed: it refuses PHP serialization and JSON encoding (both
throw), has no string conversion, and holds the plaintext outside the
object, so native export and debug paths (`var_export`, `print_r`,
`var_dump`, `get_object_vars`) show no secret either — queued payloads,
cache writes and object loggers cannot carry it out of the test:

```php
$minted = $this->mintCredential(['abilities' => ['credential:read']]);

$this->actingAsCredential($minted)->getJson('/api/thing')->assertOk();
// or present it explicitly:
$this->getJson('/api/thing', ['Authorization' => $minted->bearerHeader()]);
```

No plaintext is ever persisted, logged, serialized, or returned by any HTTP
surface. Minting, rotation and revocation verbs land in later releases,
after the sealed secret carrier exists.
