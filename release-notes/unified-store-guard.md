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

For asymmetric custody, `Credential::activePublicKeysFor($subjectType, $subjectRef)`
returns every active public key enrolled for a subject — the verification
side of a keypair the client generated and keeps.

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
credential rows whose plaintext lives only in test memory:

```php
$minted = $this->mintCredential(['abilities' => ['credential:read']]);

$this->actingAsCredential($minted)->getJson('/api/thing')->assertOk();
// or present it explicitly:
$this->getJson('/api/thing', ['Authorization' => $minted->bearerHeader()]);
```

No plaintext is ever persisted, logged, serialized, or returned by any HTTP
surface. Minting, rotation and revocation verbs land in later releases,
after the sealed secret carrier exists.
