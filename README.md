# Built for Cloud

Shared building blocks for administering **cloud-first Laravel applications from the
[Laravel Cloud](https://cloud.laravel.com) CLI** — no admin UI required.

These are the pieces that several Artisan Build apps (Matte, Hone, …) need in common: things you
manage by running an Artisan command in your production environment and reading its output back on
your machine. The package started with **API token management** and now also provides a shared
**auth foundation** for apps that need an identical user/admin/invitation story.

> **Status:** the initial `0.x` release is being finalised. The package follows semantic versioning;
> pin to a version range you have tested.

## Installation

```bash
composer require artisan-build/built-for-cloud
```

The service provider is auto-discovered. Publish the config if you want to tweak it:

```bash
php artisan vendor:publish --tag=built-for-cloud-config
```

### Session drivers

Built for Cloud supports Laravel's non-database session drivers, including `cookie`, `redis`, `file`,
and `array`. Laravel Cloud injects `cookie` by default, and `redis` is the recommended step up when a
more robust session store is needed. The package refuses to boot with `database` sessions because
they are intended for local development and hobby sites and cannot safely store delegated Console
actor identifiers in Laravel's numeric `sessions.user_id` column.

## API tokens

Tokens are stored **hashed** in an `api_tokens` table (this package ships the migration). A token
resolves only while it is unexpired; everything else about it — usage counts, rotation, revocation —
is metadata around that one rule.

| Concept | Behaviour |
| --- | --- |
| **Resolution** | A presented bearer token matches a row by `sha256` hash and resolves only when `expires_at` is `null` or in the future. That single check is the whole gate. |
| **Rotation** | Issues a new secret for the same logical token and lets the old one keep working for a **1‑hour grace window** (zero-downtime). `--emergency` kills the old secret immediately. |
| **Revocation** | Stops a token resolving immediately and records *why* (`revoked_at`) for the audit trail. |
| **Usage** | Each token tracks `last_used_at` and a request counter. Consuming apps can attribute their own records (e.g. jobs) to the resolving token. |

### The fallback token

A single plaintext **fallback token** can be read straight from the environment (`FALLBACK_TOKEN`).
Any caller presenting it authenticates without a database row — handy for bootstrapping a fresh
install or wiring up internal apps quickly.

It is deliberately low-ceremony and **not meant for production workloads**: delete it from the
environment to disable it, and provision per-app database tokens instead. When `FALLBACK_TOKEN` is
absent, fallback authentication is off entirely.

### Client identity

A BfC client app (`artisan-build/bfc-client`) sends a stable `X-BfC-Client-Id` header alongside the
bearer credential it already authenticates with. This package records that value on the unified
`credentials` row that authenticated, so a control plane can attribute a credential to a client install.

| Rule | Behaviour |
| --- | --- |
| **Shape** | Valid UTF-8, **1–255 bytes** (bytes, not characters), no CR, LF or NUL, exactly one header value. |
| **Opaque** | Compared byte-wise and stored **verbatim** — no trimming, normalising, case-folding or truncation. |
| **Not a credential** | It grants nothing. A credential without the route ability still gets `403`; a request with no bearer credential still gets `401`. |
| **Untrusted text** | It is opaque, attacker-controlled text of up to 255 bytes, and it is readable through credential surfaces — anything rendering it into HTML, a terminal or a log must escape it itself. |
| **Non-fatal** | A header that violates the contract is logged (never its value — it is attacker-controlled) and dropped. The request proceeds exactly as it would have. |
| **Storage** | `credentials.client_identity`, plus `client_identity_last_seen_at`, bumped on **every** valid presentation, not only on change. A changed identity overwrites — last writer wins. |

Rejecting NUL is a deliberate **server-side narrowing** of the shipped client contract, which
permits it: PostgreSQL truncates a bound value at the first NUL silently rather than erroring, so
accepting one would mean the stored identity differing from the presented one on some drivers —
and would let two distinct identities collide on a single row.

The single-value rule is enforced only where the server preserves header multiplicity (Octane,
Swoole, RoadRunner); under PHP-FPM or Apache, repeated header lines are folded into one
comma-joined value before PHP sees it, and that folded value is stored as the opaque string it
arrives as.

It is **forward-only**: the migration adds nullable columns and backfills nothing. Existing tokens
stay `null` until a client actually presents a header, and a request without the header leaves a
stored identity untouched.

### Observing clients with no working credential

The Yellow state: **something calling itself client X is reaching us and its credential does not
work** — expired, revoked, wrong, or absent entirely. When enabled, a request to a token-guarded
route that presents a contract-valid `X-BfC-Client-Id` and **authenticates nothing** records that
claimed identity in `bfc_client_identity_observations`.

> **This signal is advisory and spoofable.** A claimed identity on an unauthenticated request is
> not proof of anything — anyone can send any header, and nothing verified who sent it. Treat a row
> here as "worth a look", never as "client X is present". It grants nothing and never influences
> authentication. The endpoint says so in its own payload so a consumer cannot miss it.

**It is off by default, deliberately.** This is a database write driven by an *unauthenticated*
request, and the `bfc.token.admin` routes carry no `throttle:` middleware. A provider opts in with
`BUILT_FOR_CLOUD_OBSERVE_UNAUTHENTICATED=true`; no consuming app inherits it by upgrading.

**Know what you are turning on.** With observation enabled, a claim with no bearer token costs about
three extra database operations (a keyed update that matches nothing, a count against the cap, an
insert), and a claim with an unknown bearer about five in total once token resolution is included —
on routes that carry **no `throttle:` middleware**. Put rate limiting in front of these routes before
enabling this in production.

| Rule | Behaviour |
| --- | --- |
| **What counts** | Only the genuine no-credential paths: no bearer token, or a bearer that resolves to nothing (unknown, expired, revoked). |
| **What does not** | A `403` — that caller *has* a working credential and merely lacks the admin scope. Nor the fallback token, which authenticates. Neither is observed. |
| **Malformed headers** | A contract-violating value — too long, CR/LF/NUL, invalid UTF-8, empty — is dropped and never observed, and deliberately **not logged** on this path, since it is unauthenticated and unthrottled. |
| **Repeat claims** | Increment `observation_count` and bump `last_seen_at`. `first_seen_at` never moves — it is the earliest signal. |
| **The cap** | `BUILT_FOR_CLOUD_MAX_OBSERVATIONS` (default `100`) caps the number of **distinct** identities stored. It is enforced **per request, not atomically** — concurrent requests can each pass the check and briefly overshoot it. An approximate ceiling, not an exact one. |
| **At the cap** | A **new** identity is dropped; existing rows still update. **Nothing is evicted** — otherwise anyone spraying unbounded distinct identities could push the genuine client out. |
| **Never fatal** | The write is best-effort. If it throws, the caller still gets exactly the `401` it was already going to get — silently, with no log line, since this path is unauthenticated and unthrottled. |
| **Byte-exact** | Rows are keyed on a sha256 digest of the identity's exact bytes, so `client-a` and `CLIENT-A` stay distinct even on a case-insensitive database collation. |

Repeated header lines are **not** among the malformed cases in a typical deployment. As in the
section above, the single-value rule is enforced only where the server preserves header multiplicity
(Octane, Swoole, RoadRunner); under PHP-FPM or Apache the lines are folded into one comma-joined
value before PHP sees it. That folded value is contract-valid and byte-indistinguishable from a
legitimate identity that really is `a, b`, so it **is observed**, as the single opaque identity it
arrives as. There is no correct behaviour available at the PHP layer.

#### `GET /bfc/client-observations`

Always present with the BfC HTTP surface and guarded by an operator credential carrying exactly
`credential:read` (or `credential:admin` break-glass). Rows are ordered by `last_seen_at`, **most
recent first**. The configurable `{prefix}/client-observations` route remains a transitional alias
while the legacy credential API is enabled, but uses the same unified gate.

```json
{
  "enabled": true,
  "advisory": true,
  "spoofable": true,
  "note": "These identities were claimed on requests that presented no valid credential; ...",
  "at_capacity": false,
  "max_observations": 100,
  "observations": [
    {
      "client_identity": "...",
      "first_seen_at": "2026-08-24T10:28:08.000000Z",
      "last_seen_at": "2026-08-24T11:02:41.000000Z",
      "observation_count": 3
    }
  ]
}
```

`enabled` is present in both states: when the feature is off the endpoint still returns `200` with
an empty `observations` list rather than a `404`, so a control plane can tell **"off"** from **"on
and nothing seen"**. `at_capacity` tells it **"no new clients are being recorded"** apart from **"no
new clients exist"** — silent truncation otherwise reads as complete data. The identity is the same
opaque, attacker-controlled text as everywhere else: escape it before rendering.

### Listing tokens

`GET {prefix}/` — where `{prefix}` is `built-for-cloud.credential_api.prefix`, default
`api/credentials` — returns a JSON array of token rows, **ordered by `created_at`, oldest first**.
The endpoint is guarded by the `bfc.token.admin` middleware: no bearer token is `401`, a token
without the admin scope is `403`.

Every row has exactly these seven keys, always present:

| Key | Type | Notes |
| --- | --- | --- |
| `name` | `string` | The logical token name. |
| `last_used_at` | `string\|null` | ISO-8601 with microseconds, UTC — e.g. `2026-08-24T10:28:08.000000Z`. |
| `expires_at` | `string\|null` | Same format. `null` means it never expires. |
| `revoked_at` | `string\|null` | Same format. |
| `abilities` | `string[]` | `[]` when the token has none — never `null`. |
| `client_identity` | `string\|null` | The opaque client identity, **verbatim**. `null` means no client has ever presented this token. |
| `client_identity_last_seen_at` | `string\|null` | Same format as the other timestamps. `null` whenever `client_identity` is `null`. |

The secret never appears: neither the plaintext token nor its `token_hash` is part of a row.

The two `client_identity` fields are **additive and nullable** — they were added after the first
five. A consumer validating this response strictly should permit them rather than reject the row,
and must treat `null` as meaningful (no client has ever presented that token) rather than coercing
it to an empty string.

## Administering from the Cloud CLI

Token administration is designed to be driven from your machine against your deployed environment.
Each command resolves the target environment by asking Cloud for the application's environment list
(using a single one automatically, prompting when there is more than one), then runs the work in
production via the Cloud CLI and brings the output back to you.

Secrets never leave your machine: a new token's plaintext is generated locally and shown once — only
its hash is sent to production, so plaintext never lands in retained command output.

```
php artisan token:create <name>      # issue a new per-app token (plaintext shown once)
php artisan token:rotate <name>       # rotate, with a 1h grace window (--emergency to cut over now)
php artisan token:revoke <name>       # revoke immediately
php artisan token:list                # list tokens and their status
php artisan token:usage [<name>]      # show usage for a token (or all)
```

### Ownership bootstrap and recovery

An unclaimed environment mints a one-time ownership claim token during migration and writes the
plaintext to the log exactly once. When that log line is gone — or a still-owning control plane has
lost its admin owner token — these two commands are the way back in. Both follow the same
driver/execute split as the token commands: the plaintext is generated and shown on your machine,
and only its hash travels to production.

```
php artisan bfc:ownership:mint-claim            # re-mint a pending claim (UNCLAIMED environments only)
php artisan bfc:ownership:remint-owner-token    # re-issue the current owner's admin token
```

`mint-claim` refuses with a non-zero exit when ownership is already claimed, so it can never be used
to take an environment away from its owner; exchange the token it prints at `POST /bfc/ownership/claim`
as usual. `remint-owner-token` requires ownership to already be claimed, keeps the same owner, and
revokes the previous owner token as it issues the replacement. It is console-only by design — there is
no HTTP route that re-issues an owner token.

Run either half directly against a deployed environment if you prefer to drive the Cloud CLI yourself,
passing the hash of a token you generated locally:

```
cloud command:run <env> --cmd "php artisan bfc:ownership:mint-claim --execute --hash=<sha256>"
```

## Auth foundation

Built for Cloud owns the canonical `ArtisanBuild\BuiltForCloud\User` model and the fresh-install
`users` migration. A supported host does not define `App\Models\User` or a users migration. The
service provider registers the package model on Laravel's normal `web` session guard and `users`
Eloquent provider, including when a headless host declares neither entry. A conflicting materialized
human model, provider, selected guard, or `web` guard fails during boot instead of being used.

The local database primary key is stable attribution. Domain packages receive its string form only
through `Contracts\IdentityContext`, together with closed role decisions, authority mode/generation,
credential ownership, and the same-actor-or-Admin/Owner helper. `DomainIdentityContext::forUser()`
derives the opaque actor ID only from the canonical database primary key. That interface carries no
Eloquent, guard, hash, credential ID, or token-display types.

The package migration stores unique email, nullable password, `owner`/`admin`/`member` role, human
status, trusted Scalpels issuer/connection/subject provenance, original contact email, generated-email
state, and timestamps reserved for later managed-membership freshness behavior. External provenance is
either fully null or fully populated, and fully populated triples are unique at the database boundary.
It also creates one structurally guarded `bfc_authority` row in `standalone` mode at generation 1.
`InstallationAuthority::change()` is the non-Eloquent write API; it advances that generation with a
compare-and-set update and returns the exact state it wrote, so stale writers cannot change authority.

### Role policy

`RolePolicy` implements only the frozen coarse policy:

| Role | Use product | Manage Members | Manage Admins | Initiate mode transition |
| --- | --- | --- | --- | --- |
| Owner | yes | yes | yes | yes |
| Admin | yes | yes | no | no |
| Member | yes | no | no | no |

Unknown role or authority-mode strings deny every context decision. `bfc.auth` also rejects inactive
canonical users and persisted unknown roles. A database-generated unique owner slot prevents a second
Owner through model, bulk, or raw writes. Installation-owned credentials receive no human-role product,
membership, Admin, transition, or same-actor authority in this foundation. No destructive/configuration
policy or custom permission system is implied.

### Create the first admin

The legacy shared command creates the initial Owner in the package model:

```bash
php artisan create-admin --email=admin@example.com --password=secret --name="Admin"
```

Once an Owner exists, the command refuses by default. Pass `--force` to create an Admin; it never
creates a second Owner:

```bash
php artisan create-admin --email=ops@example.com --password=secret --name="Ops" --force
```

When an option is omitted, the command prompts for it using Laravel Prompts.

The command requires the package `role` column. Its command name is retained as legacy residue until
the standalone lifecycle slice replaces initial-owner and membership-management flows.

### Standalone membership

In standalone authority mode the package owns login, password recovery, addressed invitations,
membership actions, and session management under `/bfc/*`. Every route carries the
`bfc.standalone` authority gate; managed installations receive `404` before local authentication,
writes, or mail. Mutating browser routes use Laravel's web session and CSRF protection.

Password-reset and invitation links enter through stateless bearer handoff routes. Those routes
exclude Laravel's `StartSession` middleware, set a short-lived encrypted cookie, and redirect to a
clean session-backed form URL. Hosts may add session middleware to route groups, but must not put
`StartSession` or a subclass in the global HTTP kernel: global middleware executes outside Laravel's
route-level exclusion and is not a supported package configuration.

Owner and Admin may invite a Member, while only Owner may invite an Admin. Issuance stores only a
SHA-256 digest of a bounded, single-use token and sends the acceptance link through the configured
Laravel mailer. Acceptance creates the canonical package user with the addressed email and the role
fixed at issuance; request-supplied identity, role, status, provenance, and off-site redirects are
ignored. The supported invitation entry points are:

- `GET /bfc/invitations/{token}` for the stateless handoff, then `GET` and `POST /bfc/invitations/accept` for acceptance.
- `POST /bfc/members/invitations` for Owner/Admin issuance.
- `GET /bfc/members`, `PUT /bfc/members/{user}/role`, and `DELETE /bfc/members/{user}` for membership management.

`Invitation` remains the persisted model. Its query scopes are available for reporting and
housekeeping, but invitation creation and acceptance run through the package actions and routes:

```php
Invitation::pending()->get();
Invitation::accepted()->get();
Invitation::expired()->delete();
```

### Middleware aliases

The service provider registers route middleware aliases:

| Alias | Behaviour |
| --- | --- |
| `bfc.auth` | Requires an authenticated user. JSON requests receive `401`; browser requests redirect to a `login` route when one exists, otherwise `401`. |
| `bfc.admin` | Requires a package Owner/Admin, while retaining the existing delegated-console branch; otherwise `403`. |

Use them in the consuming app's routes:

```php
Route::middleware('bfc.auth')->group(function () {
    // signed-in users
});

Route::middleware('bfc.admin')->group(function () {
    // Owner and Admin only
});
```

Consuming applications must not redefine the package's `bfc.*` middleware aliases or groups,
attach or exclude package gates on package routes, re-register package routes, or reshape them from
a route listener. The package fails closed where it can; behaviour is undefined where it cannot.

### Thin-host conformance

`ContractAssertions::assertBuiltForCloudContract()` verifies the package model configuration and
identity/authority schema. `assertBuiltForCloudThinHostSources($hostRoot)` additionally reports
conventional app-owned `User`, users migration, auth controller/UI, and token-command paths.

The source check is intentionally a path-pattern drift detector. It does not prove arbitrary PHP
cannot implement auth indirectly, inspect generated runtime code, or establish fleet-wide
completeness. The package suite includes both an artifact-free thin Testbench host and a rogue
positive control for every advertised source classifier, the configuration scanner, and the
consumer-facing assertion wrapper so a scanner that visits nothing cannot report success.

### Foundation boundary

This slice does not implement managed Scalpels HTTP exchange, email collision allocation,
five/thirty-minute freshness calls, transition orchestration, or unified credential replacement.
Existing `api_tokens`, fallback-token, ownership, delegated Console actor/guard, and app-specific
credential declaration surfaces remain separate contracts; they are not evidence that those later
unified-auth behaviors exist.

## Installer scaffold

Client packages can share the same `*:install` command plumbing with
`ArtisanBuild\BuiltForCloud\Commands\Concerns\WritesInstallEnv`. The trait keeps installer commands
focused on prompts and option parsing while it handles the repeatable side effects:

| Helper | Behaviour |
| --- | --- |
| `setEnvironmentValue()` | Purely returns `.env` contents with a key appended or replaced idempotently. Values with spaces or special characters are quoted. |
| `writeEnvFile()` | Reads an env file, applies key/value updates, writes only when the contents changed, and creates the file when missing. |
| `pinComposerConstraint()` | Sets `require[vendor/package]` to a clean caret major such as `^2` in `composer.json`, creating `require` when needed. |
| `summarize()` | Prints a tidy install summary from the consuming Artisan command. |

Prompts stay in the consuming command, so each app can ask the right questions while sharing the file
and composer mutation logic:

```php
use ArtisanBuild\BuiltForCloud\Commands\Concerns\WritesInstallEnv;
use Illuminate\Console\Command;

final class SinkInstallCommand extends Command
{
    use WritesInstallEnv;

    protected $signature = 'sink:install {--api-url=}';

    public function handle(): int
    {
        $apiUrl = $this->option('api-url') ?: text('Sink API URL');

        $envChanged = $this->writeEnvFile($this->laravel->environmentFilePath(), [
            'SINK_API_URL' => $apiUrl,
        ]);

        $this->pinComposerConstraint(base_path('composer.json'), 'artisan-build/sink', 1);

        $this->summarize([
            'env changed' => $envChanged,
            'composer package' => 'artisan-build/sink:^1',
        ]);

        return self::SUCCESS;
    }
}
```

A cloud-provisioning installer command is planned for a future v2 release; this scaffold only covers
local install command helpers.

## Contract conformance

Consuming apps can run the package contract kit in CI to prove their installed app still exposes the
Built for Cloud routes, auth gates, token model shape, and scope vocabulary expected by the shared
contract. Add a test in the consuming app's own suite after the package migrations are available:

```php
<?php

use ArtisanBuild\BuiltForCloud\Testing\ContractAssertions;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);
uses(ContractAssertions::class);

it('satisfies the Built for Cloud contract', function (): void {
    $this->assertBuiltForCloudContract();
});
```

The trait is shipped under the package's normal PSR-4 autoload (`src/Testing`), so downstream tests can
import it directly from `ArtisanBuild\BuiltForCloud\Testing\ContractAssertions`. It includes helpers
for minting admin and consume-scoped API tokens when an app wants to assert individual contract areas.

## Contributing

This package is developed by [Artisan Build](https://artisan.build). Issues and pull requests are
welcome.

### Releasing

Every tag gets a version bump: update `BuiltForCloud::VERSION` to the version you are about to tag
**before** tagging, because `/bfc/meta` reports that constant and control planes use it to decide
which capabilities an instance has. Then `git tag vX.Y.Z && git push --tags`.

## License

MIT © Artisan Build. See [LICENSE](LICENSE).
