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

## Auth foundation

Built for Cloud augments your Laravel app's existing user model. It does **not** create or own a
`users` table. Instead, it reads the configured model from `config('auth.providers.users.model')`
(falling back to `App\Models\User`) and adds reusable admin and invitation building blocks around it.

### User admin flag

The package ships a guarded migration that runs late and adds `is_admin boolean default false` to an
existing `users` table. It never creates or replaces your app's user table, so run your app's users
table migration first and let the package migration run after that. If the users table does not exist
yet, the package migration is a no-op.

Make sure your app's user model casts the column as a boolean. Keep `is_admin` out of `$fillable` as
defense-in-depth so user-submitted form data cannot mass-assign privileges:

```php
protected $fillable = ['name', 'email', 'password'];

protected function casts(): array
{
    return ['is_admin' => 'boolean'];
}
```

### Create the first admin

Use the shared command to create an administrator in the configured user model:

```bash
php artisan create-admin --email=admin@example.com --password=secret --name="Admin"
```

If any admin already exists, the command refuses to create another one. Pass `--force` when you
intentionally want multiple admins:

```bash
php artisan create-admin --email=ops@example.com --password=secret --name="Ops" --force
```

When an option is omitted, the command prompts for it using Laravel Prompts.

The command requires the `is_admin` column to exist and fails with a migration reminder when it is
missing. It sets the admin flag with `forceFill()`, so your app should not make `is_admin` fillable.

### Invitations

The package provides an `ArtisanBuild\BuiltForCloud\Invitation` model and migration. Consuming apps
build their own routes, controllers, notifications, and views around these library methods:

```php
use ArtisanBuild\BuiltForCloud\Invitation;

$invitation = Invitation::invite('new@user.test');

$user = Invitation::accept($invitation->token, [
    'name' => 'New User',
    'password' => 'plain-password',
]);
```

`invite()` generates a unique token and defaults `expires_at` to seven days from now. `accept()` only
accepts pending, unexpired invitations; it creates the configured user with the invitation email,
hashes a provided `password`, marks `accepted_at`, and returns the new user. `accept()` never grants
admin access: privileged incoming attributes such as `is_admin` are ignored and the created user is
forced non-admin when the column exists. Invalid, expired, or already accepted tokens throw
`ArtisanBuild\BuiltForCloud\Exceptions\InvalidInvitation`.

Useful scopes are available for app UI and housekeeping:

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
| `bfc.admin` | Requires an authenticated user whose `is_admin` attribute is truthy; otherwise `403`. |

Use them in the consuming app's routes:

```php
Route::middleware('bfc.auth')->group(function () {
    // signed-in users
});

Route::middleware('bfc.admin')->group(function () {
    // administrators only
});
```

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

## Contributing

This package is developed by [Artisan Build](https://artisan.build). Issues and pull requests are
welcome.

## License

MIT © Artisan Build. See [LICENSE](LICENSE).
