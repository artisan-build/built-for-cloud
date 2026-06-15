# Built for Cloud

Shared building blocks for administering **cloud-first Laravel applications from the
[Laravel Cloud](https://cloud.laravel.com) CLI** — no admin UI required.

These are the pieces that several Artisan Build apps (Matte, Hone, …) need in common: things you
manage by running an Artisan command in your production environment and reading its output back on
your machine. The first domain this package covers is **API token management**.

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

## Contributing

This package is developed by [Artisan Build](https://artisan.build). Issues and pull requests are
welcome.

## License

MIT © Artisan Build. See [LICENSE](LICENSE).
