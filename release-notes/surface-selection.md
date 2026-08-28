# Surface selection (PRD 1.14, fleet F2)

The `built-for-cloud.surfaces` config key makes the package a true package-with-flags: five
independently selectable surface families, all ON by default (exactly the pre-1.14 behavior),
each verifiably absent when turned off.

| family | env | what it gates |
|---|---|---|
| `routes` | `BUILT_FOR_CLOUD_SURFACE_ROUTES` | every HTTP route the package mounts — all of `/bfc/*` and the legacy credential API |
| `migrations` | `BUILT_FOR_CLOUD_SURFACE_MIGRATIONS` | `loadMigrationsFrom` for the package's schema migrations |
| `commands` | `BUILT_FOR_CLOUD_SURFACE_COMMANDS` | the `bfc:*` / `token:*` artisan commands |
| `listeners` | `BUILT_FOR_CLOUD_SURFACE_LISTENERS` | the package's event listeners (the ownership webhook queue) |
| `data_migrations` | `BUILT_FOR_CLOUD_SURFACE_DATA_MIGRATIONS` | data-WRITING migration steps — today, the initial ownership-claim mint |

Why it exists: at 1.14's head, the provider mounted everything unconditionally, so an app that
used only the auth foundation still served a live `POST /bfc/ownership/claim` minting
admin-scoped owner rows into tables it never read — "the worst of the three options". With
`routes` off, capstan and reel stop mounting `/bfc/*` from config, no fork, no redeploy dance
beyond the config change.

The boundaries, stated:

- **Families, never single routes.** The claim surfaces in particular are never env-gated one
  by one (PRD 1.12) — `/bfc/claim` and its siblings mount whole-family or not at all.
- **Not surfaces:** the `bfc` guard driver, the rate limiters, the middleware aliases
  (`bfc.ability`, `bfc.hmac`, …) and config publishing always register — they mount nothing,
  and an app with `routes` off still uses the aliases to gate its own routes (the per-tool MCP
  primitive included).
- **`migrations` off means the app owns the schema.** The package's runtime still expects its
  tables to exist wherever the app's own migrations created them.
- **`migrations` is a fresh-install flag, not a retroactive one.** Turning it off AFTER the
  package migrations have run strands their rollback: the `migrations` table still records
  the entries, but the migrator can no longer find the files behind them, so
  `migrate:rollback` fails when it reaches one. Flip it only on a fresh install or for a
  surface that never served — an app that already migrated keeps it on, or copies the
  package migration files into its own `database/migrations` before flipping.
- **`data_migrations` is separate from `migrations`** because wanting the schema without the
  framework seeding state into it is a legitimate shape. The initial ownership-claim mint
  checks this flag itself, so it composes with either migration-loading answer.

Riding along as its own D7 bug fix (its own commit): the initial ownership-claim migration
**no longer logs the plaintext claim token** — the admin-yielding secret used to land in the
application log. It now logs the claim row id and timestamp only, and the recovery path for an
unclaimed environment is `bfc:ownership:mint-claim` (TTY, shown once), which existed for
exactly this. That fix ships mutation-verified.
