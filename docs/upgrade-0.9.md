# Upgrade to 0.9

Version 0.9 removes the legacy token store and its compatibility surfaces. This is a forward-only
upgrade: update integrations to the unified credential APIs and mint replacement credentials before
deploying 0.9. Legacy plaintext secrets cannot be recovered from their hashes, and 0.9 does not
provide an in-place compatibility mode for the removed store.

Use the `bfc:credential:*` commands with `--local` only when you intend to operate on the local
database. Without `--local`, commands that support Laravel Cloud delegation operate on the selected
remote environment.

## Purpose migration: retire all and re-mint

The purpose migration adds nullable string column `credentials.purpose` with no database default.
Purpose is protocol authority, so the migration does not infer it from kind, subject, or legacy
abilities. Instead it retires every credential row present at migration time by setting
`revoked_at` once for rows that were still live and preserving the timestamp of rows already
revoked. Stored lifecycle `status`, subject, abilities, ids, and row count are not rewritten.

After migration, `bfc:credential:list --local` and its `--json` form show these rows as revoked
tombstones with `purpose` set to null. They remain visible for inventory but cannot authenticate,
sign, verify, publish an actor, or participate in active public-key selection. The list exposes no
secret hash, ciphertext, key material, fingerprint, MAC, or secret-derived substitute.

Re-mint every application-owned credential with an explicit matrix-valid purpose, distribute the
new reveal-once secret or claim delivery, and complete any required activation before restoring
traffic. There is no classifier, compatibility bridge, fallback store, or automatic re-mint.
Rollback drops only the `purpose` column; it deliberately leaves every migration retirement in
force and never resurrects an old credential.

The accepted purpose values are `operator_management`, `dashboard_metadata`, `consumption`, `mcp`,
`signing`, `signing_root`, `enrollment`, and `system_deployment`. Generic mint cannot create
`signing_root`; it also rejects the reserved `(installation, bfc:signing-root)` identity. Every
persisted ability on a new credential must be a documented `OperatorAbility` value. Legacy claim
scope strings such as `consume` and `onboard` are not abilities.

## Removed surfaces

This table is rendered from `LegacyRemovalInventory::upgradeGuide()`. The test suite compares this
marked block byte-for-byte with the inventory renderer so additions, removals, replacements, and
ordering cannot drift independently.

<!-- legacy-removal-inventory:start -->
| Surface | Removed in 0.9 | Replacement |
| --- | --- | --- |
| Class | `ArtisanBuild\BuiltForCloud\ApiToken` | `ArtisanBuild\BuiltForCloud\Credential` |
| Class | `ArtisanBuild\BuiltForCloud\ApiTokenMinter` | `ArtisanBuild\BuiltForCloud\UnifiedStoreCredentialMinter` |
| Class | `ArtisanBuild\BuiltForCloud\TokenRegistry` | `ArtisanBuild\BuiltForCloud\Auth\CredentialResolver and the unified credential actions` |
| Class | `ArtisanBuild\BuiltForCloud\LegacyRotationResult` | `ArtisanBuild\BuiltForCloud\RotationResult` |
| Class | `ArtisanBuild\BuiltForCloud\DurableStore` | `none, forward-only` |
| Class | `ArtisanBuild\BuiltForCloud\Contracts\DeclaresDurableStore` | `none, forward-only` |
| Class | `ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureAdminToken` | `ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAdmin` |
| Class | `ArtisanBuild\BuiltForCloud\Http\Controllers\ManageTokens` | `ArtisanBuild\BuiltForCloud\Http\Controllers\ManageCredentials` |
| Class | `ArtisanBuild\BuiltForCloud\Commands\FallbackTokenGenerateCommand` | `ArtisanBuild\BuiltForCloud\Commands\InstallOperatorCredentialCommand` |
| Class | `ArtisanBuild\BuiltForCloud\Commands\TokenCreateCommand` | `ArtisanBuild\BuiltForCloud\Commands\CredentialMintCommand` |
| Class | `ArtisanBuild\BuiltForCloud\Commands\TokenListCommand` | `ArtisanBuild\BuiltForCloud\Commands\CredentialListCommand` |
| Class | `ArtisanBuild\BuiltForCloud\Commands\TokenRevokeCommand` | `ArtisanBuild\BuiltForCloud\Commands\CredentialRevokeCommand` |
| Class | `ArtisanBuild\BuiltForCloud\Commands\TokenRevokeSelfCommand` | `none, forward-only` |
| Class | `ArtisanBuild\BuiltForCloud\Commands\TokenRotateCommand` | `ArtisanBuild\BuiltForCloud\Commands\CredentialRotateCommand` |
| Class | `ArtisanBuild\BuiltForCloud\Commands\TokenUsageCommand` | `none, forward-only` |
| Class | `ArtisanBuild\BuiltForCloud\Database\Factories\ApiTokenFactory` | `ArtisanBuild\BuiltForCloud\Database\Factories\CredentialFactory` |
| Enum case | `AuditActorType::AdminToken` | `AuditActorType::OperatorIntegration` |
| Enum case | `Audit\AppActorType::LegacyApiToken` | `Audit\AppActorType::ApiToken` |
| Method | `EnsureCredentialAdmin::isFallback` | `none, forward-only` |
| Middleware alias | `bfc.token.admin` | `bfc.credential.admin with an explicit operator ability` |
| Table | `api_tokens` | `credentials` |
| Column | `ownership.owner_token_id` | `ownership.owner_credential_id` |
| Column | `onboarding_tokens.durable_token_id` | `onboarding_tokens.durable_credential_id` |
| Column | `onboarding_tokens.durable_store` | `none, forward-only` |
| Config key | `built-for-cloud.fallback_token` | `none, forward-only; mint a real operator credential` |
| Environment variable | `FALLBACK_TOKEN` | `none, forward-only; run bfc:install:operator-credential` |
| Config key | `built-for-cloud.credential_api` | `none, forward-only; the unified HTTP surface is fixed under /bfc` |
| Config key | `built-for-cloud.credential_api.prefix` | `none, forward-only; the unified HTTP surface is fixed under /bfc` |
| Command | `token:create` | `bfc:credential:mint` |
| Command | `token:list` | `bfc:credential:list` |
| Command | `token:revoke` | `bfc:credential:revoke` |
| Command | `token:rotate` | `bfc:credential:rotate` |
| Command | `token:usage` | `none, forward-only` |
| Command | `bfc:token:revoke-self` | `none, forward-only` |
| Command | `fallback-token:generate` | `bfc:install:operator-credential` |
<!-- legacy-removal-inventory:end -->

## Migration sequence

1. Replace direct references to removed classes and middleware aliases.
2. Move callers to the fixed `/bfc` HTTP surface and remove the retired route-prefix configuration.
3. Mint unified credentials with the required subject, purpose, and closed ability values; distribute them through the
   reveal-once or claim-code flow, and activate HMAC credentials before cutover.
4. Update ownership and onboarding integrations to the replacement credential columns.
5. Revoke the old credentials in the pre-0.9 installation, deploy 0.9, and verify each integration
   with its new credential.

Do not copy rows from the removed token table into `credentials`: the stores have different lifecycle,
subject, delivery, and activation invariants. Use the unified mint and rotation surfaces instead.
