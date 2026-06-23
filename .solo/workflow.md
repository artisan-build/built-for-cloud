# Workflow — built-for-cloud

Project profile for Solo-driven work in the shared `artisan-build/built-for-cloud` library (token
admin, auth foundation, cloud-CLI helpers, install scaffold). Consumed by sink and other suite apps
via Packagist (`^0.1`). This is a **library** (no app shell).

## Phase & mode
- phase: pre-launch (dev library; published 0.1.x)
- default mode: A-autonomous — merge each PR when CI is green; no human PR code review unless asked.
- merge method: `gh pr merge --squash` after CI green (repo has issues/PRs ENABLED).

## Hard gate (must be green before review; verify on committed SHA, clean tree)
- commands (run all three at repo root): `composer stan` (phpstan/larastan, memory 512M) AND
  `composer lint:test` (pint --test) AND `composer test` (pest).
- there is NO composite `composer ready` and NO `composer audit` in this repo's gate.
- monorepo: no (single package).

## CI (the merge gate for Mode A)
- status: verified — testing (pest) + static analysis (phpstan) present.
- runner: PHP 8.4; sqlite in-memory via Testbench (TestCase registers BuiltForCloudServiceProvider).
- tests that need a users table set one up (loadLaravelMigrations / a test migration) + a test User
  model (Authenticatable, is_admin) + `config(['auth.providers.users.model' => ...])`.

## Dependency install (fresh worktree/branch)
- command: `composer install --no-interaction`.
- post-install: none required (library; no .env, no app DB).

## Harness map (role → runtime; decorrelate by ROLE/FRAMING, not lineage)
- implementer: OpenCode (Solo `agent_tool_id 2`).
- adversarial reviewer: Claude (Solo `agent_tool_id 3`) — security framing (command-injection, secret
  handling, auth/privilege). Only Claude + OpenCode run reliably in this Solo env.

## Ship details
- branch naming: `feat/<slug>`.
- PR target repo: `artisan-build/built-for-cloud` (branch `main`).
- release: **manual** — after merge, `git tag vX.Y.Z && git push --tags`; Packagist auto-updates.
  Bump additively within 0.1.x (new optional features → patch). Consumers then `composer update
  artisan-build/built-for-cloud`.

## Stack notes / quirks
- `token:create` is the canonical **local-driver → cloud-wrap** pattern: it runs LOCALLY, and for a
  Cloud target uses `CloudCommandRunner::run($env, '<cmd> --execute …')` which shells
  `cloud command:run <env> --cmd "php artisan …"`. It `escapeshellarg`s every interpolated value
  (command-injection guard) and sends only a HASH over the wire, never a plaintext secret. New
  cloud-wrapping commands MUST follow both disciplines.
- `CloudCommandRunner`: `resolveEnvironment(?string)` (lists via `cloud environment:list`, prompts if
  multiple, throws if CLI unavailable / no `.cloud/config.json` application_id); `run($env, $cmd)`
  (returns `['output','exitCode']`). Cloud binary + application id from `config('built-for-cloud.cloud.*')`.
- `create-admin` writes directly to the app's DB (Eloquent), resolving the model from
  `config('auth.providers.users.model')`; it is NOT a cloud-wrapper by default (unlike token:create).
