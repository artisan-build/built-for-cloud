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
- implementer: **Claude — Solo `agent_tool_id 3`.**
  ⚠️ **Do NOT use OpenCode (id 2) on this machine** — it hangs on a Kitty graphics probe under the Solo
  PTY and never becomes ready (same failure the scalpels_app profile documents). Corrected 2026-08-23.
- adversarial reviewer: **Codex, one-shot via `codex exec` in a Bash call — NOT a Solo agent** (its
  interactive TUI dies under the Solo PTY here). Security framing (command-injection, secret handling,
  auth/privilege), which keeps the reviewer off the implementer's model lineage. Invoke as:
  `codex exec --sandbox danger-full-access --cd <worktree> "$(cat brief.md)" </dev/null > <outfile> 2>&1`
  (background it and poll the outfile). ⚠️ **`</dev/null` is MANDATORY** — without it `codex exec` reads
  stdin forever and hangs, looking exactly like a slow review.

## Toolchain conformance — the ride-along rule (STANDING, all projects)

Run the project's full conformance command (`composer lint`, or the stack equivalent) as part of
FINALIZING every PR, and **let whatever it changes ride along in that PR** as a single isolated commit
titled `composer lint`.

The point is that conforming to the current standard is **passive** rather than something anyone has to
remember. Tools like Rector exist to keep the codebase at the current standard continuously; if their
output only lands when someone thinks to run them, the codebase drifts and the eventual catch-up is a huge
unreviewable diff.

This is **the boy scout policy: leave things better than you found them, even when the improvement is
not strictly related to the work at hand.**

- **Applies to EVERY project — ours and clients' alike — and to every PR regardless of size.** A
  one-line CI or YAML change gets the sweep exactly like a feature branch does. The only way it comes
  off is Ed specifying that deviation explicitly at the project or client level; a client exception is
  recorded there, never inferred.
- ⚠️ **Scope-discipline language does NOT suspend this rule.** "No unrelated cleanups", "one-line
  change only", and "don't expand scope" mean *don't invent extra work* — they never mean skip the
  ride-along. An agent that reads them that way will skip the sweep and cite the brief as
  justification. If you are writing a tightly-scoped brief, say so explicitly: *"no unrelated
  cleanups, but the standing `composer lint` ride-along still applies as its own commit."*
- **Do NOT open a separate branch for these changes.** As long as the tool CONFIGURATION is unchanged, the
  unrelated changes riding along on any given PR are small.
- **The one exception:** introducing a new Rector rule, or changing `pint.json` / equivalent tool config.
  That sweep is large and deliberate, so it gets its own dedicated branch and PR.
- Keep it in its OWN commit so a reviewer can separate "the feature" from "the sweep" at a glance.

## Ship details
- branch naming: `feat/<slug>`.
- PR target repo: `artisan-build/built-for-cloud` (branch `main`).
- release: **manual** — after merge, bump `BuiltForCloud::VERSION` (`src/BuiltForCloud.php`) to the
  version being tagged, then `git tag vX.Y.Z && git push --tags`; Packagist auto-updates.
  **Every tag gets a VERSION bump** — `/bfc/meta` reports the constant, so a stale VERSION lies to
  every control plane that reads it (it sat at 0.3.0 through the v0.3.1 tag).
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
