# The audit model, the lifecycle event stream, and the transactional outbox

Every credential lifecycle transition the package performs now appends an audit event and delivers
lifecycle notifications through one transactional stream (PRD 1.9 / D8, 1.16, 1.3).

## The instance-side, append-only audit model

- **`credential_audit_events` ships in the package and lives in each consuming app's own
  database.** A deployed environment's audit history lives in that environment's database and
  nowhere else; a self-hoster gets the full trail with zero fleet tooling. Anything a fleet manager
  keeps is a cache, never the record — a customer who leaves keeps their history.
- **Ids only — never secret values, never hashes.** Rows carry event type, code id, credential id,
  supersession lineage, provider/deployment/environment context, an actor (type + ref strings
  covering an admin token, a bound user, an operator integration, the local CLI operator, and the
  bearer of a presented code/credential), the intended recipient where a code was addressed, the
  TTLs selected, a bounded `reason_code` enum plus a bounded 500-character free-text `note`, and
  timestamps.
- **Append-only, enforced twice.** The model throws on any update or delete; database triggers
  abort raw UPDATE/DELETE on sqlite, mysql/mariadb, and pgsql. **The stated trade (D8):** a
  compromised instance can still tamper with its own history — a connection with schema privileges
  can drop the triggers, and direct file access rewrites anything. Append-only is by construction,
  not cryptographic; divergence between an instance's rows and a fleet-side cache of the fleet's
  OWN actions is itself a tamper signal. Unknown drivers (sqlsrv) get model-level enforcement only.
- **`note` and `reason` are customer-visible (D7).** They are stored verbatim, escaped by every
  renderer, and any spreadsheet-consumable export MUST pass cells through
  `CsvFieldSanitizer::sanitize()` — this release ships the tested helper; the export surface itself
  rides the audit-read verb in the two-transport release.

## One lifecycle event stream, transactional or it is fiction

- **One vocabulary** (`LifecycleEventType`): `issued`, `delivered`, `exchanged`, `first_used`,
  `rotated`, `revoked`, `expiring` — plus `sensitive_read` and `denied_action`, reserved now so the
  operator-surface releases emit through the same stream. Audit rows and notifications are both
  subscribers of this one stream; two vocabularies would drift.
- **The audit insert and an outbox row commit in the SAME transaction as the state transition**
  (SEC-V3-09). Hooked surfaces: claim-code issue (`issued`, plus `revoked` for durables invalidated
  by supersession), exchange (`exchanged`, plus both D1d revocations as `revoked` rows with
  old → new lineage), the first-use burn (`first_used`, inside the existing burn transaction, with
  the code linkage and intended recipient), rotation (`issued` for the replacement plus `rotated`
  per superseded row with lineage; `emergency` reason under `--emergency`), and every revoke path
  (`revoked` with its reason). A transition that rolls back takes its audit row and outbox row with
  it; nothing is ever delivered about a mutation that did not happen. The recorder refuses to run
  outside a transaction.
- **The outbox (`credential_outbox`) is consumed after commit, idempotently.** A synchronous
  post-commit dispatcher drains it in-process (no queue dependency), and `bfc:outbox:drain`
  re-drains anything left behind. Claims are conditional updates gated on affected rows; a consumer
  that dies mid-delivery leaves its row claimable again after the claim TTL
  (`built-for-cloud.audit.outbox.claim_ttl_seconds`, default 300); a subscriber that throws
  releases its claim with the exception class recorded and never breaks the caller. The unique
  `dedup_key` (default: the audit event id) means the same logical event is never enqueued twice —
  and it is a free string, so later integration event-id machinery (SEC-V3-05) needs no schema
  change. Delivery is exactly-once in normal operation and at-least-once across a process death.

## One lifecycle-notification policy

- **`built-for-cloud.notifications.policy` is the one table**: event × declared recipients
  (`issuer`, `holder`). Defaults are SEC-6's two notices plus the expiry warning: `exchanged`
  notifies the issuer (with the exchange actor on the audit row), `first_used` notifies the
  intended recipient, `expiring` notifies the holder. Apps extend or replace the table in config.
- **"Holder" resolves declaratively, and NOBODY is a first-class answer.** The event's addressed
  recipient wins where a code was addressed; otherwise the app declaration may implement
  `DeclaresHolderResolution` (the `DeclaresBurnMode` pattern) to map a credential to its bound
  user's email. The default declaration resolves NOBODY: an unbound subject (a CI key, an app
  token) notifies no one, and there is deliberately no operator fallback to spam.
- **Notifications carry ids and metadata only** — never a secret, never a claim code, not even the
  free-text note. A queued notification payload is a database row (D7); ids cannot leak. The
  issuer inbox is `built-for-cloud.notifications.issuer` (null by default: issuer rows notify no
  one until an inbox is declared).

## The three lifetimes (PRD 1.3)

Three separately bounded lifetimes, one of which has a default:

1. **Claim code** — `ttl_seconds` required, bounded 60s–7d.
2. **Durable credential** — caller-chosen expiry, **no default, ever**. Revocation-on-event, not
   expiry, is the intended end of a durable's life.
3. **Rotation grace** — 1 hour, or 0 with `--emergency`.

- **The expiry warning is conditional on the issuer's choice.** When a durable HAS an
  `expires_at`, `bfc:credentials:warn-expiring` (schedule it however the app schedules things)
  emits `expiring` through the same stream ahead of the lapse — once per credential per chosen
  expiry, idempotent across runs and concurrent runs (the outbox dedup key enforces it). A durable
  without expiry never warns; nothing nudges anyone toward setting one. The window is
  `built-for-cloud.lifetimes.expiry_warning_hours` (default 72) or `--window-hours`.
- **The holder can reach the emergency revoke** (the surviving case: the hitch-minted MCP token).
  `bfc:token:revoke-self` takes the credential over STDIN (piped) or a hidden prompt — **never as
  an argument**, which it refuses without echoing — and revokes exactly the presented credential,
  emitting `revoked` with reason `holder_request`. Presenting for revocation is not a use: no
  usage bump, no first-use burn. The HTTP variant rides the two-transport release.

## Notes for upgrading apps

- Two new migrations run on upgrade (`credential_audit_events`, `credential_outbox`). No existing
  table changes.
- The package now requires `illuminate/notifications` (part of the framework every consuming app
  already ships).
- `TokenRegistry::rotate()` and `revoke()` accept an optional `AuditActor` (and `revoke()` an
  `AuditReason`); existing call sites work unchanged and record an unknown actor.
- Mint paths outside the claim flow (`token:create`, `POST /api/credentials`) do not yet emit
  `issued` — the mint/delivery verbs of a later release hook them into the same stream.
