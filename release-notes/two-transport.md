# The two-transport rule, the unified verbs, `--local` everywhere, the installer mint, and the public HTTP contract

The framework's spine (PRD 1.0 + 1.6 + 1.11 + 1.20 + 0.2): every verb ships twice from one
implementation, the CLI is a complete zero-Cloud management surface, the HTTP surface is a
versioned public contract, and the installer mints a real credential instead of a fallback.

## The rule (PRD 1.0)

**One invokable action class per verb, two transports.** Each unified-store verb is a single
action (`Actions\MintCredential`, `Actions\ListCredentials`, `Actions\RevokeCredential`) consumed
by BOTH an artisan command that runs fully locally with `--local` (direct database, same process,
zero Cloud dependency) and an admin-token-guarded HTTP endpoint at a fixed `/bfc/credentials`
path. Every authority answer — the per-verb matrix, mint ceilings, declared-unsupported fields —
lives INSIDE the action, so neither transport can do anything the other cannot. CLI-only is a
bug; HTTP-only is a bug.

## The verbs (PRD 1.6)

- **mint** — `mint(Subject, MintOptions): MintResult`, never mint-by-id (you cannot mint by id a
  row that does not exist). Mints into the unified `credentials` store. `MintResult` carries a
  `CredentialSummary` AND a delivery shape: `bearer` (a token string) · `basic_auth` (the
  `auth.json` username/password pair; username presentation-only) · `enrollment_code` (a
  claim-primitive code the client redeems by generating its own keypair — the code never carries
  key material; the row is `pending`; the enrollment-completing exchange ships with the first
  asymmetric consumer's rebuild) · `none` (the secret was never ours to hand over). The secret
  travels only inside the sealed `MintedSecret` carrier and is revealed exactly once at the
  transport boundary. Mint refuses, identically on both transports: a matrix `issue` denial;
  ability/lifetime widening past a declared ceiling (`ConstrainsMintedCredentials` — refusal,
  never a substituted default); options setting a declared-unsupported field; the `hmac` kind
  (later release). **No expiry is ever defaulted.**
- **list** — the unified-store listing with the declared-unsupported discrimination
  (`DeclaresUnsupportedSummaryFields`): an unsupported field is serialized null AND named in the
  row's `unsupported` list, so consumers distinguish "absent" from "unknowable" instead of
  guessing at nulls. The legacy `api_tokens` listing (`GET /api/credentials`) is unchanged.
- **revoke** — by id, the precise verb; pending enrollments are revocable and revoking one
  consumes its outstanding enrollment code. Emits the `revoked` audit event.
- **Rotation is NOT in this release** — the unified rotate verb ships next; `token:rotate
  --local` below is transport plumbing on the existing legacy rotation only.

## `--local` on the seven legacy commands (PRD 1.11)

`token:create`, `token:list`, `token:revoke`, `token:rotate`, `token:usage`,
`bfc:ownership:mint-claim` and `bfc:ownership:remint-owner-token` all gain `--local`: the same
command body the `--execute` half runs remotely, run against the local database with no Cloud
binary and no hand-computed sha256. The cloud-wrapped driver paths are untouched. Secrets keep
D7's CLI discipline everywhere: commands OUTPUT secrets (printed once to the TTY), never accept
them as arguments, and captured output beyond the single reveal is leak-harness-asserted clean.

## The installer mint (PRD 1.20) — FALLBACK_TOKEN retirement begins

`bfc:install:operator-credential` mints a REAL, revocable, `operator`-subject credential through
the same mint action (`--local` semantics: in-process, direct database) and prints it once to the
TTY. It is **wired into the install scaffold**: the scaffold concern (`WritesInstallEnv` gains
`mintInstallOperatorCredential()`) runs it as part of an app's install command,
**idempotently** — a re-run skips with a notice when a live operator credential already exists
(`--force` mints another deliberately). And the credential **works on the surface
it exists to manage**: the `/bfc/credentials` gate accepts either a legacy admin `api_tokens`
token or a unified-store operator credential holding `credential:admin` — the ability the
installer mints with — with the audit actor reflecting which store authenticated.

`fallback-token:generate` and the `fallback_token` config key are **deprecated** (warn +
docblock), not deleted — live 0.4.x apps still carry fallbacks, the fail-closed MCP gate stays
as the belt, and a later major removes them. Scope of the claim, stated precisely: the bfc guard
and every unified-store path never consult the fallback, and the installer path never writes or
reads one; the legacy `TokenRegistry::resolve()` still honours it for 0.4.x consumers, and the
admin gates still CONSULT the config — solely to REJECT a presented fallback with a
distinguishable 403 rather than a misleading 401 (explicit and tested on the new gate).

## API_VERSION 2 and the public contract (PRD 0.2, GATE-3)

`docs/http-contract.md` now documents EVERY mounted HTTP surface in plain HTTP+JSON, for a
consumer with no PHP — request/response shapes, auth, status codes, the claim error enum, and the
compatibility rule: what bumps `API_VERSION` (any incompatible change to a documented shape),
what does not (additive fields — consumers must ignore unknown fields), and what a consumer may
pin (the major + `bfc_version`/`capabilities` for feature detection). **`API_VERSION` is now 2**
— the credential listing grew across 0.4.x while the constant stagnated at 1, revoke-by-name's
response changed, and the unified verb routes exist; the doc's changelog carries the inventory. A
package test enumerates registered routes against the doc in BOTH directions, so the doc cannot
silently rot. `/bfc/meta` gains the `credentials` capability (additive).

## The seam toggle (PRD 1.0)

The claim exchange still mints durables only through the `DurableCredentialMinter` seam. The
default stays `api_tokens` — every existing onboarding consumer is untouched. An app opts in **at
rebuild time** by implementing `DeclaresDurableStore` on its declaration and returning
`DurableStore::Credentials`: exchange then mints a unified-store `bearer` row
(subject `external_consumer`, ref = the claim's name), and the make-before-break revocations,
`verify`, and the burn all follow the declared store. Burn semantics are intact on the unified
store: the guard's usage recording is now the same gated SEC-2 transition `api_tokens` has — a
first use consumes the linked claim code and emits `first_used` in one transaction, and a row
revoked between resolve and use no longer authenticates (previously the unified guard stamped
`last_used_at` unconditionally).

**The store transition cannot strand a durable.** `onboarding_tokens` gains an additive nullable
`durable_store` column, stamped at exchange (null backfills to `api_tokens`, the only store that
existed). Make-before-break always revokes the code's linked durable in its RECORDED store,
never the currently declared one; the name/scope sweep covers the current target store **plus**
the recorded store of the code's own linked durable — the stated choice: it covers the
transition exactly without extending the documented name-collision domain into a store the code
never touched. Burn lookups honour the same discriminator (an `api_tokens` linkage is the legacy
registry's to burn; a `credentials` linkage the unified recorder's).

## Mint paths emit `issued`

The unified mint emits `issued` on both transports, always. The legacy mint paths were cheap and
additive to close too: `token:create` (`--execute` and `--local`) and `POST /api/credentials` now
record `issued` (ids only) in the same transaction as the store.

## The transport-parity suite (for consuming apps)

`ContractAssertions` gains `assertBuiltForCloudTransportParityContract()` (additive): for each
two-transport verb it runs the SAME action through the CLI (`--local`) and HTTP and asserts
identical outcomes — row state, audit events, delivery-shape content, for the `bearer` AND
`basic_auth` deliveries — under the app's active declaration. Every comparison is **like for
like**: both legs put the identical question (same subject_ref, same inputs, same pre-state) to
each transport, so a subject-conditional declaration answers both legs the same way and never
reads as false divergence. A declaration that refuses must refuse on BOTH transports **with the
same error, message-equal**, leaving no row. Run it in CI next to the existing contract
assertions; the package runs it too.

**Scope of the guarantee:** parity is defined over the verb's own inputs (subject, options,
abilities, target row). `authorizeVerb` receives each transport's real request by design —
`resolveSubject` needs real context — so a declaration keying authorization on request internals
is app-owned divergence, outside what the suite asserts.

**Validation is shared too:** both transports build options through `MintOptions::fromInput()`,
so junk is rejected identically (`InvalidCredentialInput` → CLI failure exit / HTTP 422, same
message): a non-integer `code-ttl` like `60junk` is refused, never truncated, and **an empty
abilities list normalizes to null** (both grant nothing; summaries serialize the one canonical
shape).
