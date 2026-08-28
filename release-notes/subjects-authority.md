# The per-verb authority matrix and the additive credential-API shape

The subject model and the authority model, kept separate on purpose (PRD 1.4 + 1.5, D2): a
subject type describes what a revocation costs; authority is an explicit, executable, per-verb
declaration. Plus the additive listing/revocation shape the fleet screen and every control-plane
consumer build on.

## The verb-aware authority hook

- **New opt-in contract `AuthorizesCredentialVerbs`** (the `DeclaresBurnMode` pattern):
  `authorizeVerb(CredentialVerb $verb, ?Subject $subject, Request $request): bool`, consulted by
  the credential API on every verb it serves. `CredentialVerb` is the matrix's five-verb
  vocabulary — `issue`, `list_metadata`, `rotate`, `revoke`, `receive_replacement` (`rotate` and
  `receive_replacement` are declared now; the surfaces that consult them ship with the rotation
  route and the delivery shapes). A separate opt-in interface rather than a changed
  `CredentialDeclaration::authorize()` signature, so no existing declaration breaks.
- **Nothing is inferred from possession.** No permission ever derives from `subject_type`, from
  `subject_ref`, or from holding a credential name. The subject the hook sees is what the TARGET
  ROW declares — a client-supplied subject or name in any request input never reaches the matrix
  and never widens anything (SEC-V3-07; named negative tests on the revoke path).
- **The matrix can only narrow.** Every credential-API verb is already an operator-scope action
  behind the admin-token gate; a declaration that does not implement the contract gets exactly
  that gate (every verb allowed), and implementing it can only deny further — a declaration
  denying `revoke` produces 403 even for a valid admin token. It can never widen past the guard
  or the credential's abilities, which are checked first.
- **`list_metadata` granularity is per-row filtering:** each row the declaration denies drops out
  of the listing; a blanket deny yields an empty `200 []`, not a 403.
- **Revoke-by-name fails closed against the matrix:** if ANY resolvable row of the name is
  denied, the whole request 403s and nothing is revoked.

## The five subject types (D2's cost-of-revocation table)

`subject_type` and `subject_ref` are now nullable columns on `api_tokens`. **A subject is
declared as a pair or not at all:** both columns together, or both null — and both-null is the
one shape that means "this row predates subjects" (declare-don't-guess, never a
retro-classification). A partial pair is refused at the model's saving hook, because it would
silently map to the legacy null subject and inherit legacy authority under a tenant-scoped
matrix. What one revocation costs:

| `subject_type`      | what one revocation costs                                                     |
|---------------------|-------------------------------------------------------------------------------|
| `application`       | a whole application stops reporting                                           |
| `installation`      | one enrolled install of one application; sibling installs survive             |
| `user_principal`    | one authenticated user's own credential; they hold a session and can revoke it themselves |
| `external_consumer` | one outside party — a person, a CI runner, or a client system — is cut off; siblings keep working |
| `operator`          | a control plane loses management access; the app itself keeps running         |

## Revoke-by-id vs revoke-by-name

- **`DELETE /api/credentials/id/{id}` is the precise verb** (D2 consequence 1, D6): exactly that
  row dies; a same-named sibling — a rotation grace row, another install's credential — survives
  and keeps authenticating. Emits the `revoked` audit event with the acting admin token and
  reason `operator_request`. 404 for an unknown id; idempotently 204 for a row already dead (one
  death, one audit event). Same admin gate as every other credential-API route.
- **Revoke-by-id kills whatever still resolves — never a silent no-op on a live row.** Its
  predicate is resolvability, not `revoked_at`: legacy resolution ignores `revoked_at`
  (test-pinned; `revoke()` has always set both columns), so an anomalous row carrying
  `revoked_at` with no effective expiry (an import, a manual repair) lists as `revoked` while
  still authenticating. Revoke-by-id repairs that anomaly on contact: it stamps `expires_at`
  (keeping the original `revoked_at` where one exists) and emits the audit event a real death
  deserves. "Already dead" — the idempotent 204 with no event — means EXPIRED, the one state
  that no longer authenticates. No package verb can produce or leave behind the anomalous state.
- **`DELETE /api/credentials/{name}` stays for CLI compatibility** and keeps its revocation
  semantics: it revokes EVERY resolvable row of that name. By-id is the verb to prefer wherever a
  row id is known.
- **The name verb authorizes and revokes the SAME id set.** The rows are selected and locked
  under the revocation's own transaction, that id set is run through the verb matrix, and the
  revocation write is keyed on exactly those ids — never re-queried by name — so nothing can die
  unauthorized. A same-named row created after the locked select is simply not in this
  revocation, and the response body reports the ids that actually died.

## Status semantics (`unknown` never escalates)

Each listing row now carries a computed `status`: `revoked` (revocation wins over the expiry it
also sets — it is the deliberate act), `expired`, `active`, or `unknown`. Two rules for
consumers:

- **`unknown` NEVER escalates to a failure state** (FLT-R2). It means the row structurally cannot
  carry a usage signal; a signal that cannot move is not a signal that stopped. On the
  `api_tokens` store every row structurally carries the signal, so this provider never emits
  `unknown` — the value is reserved in the vocabulary for stores whose rows cannot carry it.
- **The instance-reported status is an INPUT to the consuming control plane's own mapper**
  (FLT-H). Scalpels' mapper stays authoritative for connection health; this package reports, it
  does not judge.

## API_VERSION note

Every field added by this release, for the version-bump-or-drop decision (PRD 0.2). All additive;
nothing existing was renamed, removed, or reordered ahead of the pre-existing keys.

**Added to each `GET /api/credentials` listing row:**

- `id` — the row id (the revoke-by-id/rotate-by-id target).
- `request_count` — total successful presentations.
- `subject_type` — nullable; one of the five subject types, or null when the row predates
  subjects.
- `subject_ref` — nullable; the subject's partition key (tenancy lives here, never in the name).
- `status` — computed: `active` / `expired` / `revoked` / `unknown` (semantics above).
- `presentation_cadence_seconds` — nullable; the provider's declared presentation cadence (new
  opt-in contract `DeclaresPresentationCadence`; the default declaration declares none, leaving
  the consumer's own default in charge). Per provider, so identical on every row.

**Added at the listing top level:**

- `BFC-Presentation-Cadence` response header — the same declared cadence, once. A header rather
  than a body envelope because the listing body has always been a bare JSON array and wrapping it
  would break existing consumers; omitted when no cadence is declared.

**Added routes:**

- `DELETE /api/credentials/id/{id}` — revoke-by-id (semantics above).

**Changed response:**

- `DELETE /api/credentials/{name}` now returns `200` with `{"revoked_ids": [...]}` — the ids
  that actually died — instead of an empty `204`. A name can resolve to several rows (and, under
  a narrowing matrix plus concurrency, to fewer than a caller might assume), so the response
  states the actual outcome rather than leaving the caller to guess. This is the one
  non-additive wire change in this release; callers that only checked for success keep working
  on any 2xx check, and the route, method, and path are unchanged.

**Schema note:**

- `api_tokens.subject_type` + `api_tokens.subject_ref` (nullable pair; both-or-neither enforced
  at the model — both-null means the row predates subjects).

**Containment, unchanged and re-proven:** the listing's exact-key-set invariant test now pins the
extended key set — an accidental `token_hash`, `secret_hash`, or any secret-adjacent column still
fails it — and the new/changed surfaces run under the `DetectsSecretLeaks` harness. The
consuming-app suite gains `ContractAssertions::assertBuiltForCloudCredentialListingContract()`
(additive; not part of `assertBuiltForCloudContract()`, since the credential API is disabled by
default).
