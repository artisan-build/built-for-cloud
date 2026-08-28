# Invitations converge onto the claim-code primitive (PRD 1.13 / D4 / D1e)

The package `Invitation` is now a claim code in `at_exchange` mode: hashed at rest (as it always
was), single-use under a conditional-update burn, optionally addressed, with a REQUIRED bounded
ttl — and an app hook for composing the user its acceptance creates. The invite verb is
machine-callable over two transports with the SEC-V3-05 ordering gate.

## BREAKING: `Invitation::invite()` requires `ttl_seconds`

```php
// before
Invitation::invite(string $email, ?string $invitedBy = null, ?DateTimeInterface $expiresAt = null);

// after
Invitation::invite(?string $email, int $ttlSeconds, ?string $invitedBy = null, ?string $role = null);
```

The 7-day default is **deleted** (D1b: a claim code's lifetime is always the issuer's explicit
choice; making the parameter required is what guarantees the deletion leaves no no-expiry hole).
`ttlSeconds` is bounded **60–604800** (7 days — D4 cost 6: capstan's 14-day default becomes
impossible by design; re-issue instead). Out-of-bounds throws `InvalidCredentialInput`.

**sink is the one known consumer** (`Invitations.php:26`) and must pass a ttl when it takes this
package version — scheduled as the Phase-2 sink bump, not shipped here. `email` is now nullable
(open codes); sink always passes one and needs no change for that. `$expiresAt` is gone: the ttl
IS the expiry choice.

## The `at_exchange` burn on `accept()`

Acceptance consumes the invitation under a **conditional update gated on affected rows**
(`update … where accepted_at is null`) inside the locked transaction — never a read-then-write.
Of two concurrent accepts exactly one wins; the loser gets the claim-contract refusal. This
preserves the SHAPE of capstan's own single-use guarantee (D4 cost 5 / FLT-R3) so the 2.2
convergence replaces a conditional update with a conditional update.

`accept()` now refuses with `InvalidInvitation` carrying the claim contract's **error enum**
(`$exception->error`): `code_not_found`, `code_already_claimed`, `code_expired`. Messages are
secret-free — the old `forToken()` message embedded the presented code; the kept-for-BC
`forToken()` factory no longer does. `accept()` also records the invitation's `exchanged`
lifecycle event (audit + outbox, same transaction) and stamps `used_by` with the created user's
key.

## The `accept()` attribute-composition hook

Bind `ArtisanBuild\BuiltForCloud\Contracts\ComposesInvitedUserAttributes` in the container to
compose the created user's attributes (capstan projects the stored `role`; crate projects
key-management-only). **An app that binds nothing sees today's behaviour exactly.** The hook is
TRUSTED APPLICATION CODE — binding one is a privileged act. The package strips `is_admin` from
its return and keeps an addressed invitation's email authoritative, but these are guard-rails
against accidental pass-through of registrant input, **not a privilege boundary against the
hook itself** (a hook can reach the same user model directly).

## Table generalized in place (no rename)

Additive migration: `used_by` (nullable string 64), `role` (nullable string, stored and never
interpreted), `email` nullable, `invited_by` widened uuid → nullable string(64) (the decided D4
shape: bigint and uuid inviter ids alike stringify; no FK — the package cannot know the host's
user key type). One upgrade path for fresh and existing databases; an app-owned table (flag off
or no `token` column) is never touched.

**Rollback never drops the invitations table (FLT-F).** The create migration records as run
whether it created the table, was flag-skipped, or found the app's own table already there — so
at rollback time flag-on + table-present cannot prove whose table it is, and the package
refuses to guess: `down()` is a deliberate no-op. An operator who truly wants the package's
table gone drops it manually (`DROP TABLE invitations`).

## The machine-callable invite verb + version gate (SEC-V3-05)

`POST /bfc/invitations` and `bfc:invitation:issue --local` run one action behind the
credential-admin gate (verb matrix `issue` consulted). Optional integration-event parameters —
`integration_namespace`, `event_id`, `entitlement_version`, `external_subject`, all-or-none —
drive the ordering gate: the latest accepted version per (namespace, external subject) is stored
in `integration_entitlements`, events not newer are transactionally acknowledged-and-ignored,
and every decided event id is recorded in `integration_events` so replays answer idempotently
(no second invitation; replay-after-accept resurrects nothing). `entitlement_version` is bounded
to **[1, 2^53]** — oversize values (including digit strings that would saturate integer
parsing) are rejected, never accepted, so a poisoned maximum can never freeze a subject.
Concurrent deliveries racing the gate's FIRST row for a (namespace, subject) — or the same
event id — are re-decided in a fresh transaction against the winner's committed row and receive
the documented acknowledgement, never a unique-violation 500. Both tables are event-kind
generic — the offboarding verb (1.15) plugs into the same gate.

**Supersession** (mirroring the onboarding primitive): an APPLYING integration event consumes
every prior pending (unaccepted, unexpired) invitation of its (namespace, subject); issuing an
ADDRESSED invitation consumes every prior pending invitation of the same email. Superseded
codes refuse acceptance as `code_already_claimed` (`used_by` null distinguishes supersession
from a real acceptance). Open, non-integration codes supersede nothing. The package
`Invitation::invite()` model helper (sink's path) is unchanged — supersession is the verb's
semantic.

**Non-enumeration and the two response shapes:** the HUMAN path always issues and answers
`201` with the single reveal, shape-identical whatever the prior state. The INTEGRATION path
answers one uniform **`202 {"accepted": true}`** with NO invitation data — applied, ignored,
and replayed events are indistinguishable in the body, so even an authorized caller cannot
probe gate state. Response timing stays a best-effort side channel (an applying event does
more work); documented, with a debt row to revisit.

**Delivery:** on the integration path the INSTANCE delivers (D1e): an addressed applying event
mails the invitee the invitation code (`InvitationDeliveryNotification`, deliberately unqueued,
sent after commit) — that mail is the code's one egress on that path. An unaddressed
integration event is acknowledged and its invitation has no delivery channel; deliver by
issuing an addressed invitation from the admin/human surfaces, which supersedes it. The
lifecycle `issued` notice stays ids-only and policy-gated (`'issued' => ['holder']`);
unaddressed invitations notify nobody either way. On the human path the code's ONE egress
remains the verb's response/TTY reveal, and the caller owns delivering the accept link.

**Authority note:** the version gate trusts any caller the credential-admin gate admits — any
admin token or `credential:admin` operator can advance any namespace. Namespace-scoped
operator abilities arrive with the MCP/ability-vocabulary work; until then, per-integration
credentials give audit attribution, not authority isolation.

**Input bounds at the shared boundary:** `invited_by` max 64 characters;
`role`/`integration_namespace`/`event_id`/`external_subject` max 255 — the same `422` on both
transports.

`ContractAssertions` gains `assertBuiltForCloudInvitationTransportParity()`, wired into
`assertBuiltForCloudTransportParityContract()`.
