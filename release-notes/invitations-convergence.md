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
key-management-only). **An app that binds nothing sees today's behaviour exactly.** The hook
cannot escalate: `is_admin` is stripped from its return, and an addressed invitation's email
still overrides.

## Table generalized in place (no rename)

Additive migration: `used_by` (nullable string 64), `role` (nullable string, stored and never
interpreted), `email` nullable, `invited_by` widened uuid → nullable string(64) (the decided D4
shape: bigint and uuid inviter ids alike stringify; no FK — the package cannot know the host's
user key type). One upgrade path for fresh and existing databases; an app-owned table (flag off
or no `token` column) is never touched. The create migration's `down()` gains the `hasTable`
guard (FLT-F) alongside the config guard, so a rollback on an environment where the package
created nothing drops nothing.

## The machine-callable invite verb + version gate (SEC-V3-05)

`POST /bfc/invitations` and `bfc:invitation:issue --local` run one action behind the
credential-admin gate (verb matrix `issue` consulted). Optional integration-event parameters —
`integration_namespace`, `event_id`, `entitlement_version`, `external_subject`, all-or-none —
drive the ordering gate: the latest accepted version per (namespace, external subject) is stored
in `integration_entitlements`, events not newer are transactionally acknowledged-and-ignored,
and every decided event id is recorded in `integration_events` so replays answer idempotently
(no second invitation; replay-after-accept resurrects nothing). Both tables are event-kind
generic — the offboarding verb (1.15) plugs into the same gate.

**Non-enumeration:** the verb answers **201 with the same three keys whatever the prior state**
(`invitation_id`, `invitation_code`, `email`); the gate's ignore/replay answer is the same shape
with nulls. There is no invited/active/not-found distinction to probe.

**Notifications:** the `issued` event carries the addressed recipient; apps opt into recipient
notices by adding `'issued' => ['holder']` to `built-for-cloud.notifications.policy`
(unaddressed invitations notify nobody either way). The notification carries ids only — the
code's ONE egress is the verb's response/TTY reveal, and the caller owns delivering the accept
link.

`ContractAssertions` gains `assertBuiltForCloudInvitationTransportParity()`, wired into
`assertBuiltForCloudTransportParityContract()`.
