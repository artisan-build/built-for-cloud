<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Exceptions\RotationCutoverIncomplete;
use ArtisanBuild\BuiltForCloud\Exceptions\RotationRefused;
use Carbon\CarbonInterface;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use InvalidArgumentException;
use Throwable;

final class TokenRegistry
{
    public const FALLBACK = 'fallback';

    public function resolve(string $bearer): ?string
    {
        if ($bearer === '') {
            return null;
        }

        $fallback = config('built-for-cloud.fallback_token');

        if ($fallback !== null && $fallback !== '' && hash_equals(hash('sha256', (string) $fallback), hash('sha256', $bearer))) {
            return self::FALLBACK;
        }

        /** @var ApiToken|null $row */
        $row = ApiToken::query()
            ->where('token_hash', hash('sha256', $bearer))
            ->resolvable()
            ->first();

        if ($row === null) {
            return null;
        }

        if (! $this->recordUsage($row)) {
            return null;
        }

        return $row->name;
    }

    public function resolveModel(string $bearer): ?ApiToken
    {
        if ($bearer === '') {
            return null;
        }

        $fallback = config('built-for-cloud.fallback_token');

        if ($fallback !== null && $fallback !== '' && hash_equals(hash('sha256', (string) $fallback), hash('sha256', $bearer))) {
            return null;
        }

        /** @var ApiToken|null $row */
        $row = ApiToken::query()
            ->where('token_hash', hash('sha256', $bearer))
            ->resolvable()
            ->first();

        if ($row === null) {
            return null;
        }

        if (! $this->recordUsage($row)) {
            return null;
        }

        return $row->refresh();
    }

    /**
     * Record a successful presentation. Returns whether the authentication
     * STANDS: a row revoked or expired between the resolving read and the
     * usage write fails here, so a re-claimed-under-us credential never
     * completes a request.
     *
     * Subsequent uses take today's cheap unconditional update; a FIRST use
     * runs the atomic first-use transition (SEC-2, PRD 1.2): first-use
     * detection and claim-code consumption are ONE transaction, entered by
     * a conditional update gated on affected rows. This is the burn point
     * for `first_use` providers, and it fires for WHATEVER presented the
     * secret and resolved the row — bearer and Crate's HTTP Basic path
     * alike.
     */
    private function recordUsage(ApiToken $row): bool
    {
        if ($row->last_used_at !== null) {
            return $this->recordSubsequentUse($row);
        }

        return $this->burnFirstUse($row);
    }

    /**
     * The already-used path. The bump itself re-asserts resolvability and
     * is gated on affected rows: zero rows means the credential died
     * between the resolving read and this write, and a dead row neither
     * authenticates nor takes a bump.
     */
    private function recordSubsequentUse(ApiToken $row): bool
    {
        return ApiToken::query()
            ->whereKey($row->getKey())
            ->resolvable()
            ->update([
                'request_count' => DB::raw('request_count + 1'),
                'last_used_at' => now(),
            ]) === 1;
    }

    private function burnFirstUse(ApiToken $row): bool
    {
        return (bool) DB::transaction(function () use ($row): bool {
            // Lock the linked code rows FIRST. Exchange acquires code (its
            // lockForUpdate lookup) then durable (revocations, mint); the
            // burn must acquire in the SAME code-then-durable order, or the
            // two transactions deadlock against each other. Holding the lock
            // also freezes the linkage: no re-claim can relink the code
            // while this burn is in flight.
            // Only codes RECORDED into this store (null = the api_tokens
            // backfill): a linkage into the unified store is burned by the
            // unified recorder, never here.
            /** @var list<OnboardingToken> $pendingCodes */
            $pendingCodes = OnboardingToken::query()
                ->where('durable_token_id', $row->getKey())
                ->where(function ($query): void {
                    $query->whereNull('durable_store')
                        ->orWhere('durable_store', DurableStore::ApiTokens->value);
                })
                ->whereNull('consumed_at')
                ->lockForUpdate()
                ->get(['id', 'email'])
                ->all();

            $codeIds = array_map(static fn (OnboardingToken $code): string => $code->id, $pendingCodes);

            // The gate re-asserts the FULL resolvability predicate, not just
            // last_used_at: between the resolving read and this write a
            // re-claim may have revoked the row (or its expiry passed), and
            // `last_used_at IS NULL` alone would let a revoked credential
            // authenticate.
            $wasFirst = ApiToken::query()
                ->whereKey($row->getKey())
                ->whereNull('last_used_at')
                ->resolvable()
                ->update([
                    'request_count' => DB::raw('request_count + 1'),
                    'last_used_at' => now(),
                ]) === 1;

            if (! $wasFirst) {
                // Zero affected rows means EITHER someone else's first use
                // won OR the row changed under us. The recovery bump itself
                // decides: it carries the resolvability predicate and is
                // gated on affected rows, so a row revoked or expired at any
                // point up to THIS write fails authentication with no bump —
                // and if it succeeds, the row was live and merely already
                // used. The code is left to its current linkage either way —
                // if a re-claim relinked it, the new durable governs it now.
                return $this->recordSubsequentUse($row);
            }

            // We were first: consume the code in the SAME transaction as the
            // usage write, so a process dying between the two rolls back
            // both. The write stays gated on the linkage and pending state
            // we locked above; zero affected rows would mean the code was
            // relinked or consumed before we locked it — the authentication
            // stands (this row just proved live) but the burn is not ours to
            // complete, and the code stays governed by its current linkage.
            // Nothing is logged: there is no actionable detail that is also
            // secret-free. Under `at_exchange` the code is already consumed
            // and $codeIds is empty. Empty either way is not a failure.
            $burned = 0;

            if ($codeIds !== []) {
                $burned = OnboardingToken::query()
                    ->whereIn('id', $codeIds)
                    ->where('durable_token_id', $row->getKey())
                    ->whereNull('consumed_at')
                    ->update(['consumed_at' => now()]);
            }

            // The audit `first_used` event, in the SAME transaction as the
            // burn (SEC-V3-09). The code linkage names the code this
            // credential came from: the one burned here, or — under
            // `at_exchange`, where redemption already consumed it — the
            // consumed code still pointing at this durable. The intended
            // recipient rides along where the code was addressed, so the
            // first-use notice (SEC-6) can reach them.
            $linkedCode = $burned > 0 ? $pendingCodes[0] : $this->consumedCodeFor($row);

            $this->recorder()->record(
                event: LifecycleEventType::FirstUsed,
                credentialId: (string) $row->getKey(),
                codeId: $linkedCode?->id,
                actor: AuditActor::credentialHolder((string) $row->getKey()),
                recipient: $linkedCode?->email,
            );

            return true;
        });
    }

    private function consumedCodeFor(ApiToken $row): ?OnboardingToken
    {
        /** @var OnboardingToken|null */
        return OnboardingToken::query()
            ->where('durable_token_id', $row->getKey())
            ->where(function ($query): void {
                $query->whereNull('durable_store')
                    ->orWhere('durable_store', DurableStore::ApiTokens->value);
            })
            ->whereNotNull('consumed_at')
            ->orderByDesc('consumed_at')
            ->first(['id', 'email']);
    }

    /**
     * Record the client identity carried by a request, if it carries a conforming one.
     *
     * Best-effort by design, and the only entry point request handling should use. Attribution
     * must never break the customer's request, so an absent header touches nothing, a malformed
     * one is logged and dropped, and a Throwable from either the write or the log is swallowed.
     * The write can legitimately fail: the column inherits the consuming app's charset, so a
     * contract-VALID identity -- a four-byte emoji on a utf8mb3 or latin1 table -- can throw in
     * strict mode. That is a reason to guard the write, not to narrow the contract further.
     * (A NUL byte is a different problem and is rejected up front by ClientIdentity: PostgreSQL
     * truncates it silently instead of throwing, so no guard here would ever see it.)
     */
    public function recordClientIdentityFromRequest(Request $request, ApiToken $token): void
    {
        $values = $request->headers->all(ClientIdentity::HEADER);

        if ($values === []) {
            return;
        }

        try {
            $identity = ClientIdentity::fromRequest($request);

            if ($identity !== null) {
                $this->recordClientIdentity($token, $identity);

                return;
            }

            $this->warnAboutMalformedClientIdentity($values);
        } catch (Throwable $e) {
            $this->reportClientIdentityFailure($e);
        }
    }

    /**
     * Observe a client identity claimed on a request that authenticated NOTHING.
     *
     * ADVISORY ONLY, and off unless the provider opts in. The identity is unauthenticated and
     * trivially spoofable, so this never grants anything and never influences the response — the
     * caller gets exactly the 401 it was already going to get.
     *
     * Call this ONLY on a genuine no-credential path. A 403 means the caller HAS a working
     * credential and merely lacks the scope, which is not a NoCredential event; the fallback token
     * authenticates, so it is not one either.
     */
    public function observeUnauthenticatedClientIdentity(Request $request): void
    {
        if (! (bool) config('built-for-cloud.client_identity.observe_unauthenticated', false)) {
            return;
        }

        if ($request->headers->all(ClientIdentity::HEADER) === []) {
            return;
        }

        try {
            $identity = ClientIdentity::fromRequest($request);

            // A malformed header is dropped and never observed. Deliberately NOT logged here:
            // this path is unauthenticated and unthrottled, so a log line per malformed request
            // would be an amplification an attacker controls. The authenticated path still logs.
            if ($identity === null) {
                return;
            }

            $this->storeObservation($identity);
        } catch (Throwable) {
            // Deliberately SILENT, and deliberately asymmetric with the authenticated path
            // above, which does log its failures. That path requires a valid token; this one
            // does not, and it is unthrottled, so one log line per request is an amplification
            // the caller controls. It is not hypothetical: a contract-VALID four-byte identity
            // fails on every insert against a utf8mb3 table, and a missing table mid-rollout
            // behaves the same way. Do not "fix" this back into a log.
        }
    }

    /**
     * Increment an existing identity, or insert a new one while there is room under the cap.
     *
     * At the cap a NEW identity is dropped and NOTHING is evicted: preserving the earliest-seen
     * real signal is the point, since an attacker able to spray unbounded distinct identities
     * could otherwise push the genuine client out of the table.
     */
    private function storeObservation(string $identity): void
    {
        // Key on a digest of the EXACT bytes. `client_identity` inherits the consuming app's
        // collation, and a case-insensitive one -- MySQL's utf8mb4_0900_ai_ci default among
        // them -- compares `client-a` and `CLIENT-A` as equal, silently collapsing two distinct
        // clients into one row and corrupting the signal this feature exists to provide.
        $hash = hash('sha256', $identity);

        if ($this->incrementObservation($hash)) {
            return;
        }

        $max = (int) config('built-for-cloud.client_identity.max_observations', 100);

        if (ClientIdentityObservation::query()->count() >= $max) {
            return;
        }

        $now = now();

        try {
            ClientIdentityObservation::query()->create([
                'client_identity' => $identity,
                'client_identity_hash' => $hash,
                'first_seen_at' => $now,
                'last_seen_at' => $now,
                'observation_count' => 1,
            ]);
        } catch (UniqueConstraintViolationException) {
            // A concurrent request claiming the SAME new identity inserted between our lookup
            // and our insert. Increment the winner rather than losing the observation.
            $this->incrementObservation($hash);
        }
    }

    /**
     * Bump an existing observation. Returns false when there is no row for this identity yet.
     */
    private function incrementObservation(string $hash): bool
    {
        return ClientIdentityObservation::query()
            ->where('client_identity_hash', $hash)
            ->update([
                'observation_count' => DB::raw('observation_count + 1'),
                'last_seen_at' => now(),
            ]) > 0;
    }

    /**
     * Record the opaque client identity that presented this token.
     *
     * The value is stored verbatim; `client_identity_last_seen_at` is bumped on every valid
     * presentation, not only when the identity changes. Last writer wins.
     */
    public function recordClientIdentity(ApiToken $token, string $identity): bool
    {
        if (! ClientIdentity::isValid($identity)) {
            return false;
        }

        ApiToken::query()->whereKey($token->getKey())->update([
            'client_identity' => $identity,
            'client_identity_last_seen_at' => now(),
        ]);

        $token->refresh();

        return true;
    }

    /**
     * @param  array<int, string|null>  $values
     */
    private function warnAboutMalformedClientIdentity(array $values): void
    {
        $only = count($values) === 1 ? $values[array_key_first($values)] : null;

        // Never log the value itself: it is attacker-controlled and unvalidated.
        Log::warning('Built for Cloud discarded a malformed client identity header.', [
            'header' => ClientIdentity::HEADER,
            'values' => count($values),
            'bytes' => is_string($only) ? strlen($only) : null,
            'reason' => is_string($only)
                ? ClientIdentity::rejectionReason($only)
                : 'not exactly one header value',
        ]);
    }

    private function reportClientIdentityFailure(Throwable $e): void
    {
        try {
            // Only the exception CLASS: a driver message can echo the bound value back, and the
            // identity is attacker-controlled. Failing to log must not escape either.
            Log::warning('Built for Cloud could not record a client identity.', [
                'header' => ClientIdentity::HEADER,
                'exception' => $e::class,
            ]);
        } catch (Throwable) {
            // Nothing left to do without breaking the request this is meant to protect.
        }
    }

    /**
     * @param  list<string>  $abilities
     */
    public function store(string $name, string $hash, ?CarbonInterface $expiresAt = null, array $abilities = []): ApiToken
    {
        if ($name === self::FALLBACK) {
            throw new InvalidArgumentException('The fallback token name is reserved.');
        }

        if (! preg_match('/^[0-9a-f]{64}$/', $hash)) {
            throw new InvalidArgumentException('A token hash must be a sha256 hex digest.');
        }

        return ApiToken::query()->create([
            'name' => $name,
            'token_hash' => $hash,
            'expires_at' => $expiresAt,
            'revoked_at' => null,
            'abilities' => $abilities === [] ? null : $abilities,
        ]);
    }

    /**
     * Rotate by NAME — the CLI-compatibility verb, now with D6's corrected
     * semantics (SEC-5): it resolves the ONE resolvable row of the name and
     * delegates to {@see rotateById}, and it REFUSES whenever more than one
     * resolvable row shares the name — never picking a winner, because with
     * matching names one row can expire in an hour and another never, and
     * nothing says which lifetime the replacement should inherit. It also
     * refuses a name with NO resolvable row: rotation replaces; the mint
     * verbs create.
     */
    public function rotate(string $name, string $newHash, bool $emergency = false, ?AuditActor $actor = null): ApiToken
    {
        /** @var list<string> $sourceIds */
        $sourceIds = ApiToken::query()
            ->where('name', $name)
            ->resolvable()
            ->pluck('id')
            ->all();

        if (count($sourceIds) > 1) {
            throw RotationRefused::ambiguousName($name, count($sourceIds));
        }

        if ($sourceIds === []) {
            throw RotationRefused::unknownName($name);
        }

        // The name path cannot reach cutover completion: a stamped row
        // with a live same-name successor is two resolvable rows (the
        // ambiguity refusal above), and with the successor dead the
        // completion does not qualify — so the returned token is always
        // the row minted from $newHash, and callers may print the
        // matching plaintext.
        return $this->rotateById($sourceIds[0], $newHash, $emergency, $actor)->token;
    }

    /**
     * Rotate by ID — the primary verb (PRD 1.7, D6). The replacement
     * inherits the EXACT ability set, the subject binding, and the
     * remaining expiry of the row it replaces (the D6 defect fix: the old
     * implementation stored the replacement unscoped and non-expiring, and
     * `hasAbility()` fails closed, so rotation BROKE every scoped caller).
     *
     * Two phases, matching the unified store's rotate verb:
     *
     * 1. ONE transaction mints the replacement, stamps `rotated_at` on the
     *    old row — the provenance marker only this verb may assert,
     *    emergency included; the claim-code exchange sweep spares marked
     *    rows — and records `issued` + `rotated` (old → new lineage, D8).
     *    A follow-up write failing rolls all of it back: no orphan, retry
     *    works (failure path A).
     * 2. A separate write sets the old row's grace expiry (one hour; NOW
     *    under emergency), never extending an earlier one. If it fails,
     *    the replacement stands and {@see RotationCutoverIncomplete} names
     *    the still-live old row (failure path B).
     *
     * Re-invoking the verb on a `rotated_at`-stamped row NEVER mints again
     * (the lineage never forks): with a lineage-verified live successor it
     * performs the CUTOVER COMPLETION — the retirement write only, audited
     * with its own reason — which is failure path B's recovery under the
     * rotation's own authority, and the emergency kill of a graced old
     * row. With no live successor it refuses. On the completion path the
     * caller's $newHash is never stored, and the result says so
     * ({@see LegacyRotationResult}) — a transport must not present its
     * pre-generated plaintext.
     */
    public function rotateById(string $id, string $newHash, bool $emergency = false, ?AuditActor $actor = null): LegacyRotationResult
    {
        /** @var LegacyRotationResult $result */
        $result = DB::transaction(function () use ($id, $newHash, $emergency, $actor): LegacyRotationResult {
            /** @var ApiToken|null $source */
            $source = ApiToken::query()
                ->whereKey($id)
                ->resolvable()
                ->lockForUpdate()
                ->first();

            if ($source === null) {
                throw RotationRefused::sourceNotResolvable($id);
            }

            if ($source->rotated_at !== null) {
                return $this->completeRotationCutover($source, $actor);
            }

            $newToken = $this->store(
                $source->name,
                $newHash,
                $source->expires_at,
                $source->abilities ?? [],
            );

            // The subject binding rides along (PRD 1.7 point 3); store()
            // predates subjects, so it is stamped here, same transaction.
            if ($source->subject_type !== null) {
                ApiToken::query()
                    ->whereKey($newToken->getKey())
                    ->update([
                        'subject_type' => $source->subject_type,
                        'subject_ref' => $source->subject_ref,
                    ]);
            }

            ApiToken::query()
                ->whereKey($source->getKey())
                ->update(['rotated_at' => now()]);

            $reason = $emergency ? AuditReason::Emergency : AuditReason::Rotation;

            $this->recorder()->record(
                event: LifecycleEventType::Issued,
                credentialId: (string) $newToken->getKey(),
                actor: $actor,
                credentialExpiresAt: $source->expires_at,
                reason: $reason,
            );

            $this->recorder()->record(
                event: LifecycleEventType::Rotated,
                credentialId: (string) $source->getKey(),
                actor: $actor,
                reason: $reason,
                supersededByCredentialId: (string) $newToken->getKey(),
            );

            return new LegacyRotationResult($newToken, (string) $source->getKey());
        });

        try {
            $this->retireRotatedRow($id, $emergency);
        } catch (Throwable $exception) {
            throw RotationCutoverIncomplete::retirementFailed($id, (string) $result->token->getKey(), $exception);
        }

        return new LegacyRotationResult($result->token->refresh(), $result->supersededId, $result->completedCutover);
    }

    /**
     * The completion half of {@see rotateById}: the stamped row's live
     * successor is looked up through the audit lineage and must itself
     * still resolve — only then does re-invoking the verb retire the old
     * row (the phase-2 write that follows in rotateById), audited with
     * its own reason and minting NOTHING. Not a revoke bypass: an
     * unstamped row never reaches here, and a stamped row whose chain is
     * dead refuses.
     */
    private function completeRotationCutover(ApiToken $source, ?AuditActor $actor): LegacyRotationResult
    {
        $id = (string) $source->getKey();
        $successorId = $this->rotationSuccessorOf($id);

        /** @var ApiToken|null $successor */
        $successor = $successorId === null
            ? null
            : ApiToken::query()->whereKey($successorId)->resolvable()->first();

        if ($successor === null) {
            throw RotationRefused::alreadyRotated($id, $successorId);
        }

        $this->recorder()->record(
            event: LifecycleEventType::Rotated,
            credentialId: $id,
            actor: $actor,
            reason: AuditReason::CutoverCompletion,
            supersededByCredentialId: (string) $successor->getKey(),
        );

        return new LegacyRotationResult($successor, $id, true);
    }

    /**
     * The most recent successor the audit lineage records for a rotated
     * row, so a refused re-rotation can point at the row to rotate
     * instead.
     */
    private function rotationSuccessorOf(string $id): ?string
    {
        $successor = CredentialAuditEvent::query()
            ->where('credential_id', $id)
            ->where('event', LifecycleEventType::Rotated->value)
            ->orderByDesc('occurred_at')
            ->value('superseded_by_credential_id');

        return is_string($successor) && $successor !== '' ? $successor : null;
    }

    /**
     * The cutover (phase 2): the superseded row's expiry becomes the grace
     * end, at which point it dies by its own expiry — no reaper. The
     * guarded predicate is the never-extend rule: a row already expiring
     * earlier keeps its earlier death.
     */
    private function retireRotatedRow(string $id, bool $emergency): void
    {
        $graceEnd = $emergency ? now() : now()->addHour();

        ApiToken::query()
            ->whereKey($id)
            ->where(function ($query) use ($graceEnd): void {
                $query->whereNull('expires_at')->orWhere('expires_at', '>', $graceEnd);
            })
            ->update(['expires_at' => $graceEnd]);
    }

    /**
     * The PRECISE revoke verb (D2 consequence 1, D6): kill exactly one row
     * by id — a same-named sibling (a rotation grace row, another install's
     * credential) survives untouched. `revoke()` below stays the CLI-compat
     * name verb and keeps its existing semantics: it expires EVERY
     * resolvable row of the name.
     *
     * The predicate is RESOLVABILITY, not `revoked_at`: resolution ignores
     * `revoked_at` (test-pinned legacy semantics — expiry is what kills),
     * so an anomalous row carrying `revoked_at` with no effective expiry
     * (an import, a manual repair) still authenticates. This verb kills
     * whatever still resolves — stamping `expires_at` and, only where it
     * is null, `revoked_at` — and thereby REPAIRS that anomaly on contact,
     * with the audit event a real death deserves. Package verbs can no
     * longer produce or leave behind the anomalous state.
     *
     * Idempotent only on rows that are already DEAD (expired — the one
     * state that no longer authenticates): a no-op returning false, no
     * second `revoked` audit event for the same death. Never a silent
     * no-op on a row that still resolves.
     */
    public function revokeById(string $id, ?AuditActor $actor = null, AuditReason $reason = AuditReason::OperatorRequest): bool
    {
        return (bool) DB::transaction(function () use ($id, $actor, $reason): bool {
            /** @var ApiToken|null $live */
            $live = ApiToken::query()
                ->whereKey($id)
                ->resolvable()
                ->lockForUpdate()
                ->first(['id', 'revoked_at']);

            if ($live === null) {
                return false;
            }

            $now = now();

            ApiToken::query()
                ->whereKey($id)
                ->update([
                    'expires_at' => $now,
                    // An anomalous row keeps its original revocation stamp;
                    // the expiry above is what makes it true.
                    'revoked_at' => $live->revoked_at ?? $now,
                ]);

            $this->recorder()->record(
                event: LifecycleEventType::Revoked,
                credentialId: $id,
                actor: $actor,
                reason: $reason,
            );

            return true;
        });
    }

    public function revoke(string $name, ?AuditActor $actor = null, AuditReason $reason = AuditReason::OperatorRequest): int
    {
        return DB::transaction(function () use ($name, $actor, $reason): int {
            /** @var list<string> $ids */
            $ids = ApiToken::query()
                ->where('name', $name)
                ->resolvable()
                ->lockForUpdate()
                ->pluck('id')
                ->all();

            return $this->revokeIds($ids, $actor, $reason);
        });
    }

    /**
     * Revoke EXACTLY these rows — the write is keyed on ids, never on a
     * name, so a caller that authorized an id set revokes that set and
     * nothing else: a same-named row created after the caller's locked
     * select is simply not in this revocation (and never dies
     * unauthorized). Rows in the list that are already dead are skipped —
     * no second audit event for the same death. Returns how many rows
     * actually died.
     *
     * @param  list<string>  $ids
     */
    public function revokeIds(array $ids, ?AuditActor $actor = null, AuditReason $reason = AuditReason::OperatorRequest): int
    {
        if ($ids === []) {
            return 0;
        }

        return DB::transaction(function () use ($ids, $actor, $reason): int {
            /** @var list<string> $revokedIds */
            $revokedIds = ApiToken::query()
                ->whereIn('id', $ids)
                ->resolvable()
                ->lockForUpdate()
                ->pluck('id')
                ->all();

            if ($revokedIds === []) {
                return 0;
            }

            $now = now();

            $count = ApiToken::query()
                ->whereIn('id', $revokedIds)
                ->update([
                    'expires_at' => $now,
                    'revoked_at' => $now,
                ]);

            foreach ($revokedIds as $revokedId) {
                $this->recorder()->record(
                    event: LifecycleEventType::Revoked,
                    credentialId: $revokedId,
                    actor: $actor,
                    reason: $reason,
                );
            }

            return $count;
        });
    }

    /**
     * Resolved lazily rather than via the constructor so `new TokenRegistry`
     * keeps working everywhere it already does.
     */
    private function recorder(): LifecycleEventRecorder
    {
        return app(LifecycleEventRecorder::class);
    }
}
