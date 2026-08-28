<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

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
            ApiToken::query()->whereKey($row->getKey())->update([
                'request_count' => DB::raw('request_count + 1'),
                'last_used_at' => now(),
            ]);

            return true;
        }

        return $this->burnFirstUse($row);
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
            $codeIds = OnboardingToken::query()
                ->where('durable_token_id', $row->getKey())
                ->whereNull('consumed_at')
                ->lockForUpdate()
                ->pluck('id')
                ->all();

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
                // won OR the row changed under us. Re-read to tell them
                // apart.
                $stillResolvable = ApiToken::query()
                    ->whereKey($row->getKey())
                    ->resolvable()
                    ->exists();

                if (! $stillResolvable) {
                    // Revoked or expired between our read and our write: the
                    // authentication FAILS, and a dead row gets no usage
                    // bump. The code is left to its current linkage — if a
                    // re-claim relinked it, the new durable governs it now.
                    return false;
                }

                // Still live, merely already used: today's fast-path bump.
                ApiToken::query()->whereKey($row->getKey())->update([
                    'request_count' => DB::raw('request_count + 1'),
                    'last_used_at' => now(),
                ]);

                return true;
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
            if ($codeIds !== []) {
                OnboardingToken::query()
                    ->whereIn('id', $codeIds)
                    ->where('durable_token_id', $row->getKey())
                    ->whereNull('consumed_at')
                    ->update(['consumed_at' => now()]);
            }

            return true;
        });
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

    public function rotate(string $name, string $newHash, bool $emergency = false): ApiToken
    {
        $newToken = $this->store($name, $newHash);
        $expiresAt = $emergency ? now() : now()->addHour();

        ApiToken::query()
            ->where('name', $name)
            ->whereKeyNot($newToken->getKey())
            ->resolvable()
            ->update(['expires_at' => $expiresAt]);

        return $newToken;
    }

    public function revoke(string $name): int
    {
        $now = now();

        return ApiToken::query()
            ->where('name', $name)
            ->resolvable()
            ->update([
                'expires_at' => $now,
                'revoked_at' => $now,
            ]);
    }
}
