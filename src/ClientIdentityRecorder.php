<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Throwable;

final class ClientIdentityRecorder
{
    /**
     * Best-effort attribution of an authenticated unified credential.
     */
    public function recordClientIdentityFromRequest(Request $request, Credential $credential): void
    {
        $values = $request->headers->all(ClientIdentity::HEADER);

        if ($values === []) {
            return;
        }

        try {
            $identity = ClientIdentity::fromRequest($request);

            if ($identity !== null) {
                $this->recordClientIdentity($credential, $identity);

                return;
            }

            $this->warnAboutMalformedClientIdentity($values);
        } catch (Throwable $exception) {
            $this->reportClientIdentityFailure($exception);
        }
    }

    /**
     * Observe an advisory identity only when no credential authenticated.
     */
    public function observeUnauthenticatedClientIdentity(Request $request): void
    {
        if (! (bool) config('built-for-cloud.client_identity.observe_unauthenticated', false)
            || $request->headers->all(ClientIdentity::HEADER) === []) {
            return;
        }

        try {
            $identity = ClientIdentity::fromRequest($request);

            if ($identity !== null) {
                $this->storeObservation($identity);
            }
        } catch (Throwable) {
            // This unauthenticated path stays silent to prevent caller-controlled log amplification.
        }
    }

    /**
     * Store exact bytes and advance last-seen on every valid presentation.
     */
    public function recordClientIdentity(Credential $credential, string $identity): bool
    {
        if (! ClientIdentity::isValid($identity)) {
            return false;
        }

        Credential::query()->whereKey($credential->getKey())->update([
            'client_identity' => $identity,
            'client_identity_last_seen_at' => now(),
        ]);

        $credential->refresh();

        return true;
    }

    private function storeObservation(string $identity): void
    {
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
            $this->incrementObservation($hash);
        }
    }

    private function incrementObservation(string $hash): bool
    {
        return ClientIdentityObservation::query()
            ->where('client_identity_hash', $hash)
            ->update([
                'observation_count' => DB::raw('observation_count + 1'),
                'last_seen_at' => now(),
            ]) > 0;
    }

    /** @param array<int, string|null> $values */
    private function warnAboutMalformedClientIdentity(array $values): void
    {
        $only = count($values) === 1 ? $values[array_key_first($values)] : null;

        Log::warning('Built for Cloud discarded a malformed client identity header.', [
            'header' => ClientIdentity::HEADER,
            'values' => count($values),
            'bytes' => is_string($only) ? strlen($only) : null,
            'reason' => is_string($only)
                ? ClientIdentity::rejectionReason($only)
                : 'not exactly one header value',
        ]);
    }

    private function reportClientIdentityFailure(Throwable $exception): void
    {
        try {
            Log::warning('Built for Cloud could not record a client identity.', [
                'header' => ClientIdentity::HEADER,
                'exception' => $exception::class,
            ]);
        } catch (Throwable) {
            // Attribution cannot affect the authenticated request.
        }
    }
}
