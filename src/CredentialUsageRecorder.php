<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use Illuminate\Support\Facades\DB;

/**
 * The unified store's usage transition — the same SEC-2 shape
 * {@see TokenRegistry} gives `api_tokens`, so the claim-code burn stays
 * intact when the exchange seam mints `credentials` rows (PRD 1.0):
 *
 * - Returns whether the authentication STANDS: every write is gated on
 *   affected rows carrying the full active predicate, so a row revoked or
 *   expired between the resolving read and this write fails here and never
 *   completes a request.
 * - A FIRST use runs the atomic first-use transition: first-use detection
 *   and claim-code consumption are ONE transaction, and the `first_used`
 *   audit event rides it (SEC-V3-09). This is the burn point for
 *   `first_use` declarations whose durables live in the unified store.
 */
final class CredentialUsageRecorder
{
    public function __construct(private readonly LifecycleEventRecorder $recorder) {}

    public function recordUsage(Credential $credential): bool
    {
        if ($credential->last_used_at !== null) {
            return $this->recordSubsequentUse($credential);
        }

        return $this->burnFirstUse($credential);
    }

    private function recordSubsequentUse(Credential $credential): bool
    {
        return Credential::query()
            ->whereKey($credential->getKey())
            ->active()
            ->update(['last_used_at' => now()]) === 1;
    }

    private function burnFirstUse(Credential $credential): bool
    {
        return (bool) DB::transaction(function () use ($credential): bool {
            // Code-then-durable lock order, matching exchange — see
            // TokenRegistry::burnFirstUse for why. Only codes RECORDED
            // into the unified store: api_tokens linkages (including the
            // null backfill) are the legacy registry's to burn.
            /** @var list<OnboardingToken> $pendingCodes */
            $pendingCodes = OnboardingToken::query()
                ->where('durable_token_id', $credential->getKey())
                ->where('durable_store', DurableStore::Credentials->value)
                ->whereNull('consumed_at')
                ->lockForUpdate()
                ->get(['id', 'email'])
                ->all();

            $codeIds = array_map(static fn (OnboardingToken $code): string => $code->id, $pendingCodes);

            $wasFirst = Credential::query()
                ->whereKey($credential->getKey())
                ->whereNull('last_used_at')
                ->active()
                ->update(['last_used_at' => now()]) === 1;

            if (! $wasFirst) {
                return $this->recordSubsequentUse($credential);
            }

            $burned = 0;

            if ($codeIds !== []) {
                $burned = OnboardingToken::query()
                    ->whereIn('id', $codeIds)
                    ->where('durable_token_id', $credential->getKey())
                    ->whereNull('consumed_at')
                    ->update(['consumed_at' => now()]);
            }

            $linkedCode = $burned > 0 ? $pendingCodes[0] : $this->consumedCodeFor($credential);

            $this->recorder->record(
                event: LifecycleEventType::FirstUsed,
                credentialId: (string) $credential->getKey(),
                codeId: $linkedCode?->id,
                actor: AuditActor::credentialHolder((string) $credential->getKey()),
                recipient: $linkedCode?->email,
            );

            return true;
        });
    }

    private function consumedCodeFor(Credential $credential): ?OnboardingToken
    {
        /** @var OnboardingToken|null */
        return OnboardingToken::query()
            ->where('durable_token_id', $credential->getKey())
            ->where('durable_store', DurableStore::Credentials->value)
            ->whereNotNull('consumed_at')
            ->orderByDesc('consumed_at')
            ->first(['id', 'email']);
    }
}
