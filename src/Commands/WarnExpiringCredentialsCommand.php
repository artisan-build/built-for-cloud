<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Commands;

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use Illuminate\Console\Command;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;

/**
 * The conditional expiry warning (PRD 1.3, v2.1 adjustment): when — and
 * ONLY when — an issuer chose an `expires_at` on a durable, an `expiring`
 * event is emitted through the stream ahead of the lapse, and the holder
 * is warned via the notification policy. A durable without expiry never
 * warns, because nothing here ever nudges anyone toward setting one:
 * revocation-on-event, not expiry, is the intended lifecycle end.
 *
 * Schedule it however the app schedules things; running it twice is safe —
 * the outbox dedup key makes the warning once-per-expiry even across
 * concurrent runs.
 */
final class WarnExpiringCredentialsCommand extends Command
{
    protected $signature = 'bfc:credentials:warn-expiring {--window-hours= : Override the configured warning window}';

    protected $description = 'Emit an expiring lifecycle event for durables whose chosen expiry is inside the warning window';

    public function handle(LifecycleEventRecorder $recorder): int
    {
        $window = $this->windowHours();

        /** @var list<ApiToken> $expiring */
        $expiring = ApiToken::query()
            ->whereNotNull('expires_at')
            ->whereNull('revoked_at')
            // Rotation-grace rows are already superseded and bounded by
            // design; warning about them would be noise.
            ->whereNull('rotated_at')
            ->where('expires_at', '>', now())
            ->where('expires_at', '<=', now()->addHours($window))
            ->get()
            ->all();

        $warned = 0;

        foreach ($expiring as $token) {
            if ($this->emitWarning($recorder, $token, $window)) {
                $warned++;
            }
        }

        $this->line("Warned about {$warned} expiring credential(s).");

        return self::SUCCESS;
    }

    private function emitWarning(LifecycleEventRecorder $recorder, ApiToken $token, int $window): bool
    {
        $expiresAt = $token->expires_at;

        if ($expiresAt === null) {
            return false;
        }

        // Once per credential per chosen expiry: an issuer who extends the
        // expiry re-arms the warning for the new date. The existence check
        // keeps re-runs quiet; the dedup key below is what makes even a
        // concurrent double-run emit once.
        $alreadyWarned = CredentialAuditEvent::query()
            ->where('event', LifecycleEventType::Expiring->value)
            ->where('credential_id', $token->getKey())
            ->where('credential_expires_at', $expiresAt)
            ->exists();

        if ($alreadyWarned) {
            return false;
        }

        try {
            return (bool) DB::transaction(function () use ($recorder, $token, $expiresAt, $window): bool {
                // Re-assert eligibility under lock, with the SAME predicates
                // the outer query used: the world can change between the
                // select and this transaction (a revoke, a rotation, an
                // extended expiry), and a warning about a dead or moved row
                // would be a false notice. Stale rows are skipped silently —
                // the next scheduled run sees the current truth.
                $stillEligible = ApiToken::query()
                    ->whereKey($token->getKey())
                    ->whereNull('revoked_at')
                    ->whereNull('rotated_at')
                    ->where('expires_at', $expiresAt)
                    ->where('expires_at', '>', now())
                    ->where('expires_at', '<=', now()->addHours($window))
                    ->lockForUpdate()
                    ->exists();

                if (! $stillEligible) {
                    return false;
                }

                $recorder->record(
                    event: LifecycleEventType::Expiring,
                    credentialId: (string) $token->getKey(),
                    credentialExpiresAt: $expiresAt,
                    dedupKey: 'expiring:'.$token->getKey().':'.$expiresAt->getTimestamp(),
                );

                return true;
            });
        } catch (UniqueConstraintViolationException) {
            // A concurrent run won the dedup key; its warning stands.
            return false;
        }
    }

    private function windowHours(): int
    {
        $option = $this->option('window-hours');

        if (is_numeric($option)) {
            return max(1, (int) $option);
        }

        $configured = config('built-for-cloud.lifetimes.expiry_warning_hours', 72);

        return max(1, (int) (is_numeric($configured) ? $configured : 72));
    }
}
