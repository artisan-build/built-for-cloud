<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresHolderResolution;
use ArtisanBuild\BuiltForCloud\Notifications\CredentialLifecycleNotification;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Notification;
use Throwable;

/**
 * The one lifecycle-notification policy (PRD 1.16): event × declared
 * recipient (`issuer`, `holder`), one table, both SEC-6 notices as rows in
 * it — the issuer notified on exchange, the intended recipient notified on
 * first use. Extensible per app via the
 * `built-for-cloud.notifications.policy` config key.
 *
 * "Holder" resolves in this order, and NOBODY is a first-class answer:
 *
 * 1. The event's intended recipient, where the code was addressed at all.
 * 2. The app declaration's {@see DeclaresHolderResolution}, where it
 *    implements one — a bound user's email, or null.
 * 3. Nobody. An unbound subject notifies no one; there is no operator
 *    fallback to spam.
 *
 * Every resolved address — the operator's issuer config and the
 * declaration's holder answer alike — is validated here, at the delivery
 * boundary: a value that is not a plain email address, or that carries
 * CR/LF (header injection), is rejected to the NOBODY path with a log line
 * that never echoes the value.
 */
final class LifecycleNotifier
{
    public function __construct(private readonly CredentialDeclaration $declaration) {}

    /**
     * The validated, deduplicated recipient addresses this event notifies
     * under the current policy, in policy order.
     *
     * @return list<string>
     */
    public function recipientEmails(CredentialAuditEvent $event): array
    {
        $policy = config('built-for-cloud.notifications.policy', []);

        if (! is_array($policy)) {
            return [];
        }

        /** @var mixed $declared */
        $declared = $policy[$event->event->value] ?? [];

        if (! is_array($declared)) {
            return [];
        }

        $emails = [];

        foreach ($declared as $recipient) {
            $email = match ($recipient) {
                'issuer' => $this->issuerEmail(),
                'holder' => $this->holderEmail($event),
                default => null,
            };

            if (! is_string($recipient) || $email === null) {
                continue;
            }

            $email = $this->validatedAddress($email, $recipient, $event);

            if ($email !== null && ! in_array($email, $emails, true)) {
                $emails[] = $email;
            }
        }

        return $emails;
    }

    /**
     * Send this event's notice to ONE recipient. The drainer calls this
     * per address so it can mark each delivery individually.
     */
    public function deliverTo(string $email, CredentialAuditEvent $event): void
    {
        Notification::route('mail', $email)
            ->notify(CredentialLifecycleNotification::about($event));
    }

    /**
     * The issuer notice address for this instance — the party that hands
     * out codes and credentials here. Null (the default) declares no
     * issuer inbox, and issuer rows in the policy then notify no one.
     */
    private function issuerEmail(): ?string
    {
        $email = config('built-for-cloud.notifications.issuer');

        return is_string($email) && $email !== '' ? $email : null;
    }

    private function holderEmail(CredentialAuditEvent $event): ?string
    {
        if ($event->recipient !== null) {
            return $event->recipient;
        }

        if ($event->credential_id !== null && $this->declaration instanceof DeclaresHolderResolution) {
            return $this->declaration->resolveHolderEmail($event->credential_id);
        }

        return null;
    }

    /**
     * A resolved address must be a plain email with no CR/LF before it may
     * address a delivery. Rejection IS the nobody path — never a fallback
     * — and the log line names the role, never the value: the value came
     * from config or an app hook and may be attacker-influenced.
     */
    private function validatedAddress(string $email, string $recipient, CredentialAuditEvent $event): ?string
    {
        if (strpbrk($email, "\r\n") === false && filter_var($email, FILTER_VALIDATE_EMAIL) !== false) {
            return $email;
        }

        try {
            Log::warning('Built for Cloud rejected a resolved notification address; notifying nobody for that recipient instead.', [
                'recipient' => $recipient,
                'event' => $event->event->value,
            ]);
        } catch (Throwable) {
            // Failing to log must not turn a rejected address into a crash.
        }

        return null;
    }
}
