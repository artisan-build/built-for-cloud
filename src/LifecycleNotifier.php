<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresHolderResolution;
use ArtisanBuild\BuiltForCloud\Notifications\CredentialLifecycleNotification;
use Illuminate\Support\Facades\Notification;

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
 */
final class LifecycleNotifier
{
    public function __construct(private readonly CredentialDeclaration $declaration) {}

    public function notify(CredentialAuditEvent $event): void
    {
        foreach ($this->recipientEmails($event) as $email) {
            Notification::route('mail', $email)
                ->notify(CredentialLifecycleNotification::about($event));
        }
    }

    /**
     * @return list<string>
     */
    private function recipientEmails(CredentialAuditEvent $event): array
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

            if ($email !== null && ! in_array($email, $emails, true)) {
                $emails[] = $email;
            }
        }

        return $emails;
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
}
