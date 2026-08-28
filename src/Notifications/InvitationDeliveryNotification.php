<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Notifications;

use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;
use SensitiveParameter;

/**
 * The DELIVERY of an integration-issued invitation (D1e: the integration
 * triggers, the instance delivers): the addressed invitee receives the
 * invitation code by mail, because on that path the caller deliberately
 * receives nothing to deliver (SEC-V3-05 non-enumeration) — this mail IS
 * the code's one documented egress.
 *
 * Deliberately NOT queued and never to be made queueable: a queued
 * notification payload is a database row (D7), and this one carries a
 * plaintext code. It is sent synchronously after the issuing transaction
 * commits. This is distinct from {@see CredentialLifecycleNotification},
 * the ids-only policy notice.
 */
final class InvitationDeliveryNotification extends Notification
{
    public function __construct(
        public readonly string $invitationId,
        #[SensitiveParameter] public readonly string $invitationCode,
    ) {}

    /**
     * @return list<string>
     */
    public function via(object $notifiable): array
    {
        return ['mail'];
    }

    public function toMail(object $notifiable): MailMessage
    {
        return (new MailMessage)
            ->subject('You have been invited')
            ->line('You have been invited to create an account.')
            ->line('Your invitation code - usable once: '.$this->invitationCode)
            ->line('Invitation id: '.$this->invitationId)
            ->line('If you were not expecting this invitation, ignore it; it expires on its own.');
    }
}
