<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Notifications;

use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

/**
 * The one notification both SEC-6 notices (and every other policy row)
 * render through. Ids and metadata ONLY — never a secret, never a claim
 * code, and deliberately not even the free-text note: a queued
 * notification payload is a database row (D7), and ids cannot leak.
 *
 * Not queued by the package: the outbox already decouples delivery from
 * the mutation transaction and gives it retry semantics, so the send
 * happens at drain time.
 */
final class CredentialLifecycleNotification extends Notification
{
    public function __construct(
        public readonly string $event,
        public readonly ?string $credentialId,
        public readonly ?string $codeId,
        public readonly ?string $actorType,
        public readonly ?string $actorRef,
        public readonly ?string $reasonCode,
        public readonly ?string $supersededByCredentialId,
        public readonly string $occurredAt,
    ) {}

    public static function about(CredentialAuditEvent $event): self
    {
        return new self(
            event: $event->event->value,
            credentialId: $event->credential_id,
            codeId: $event->code_id,
            actorType: $event->actor_type?->value,
            actorRef: $event->actor_ref,
            reasonCode: $event->reason_code?->value,
            supersededByCredentialId: $event->superseded_by_credential_id,
            occurredAt: $event->occurred_at->toIso8601String(),
        );
    }

    /**
     * @return list<string>
     */
    public function via(object $notifiable): array
    {
        return ['mail'];
    }

    public function toMail(object $notifiable): MailMessage
    {
        $message = (new MailMessage)
            ->subject('Credential lifecycle notice: '.$this->event)
            ->line('A credential lifecycle event occurred: '.$this->event.' at '.$this->occurredAt.'.');

        if ($this->credentialId !== null) {
            $message->line('Credential id: '.$this->credentialId);
        }

        if ($this->codeId !== null) {
            $message->line('Claim code id: '.$this->codeId);
        }

        if ($this->actorType !== null) {
            $message->line('Acting party: '.$this->actorType.($this->actorRef !== null ? ' ('.$this->actorRef.')' : ''));
        }

        if ($this->reasonCode !== null) {
            $message->line('Reason: '.$this->reasonCode);
        }

        if ($this->supersededByCredentialId !== null) {
            $message->line('Superseded by credential id: '.$this->supersededByCredentialId);
        }

        return $message->line('If this activity is unexpected, revoke the credential and issue a new one.');
    }
}
