<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Notifications;

use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;
use SensitiveParameter;

final class HumanInvitationNotification extends Notification
{
    public function __construct(
        public readonly string $invitationId,
        #[SensitiveParameter] private readonly string $token,
        private readonly string $email,
    ) {}

    /** @return list<string> */
    public function via(object $notifiable): array
    {
        return ['mail'];
    }

    public function toMail(object $notifiable): MailMessage
    {
        return (new MailMessage)
            ->subject('You have been invited')
            ->action('Accept invitation', route('bfc.invitations.accept', [
                'token' => $this->token,
                'email' => $this->email,
            ]));
    }
}
