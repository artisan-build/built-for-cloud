<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Notifications;

use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;
use SensitiveParameter;

final class StandalonePasswordResetNotification extends Notification
{
    public function __construct(
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
            ->subject('Reset your password')
            ->action('Reset password', route('bfc.password.reset', [
                'token' => $this->token,
                'email' => $this->email,
            ]));
    }
}
