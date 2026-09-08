<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\IssueHumanInvitation;
use ArtisanBuild\BuiltForCloud\Actions\RequestStandalonePasswordReset;
use ArtisanBuild\BuiltForCloud\Notifications\HumanInvitationNotification;
use ArtisanBuild\BuiltForCloud\Notifications\StandalonePasswordResetNotification;
use ArtisanBuild\BuiltForCloud\StandaloneAccess;
use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Mail\Transport\ArrayTransport;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Notifications\Events\NotificationFailed;
use Illuminate\Notifications\Events\NotificationSent;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;

require __DIR__.'/../../vendor/autoload.php';

$app = require __DIR__.'/../../vendor/orchestra/testbench-core/laravel/bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();

$kind = $argv[1] ?? '';
$email = $argv[2] ?? '';
$captured = null;
$failure = null;

Event::listen(NotificationSent::class, static function (NotificationSent $event) use (&$captured): void {
    if ($event->notification instanceof HumanInvitationNotification
        || $event->notification instanceof StandalonePasswordResetNotification) {
        $captured = $event->notification->toMail(new AnonymousNotifiable)->actionUrl;
    }
});
Event::listen(NotificationFailed::class, static function (NotificationFailed $event) use (&$failure): void {
    $exception = $event->data['exception'] ?? null;
    $failure = is_object($exception) ? $exception::class : 'unknown';
});

if ($kind === 'invitation') {
    $owner = User::query()->where('email', 'owner@example.test')->sole();
    app(IssueHumanInvitation::class)($owner, $email, UserRole::Admin);
} elseif ($kind === 'reset') {
    $resetUser = User::query()->where('email', $email)->first();

    if (! $resetUser instanceof User) {
        throw new RuntimeException('The reset fixture user does not exist; user count: '.User::query()->count());
    }

    if (! StandaloneAccess::userCanReceiveRecovery($resetUser)) {
        throw new RuntimeException('The reset fixture user is not eligible for recovery.');
    }

    app(RequestStandalonePasswordReset::class)($email);
} else {
    throw new RuntimeException('Unknown mail-link kind.');
}

$transport = app('mailer')->getSymfonyTransport();

if (! $transport instanceof ArrayTransport) {
    throw new RuntimeException('The live harness requires the non-delivering array mailer.');
}

if (! is_string($captured) || ! str_contains($captured, '/bfc/')) {
    throw new RuntimeException('No '.$kind.' link was captured from the array mailer; message count: '.$transport->messages()->count().'; transaction level: '.DB::transactionLevel().'; failure: '.($failure ?? 'none'));
}

fwrite(STDOUT, $captured);
