<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Support;

use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\Notifications\HumanInvitationNotification;
use ArtisanBuild\BuiltForCloud\Notifications\StandalonePasswordResetNotification;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\SelfServicePolicyDeclaration;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Notifications\Events\NotificationSent;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;

final class StandaloneHarnessServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app['config']->set('auth.defaults.guard', 'web');
        $this->app['config']->set('auth.guards', []);
        $this->app['config']->set('auth.providers', []);
        $this->app['config']->set('cache.default', 'array');
        $this->app['config']->set('built-for-cloud.surfaces.data_migrations', false);

        if (filter_var(env('BFC_HARNESS_PERSONAL_HMAC', false), FILTER_VALIDATE_BOOL)) {
            SelfServicePolicyDeclaration::$kinds = [CredentialKind::Bearer, CredentialKind::Hmac];
            $this->app['config']->set('built-for-cloud.credentials.declaration', SelfServicePolicyDeclaration::class);
        }
    }

    public function boot(): void
    {
        Event::listen(NotificationSent::class, function (NotificationSent $event): void {
            if (! $event->notification instanceof HumanInvitationNotification
                && ! $event->notification instanceof StandalonePasswordResetNotification) {
                return;
            }

            $url = $event->notification->toMail(new AnonymousNotifiable)->actionUrl;

            if (is_string($url) && ! headers_sent()) {
                header('X-Bfc-Harness-Mail: '.$url);
            }
        });
    }
}
