<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Support;

use ArtisanBuild\BuiltForCloud\BoundCredentialScope;
use ArtisanBuild\BuiltForCloud\Contracts\ResolvesAsymmetricEnrollmentScope;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\Notifications\HumanInvitationNotification;
use ArtisanBuild\BuiltForCloud\Notifications\StandalonePasswordResetNotification;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\SelfServicePolicyDeclaration;
use Illuminate\Http\Request;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Notifications\Events\NotificationSent;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;

final class StandaloneHarnessServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app['config']->set('auth.defaults.guard', 'web');
        $this->app['config']->set('auth.guards', [
            'bfc' => ['driver' => 'bfc', 'provider' => 'users'],
        ]);
        $this->app['config']->set('auth.providers', []);
        $this->app['config']->set('cache.default', 'array');
        $this->app['config']->set('built-for-cloud.surfaces.data_migrations', false);

        if (filter_var(env('BFC_HARNESS_PERSONAL_HMAC', false), FILTER_VALIDATE_BOOL)) {
            SelfServicePolicyDeclaration::$kinds = [CredentialKind::Bearer, CredentialKind::Hmac];
            $this->app['config']->set('built-for-cloud.credentials.declaration', SelfServicePolicyDeclaration::class);
        }

        if (getenv('BFC_HARNESS_ASYMMETRIC') !== false) {
            $this->app['config']->set('built-for-cloud.credentials.app_purposes', [
                'reel.application.signing' => CredentialPurpose::Signing->value,
            ]);
        }
    }

    public function boot(): void
    {
        if (getenv('BFC_HARNESS_ASYMMETRIC') === 'bound') {
            $scope = new BoundCredentialScope(
                'reel.application.signing',
                new Subject(SubjectType::Installation, 'reel-live-installation'),
                'install_live_1',
                'app_live_1',
                'https://reel-live.example',
            );
            $this->app->instance(ResolvesAsymmetricEnrollmentScope::class, new class($scope) implements ResolvesAsymmetricEnrollmentScope
            {
                public function __construct(private readonly BoundCredentialScope $scope) {}

                public function resolve(Request $request, string $application): ?BoundCredentialScope
                {
                    return $application === $this->scope->application ? $this->scope : null;
                }
            });
        }

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
