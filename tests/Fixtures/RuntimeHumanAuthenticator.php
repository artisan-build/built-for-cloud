<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Support\Facades\Auth;
use InvalidArgumentException;

final readonly class RuntimeHumanAuthenticator
{
    public function __construct(private RuntimeIndirectAuthenticator $indirect) {}

    public function run(string $shape, string $userId, AuthFactory $auth): void
    {
        $user = User::query()->findOrFail($userId);

        switch ($shape) {
            case 'facade-login':
                Auth::login($user);

                return;
            case 'helper-login':
                auth()->login($user);

                return;
            case 'facade-guard-login':
                Auth::guard('web')->login($user);

                return;
            case 'injected-factory-login':
                $auth->guard('web')->login($user);

                return;
            case 'container-manager-login':
                $manager = app('auth');
                $manager->guard('web')->login($user);

                return;
            case 'container-make-login':
                app()->make('auth')->guard('web')->login($user);

                return;
            case 'nullsafe-guard-login':
                Auth::guard('web')?->login($user);

                return;
            case 'attempt-when':
                Auth::attemptWhen([
                    'email' => $user->email,
                    'password' => 'runtime-authority-password',
                ], static fn (): bool => true);

                return;
            case 'facade-root-login':
                Auth::getFacadeRoot()->guard('web')->login($user);

                return;
            case 'dynamic-login':
                $method = 'login';
                Auth::guard('web')->{$method}($user);

                return;
            case 'helper-indirection':
                $this->indirect->login($user);

                return;
            case 'bound-user-actor':
                AuditActor::boundUser($userId);

                return;
        }

        throw new InvalidArgumentException('Unknown runtime authority control shape.');
    }
}
