<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Console\DelegatedActorProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use SensitiveParameter;

/**
 * The real {@see DelegatedActorProvider}, wrapped so a test can observe
 * WHICH of its methods the framework actually called.
 *
 * It wraps rather than extends because the real provider is `final`, and
 * it delegates every method rather than reimplementing any, so what a
 * test observes is the real provider's answer and not a stand-in's. The
 * recording exists for one claim in particular: that Laravel's
 * remember-me branch IS entered on this guard and is fail-closed at the
 * provider, rather than being unreachable — a distinction an earlier
 * revision of the docblock got wrong.
 */
final class RecordingDelegatedActorProvider implements UserProvider
{
    /**
     * Every `retrieveByToken` call, as `[identifier, token]` pairs.
     *
     * @var list<array{mixed, mixed}>
     */
    public static array $tokenLookups = [];

    /** Every `retrieveById` call's identifier. */
    public static array $idLookups = [];

    private DelegatedActorProvider $inner;

    public function __construct()
    {
        $this->inner = new DelegatedActorProvider;
    }

    public static function reset(): void
    {
        self::$tokenLookups = [];
        self::$idLookups = [];
    }

    /**
     * @param  mixed  $identifier
     */
    public function retrieveById($identifier): ?Authenticatable
    {
        self::$idLookups[] = $identifier;

        return $this->inner->retrieveById($identifier);
    }

    /**
     * @param  mixed  $identifier
     */
    public function retrieveByToken($identifier, #[SensitiveParameter] $token): ?Authenticatable
    {
        self::$tokenLookups[] = [$identifier, $token];

        return $this->inner->retrieveByToken($identifier, $token);
    }

    public function updateRememberToken(Authenticatable $user, #[SensitiveParameter] $token): void
    {
        $this->inner->updateRememberToken($user, $token);
    }

    /**
     * @param  array<string, mixed>  $credentials
     */
    public function retrieveByCredentials(#[SensitiveParameter] array $credentials): ?Authenticatable
    {
        return $this->inner->retrieveByCredentials($credentials);
    }

    /**
     * @param  array<string, mixed>  $credentials
     */
    public function validateCredentials(Authenticatable $user, #[SensitiveParameter] array $credentials): bool
    {
        return $this->inner->validateCredentials($user, $credentials);
    }

    /**
     * @param  array<string, mixed>  $credentials
     */
    public function rehashPasswordIfRequired(Authenticatable $user, #[SensitiveParameter] array $credentials, bool $force = false): void
    {
        $this->inner->rehashPasswordIfRequired($user, $credentials, $force);
    }
}
