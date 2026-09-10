<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use Illuminate\Contracts\Cookie\QueueingFactory;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Http\Request;
use JsonException;
use SensitiveParameter;

final readonly class StandaloneHandoff
{
    public const string COOKIE = 'bfc_standalone_handoff';

    public const string INVITATION = 'invitation';

    public const string PASSWORD_RESET = 'password-reset';

    public function __construct(
        private Encrypter $encrypter,
        private QueueingFactory $cookies,
    ) {}

    public function issue(
        string $purpose,
        #[SensitiveParameter] string $token,
        ?string $intended = null,
    ): void {
        $this->cookies->unqueue(self::COOKIE);
        $minutes = $this->lifetimeMinutes();
        $payload = json_encode([
            'version' => 1,
            'purpose' => $purpose,
            'token' => $token,
            'intended' => $intended,
            'expires_at' => now()->addMinutes($minutes)->timestamp,
        ], JSON_THROW_ON_ERROR);

        $this->cookies->queue($this->cookies->make(
            self::COOKIE,
            $this->encrypter->encrypt($payload, false),
            $minutes,
            $this->path($purpose),
            httpOnly: true,
            sameSite: 'lax',
        ));
    }

    /** @return array{token: string, intended: string|null}|null */
    public function read(Request $request, string $purpose): ?array
    {
        $cookie = $request->cookie(self::COOKIE);

        if (! is_string($cookie) || $cookie === '') {
            return null;
        }

        try {
            $payload = json_decode($this->encrypter->decrypt($cookie, false), true, flags: JSON_THROW_ON_ERROR);
        } catch (DecryptException|JsonException) {
            return null;
        }

        if (! is_array($payload)
            || ($payload['version'] ?? null) !== 1
            || ($payload['purpose'] ?? null) !== $purpose
            || ! is_string($payload['token'] ?? null)
            || $payload['token'] === ''
            || mb_strlen($payload['token']) > 255
            || ! is_int($payload['expires_at'] ?? null)
            || $payload['expires_at'] <= now()->timestamp
            || (! is_null($payload['intended'] ?? null) && ! is_string($payload['intended']))) {
            return null;
        }

        return [
            'token' => $payload['token'],
            'intended' => $payload['intended'] ?? null,
        ];
    }

    public function expire(string $purpose): void
    {
        $this->cookies->unqueue(self::COOKIE);
        $this->cookies->queue($this->cookies->make(
            self::COOKIE,
            '',
            -2628000,
            $this->path($purpose),
            httpOnly: true,
            sameSite: 'lax',
        ));
    }

    public function beginRequest(): void
    {
        $this->cookies->unqueue(self::COOKIE);
    }

    public function purposeForRoute(?string $routeName): ?string
    {
        return match ($routeName) {
            'bfc.password.reset', 'bfc.password.reset.form', 'bfc.password.update' => self::PASSWORD_RESET,
            'bfc.invitations.accept', 'bfc.invitations.accept.form', 'bfc.invitations.accept.store' => self::INVITATION,
            default => null,
        };
    }

    public function path(string $purpose): string
    {
        return match ($purpose) {
            self::PASSWORD_RESET => '/bfc/reset-password',
            self::INVITATION => '/bfc/invitations/accept',
            default => throw new \InvalidArgumentException('Unknown standalone handoff purpose.'),
        };
    }

    private function lifetimeMinutes(): int
    {
        return max(2, min(15, (int) config('built-for-cloud.standalone.handoff_minutes', 10)));
    }
}
