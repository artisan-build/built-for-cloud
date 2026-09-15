<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Exceptions;

use RuntimeException;

final class CredentialAuthorizationRefused extends RuntimeException
{
    private function __construct(
        public readonly string $error,
        public readonly ?int $retryAfter = null,
        public readonly ?int $interval = null,
    ) {
        parent::__construct($error);
    }

    public static function invalidRequest(): self
    {
        return new self('invalid_request');
    }

    public static function invalidGrant(): self
    {
        return new self('invalid_grant');
    }

    public static function expired(): self
    {
        return new self('expired_token');
    }

    public static function denied(): self
    {
        return new self('access_denied');
    }

    public static function pending(): self
    {
        return new self('authorization_pending');
    }

    public static function slowDown(int $interval): self
    {
        return new self('slow_down', interval: $interval);
    }

    public static function temporarilyUnavailable(): self
    {
        return new self('temporarily_unavailable', retryAfter: 5);
    }

    public static function unavailable(): self
    {
        return new self('authorization_unavailable');
    }
}
