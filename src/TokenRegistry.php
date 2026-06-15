<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use Carbon\CarbonInterface;
use InvalidArgumentException;

final class TokenRegistry
{
    public const FALLBACK = 'fallback';

    public function resolve(string $bearer): ?string
    {
        if ($bearer === '') {
            return null;
        }

        $fallback = config('built-for-cloud.fallback_token');

        if ($fallback !== null && $fallback !== '' && hash_equals(hash('sha256', (string) $fallback), hash('sha256', $bearer))) {
            return self::FALLBACK;
        }

        /** @var ApiToken|null $row */
        $row = ApiToken::query()
            ->where('token_hash', hash('sha256', $bearer))
            ->resolvable()
            ->first();

        if ($row === null) {
            return null;
        }

        $row->forceFill([
            'request_count' => $row->request_count + 1,
            'last_used_at' => now(),
        ])->save();

        return $row->name;
    }

    public function store(string $name, string $hash, ?CarbonInterface $expiresAt = null): ApiToken
    {
        if ($name === self::FALLBACK) {
            throw new InvalidArgumentException('The fallback token name is reserved.');
        }

        return ApiToken::query()->create([
            'name' => $name,
            'token_hash' => $hash,
            'expires_at' => $expiresAt,
            'revoked_at' => null,
        ]);
    }

    public function rotate(string $name, string $newHash, bool $emergency = false): ApiToken
    {
        $newToken = $this->store($name, $newHash);
        $expiresAt = $emergency ? now() : now()->addHour();

        ApiToken::query()
            ->where('name', $name)
            ->whereKeyNot($newToken->getKey())
            ->resolvable()
            ->update(['expires_at' => $expiresAt]);

        return $newToken;
    }

    public function revoke(string $name): int
    {
        $now = now();

        return ApiToken::query()
            ->where('name', $name)
            ->resolvable()
            ->update([
                'expires_at' => $now,
                'revoked_at' => $now,
            ]);
    }
}
