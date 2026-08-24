<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use Carbon\CarbonInterface;
use Illuminate\Support\Facades\DB;
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

        ApiToken::query()->whereKey($row->getKey())->update([
            'request_count' => DB::raw('request_count + 1'),
            'last_used_at' => now(),
        ]);

        return $row->name;
    }

    public function resolveModel(string $bearer): ?ApiToken
    {
        if ($bearer === '') {
            return null;
        }

        $fallback = config('built-for-cloud.fallback_token');

        if ($fallback !== null && $fallback !== '' && hash_equals(hash('sha256', (string) $fallback), hash('sha256', $bearer))) {
            return null;
        }

        /** @var ApiToken|null $row */
        $row = ApiToken::query()
            ->where('token_hash', hash('sha256', $bearer))
            ->resolvable()
            ->first();

        if ($row === null) {
            return null;
        }

        ApiToken::query()->whereKey($row->getKey())->update([
            'request_count' => DB::raw('request_count + 1'),
            'last_used_at' => now(),
        ]);

        return $row->refresh();
    }

    /**
     * Record the opaque client identity that presented this token.
     *
     * The value is stored verbatim; `client_identity_last_seen_at` is bumped on every valid
     * presentation, not only when the identity changes. Last writer wins.
     */
    public function recordClientIdentity(ApiToken $token, string $identity): bool
    {
        if (! ClientIdentity::isValid($identity)) {
            return false;
        }

        ApiToken::query()->whereKey($token->getKey())->update([
            'client_identity' => $identity,
            'client_identity_last_seen_at' => now(),
        ]);

        $token->refresh();

        return true;
    }

    /**
     * @param  list<string>  $abilities
     */
    public function store(string $name, string $hash, ?CarbonInterface $expiresAt = null, array $abilities = []): ApiToken
    {
        if ($name === self::FALLBACK) {
            throw new InvalidArgumentException('The fallback token name is reserved.');
        }

        if (! preg_match('/^[0-9a-f]{64}$/', $hash)) {
            throw new InvalidArgumentException('A token hash must be a sha256 hex digest.');
        }

        return ApiToken::query()->create([
            'name' => $name,
            'token_hash' => $hash,
            'expires_at' => $expiresAt,
            'revoked_at' => null,
            'abilities' => $abilities === [] ? null : $abilities,
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
