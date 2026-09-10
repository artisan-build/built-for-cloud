<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Exceptions\ManagedAuthRefused;
use Illuminate\Support\Facades\DB;

final readonly class ManagedAuthConnection
{
    public function __construct(
        public string $issuer,
        public string $connectionId,
        public string $organizationId,
        public string $installationId,
        public int $authorityGeneration,
        public string $baseUrl,
        public string $clientSecret,
        public ?string $caBundle,
    ) {}

    public static function current(): self
    {
        $row = DB::table('bfc_authority')
            ->where('key', InstallationAuthority::KEY)
            ->first([
                'mode',
                'generation',
                'issuer',
                'connection_id',
                'organization_id',
                'installation_id',
                'authority_base_url',
            ]);

        $clientSecret = config('built-for-cloud.managed.client_secret');
        $caBundle = config('built-for-cloud.managed.ca_bundle');

        if (! is_object($row)
            || $row->mode !== AuthorityMode::Managed->value
            || ! is_int($row->generation)
            || $row->generation < 1
            || ! self::nonEmpty($row->issuer)
            || ! self::nonEmpty($row->connection_id)
            || ! self::nonEmpty($row->organization_id)
            || ! self::nonEmpty($row->installation_id)
            || ! self::validBaseUrl($row->authority_base_url)
            || ! self::nonEmpty($clientSecret)
            || ($caBundle !== null && ! self::nonEmpty($caBundle))) {
            throw new ManagedAuthRefused;
        }

        return new self(
            $row->issuer,
            $row->connection_id,
            $row->organization_id,
            $row->installation_id,
            $row->generation,
            rtrim($row->authority_base_url, '/'),
            $clientSecret,
            $caBundle,
        );
    }

    public function acceptsAuthorizationUrl(string $url): bool
    {
        $expected = parse_url($this->baseUrl);
        $candidate = parse_url($url);

        if (! is_array($expected)
            || ! is_array($candidate)
            || ($candidate['scheme'] ?? null) !== 'https'
            || ($candidate['path'] ?? null) !== ManagedAuthClient::AUTHORIZE_PATH
            || array_key_exists('query', $candidate)
            || array_key_exists('fragment', $candidate)
            || array_key_exists('user', $candidate)
            || array_key_exists('pass', $candidate)) {
            return false;
        }

        return strtolower((string) ($candidate['scheme'] ?? '')) === strtolower((string) ($expected['scheme'] ?? ''))
            && strtolower((string) ($candidate['host'] ?? '')) === strtolower((string) ($expected['host'] ?? ''))
            && self::port($candidate) === self::port($expected);
    }

    private static function nonEmpty(mixed $value): bool
    {
        return is_string($value) && $value !== '';
    }

    private static function validBaseUrl(mixed $url): bool
    {
        if (! self::nonEmpty($url)) {
            return false;
        }

        $parts = parse_url($url);

        return is_array($parts)
            && ($parts['scheme'] ?? null) === 'https'
            && self::nonEmpty($parts['host'] ?? null)
            && ! array_key_exists('query', $parts)
            && ! array_key_exists('fragment', $parts)
            && ! array_key_exists('user', $parts)
            && ! array_key_exists('pass', $parts)
            && in_array($parts['path'] ?? '', ['', '/'], true);
    }

    /** @param array<string, int|string> $parts */
    private static function port(array $parts): int
    {
        return isset($parts['port']) ? (int) $parts['port'] : 443;
    }
}
