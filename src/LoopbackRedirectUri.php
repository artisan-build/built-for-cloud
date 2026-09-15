<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Exceptions\CredentialAuthorizationRefused;

final readonly class LoopbackRedirectUri
{
    public function __construct(public string $value)
    {
        if (strlen($value) > 2048
            || preg_match('/[\x00-\x20\x7f\\\\]/', $value) === 1
            || preg_match('/\Ahttp:\/\/(localhost|127\.0\.0\.1|\[::1\]):([0-9]{1,5})(?:[\/?][^#]*)?\z/D', $value, $matches) !== 1) {
            throw CredentialAuthorizationRefused::invalidRequest();
        }

        $port = (int) $matches[2];

        if ($port < 1024 || $port > 65535 || parse_url($value) === false) {
            throw CredentialAuthorizationRefused::invalidRequest();
        }

        $query = parse_url($value, PHP_URL_QUERY);

        if (! is_string($query) || $query === '') {
            return;
        }

        foreach (explode('&', $query) as $member) {
            $key = rawurldecode(explode('=', $member, 2)[0]);

            if (in_array($key, ['code', 'error', 'state'], true)) {
                throw CredentialAuthorizationRefused::invalidRequest();
            }
        }
    }

    /** @param array<string, string> $parameters */
    public function append(array $parameters): string
    {
        $separator = str_contains($this->value, '?') ? '&' : '?';

        return $this->value.$separator.http_build_query($parameters, '', '&', PHP_QUERY_RFC3986);
    }
}
