<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http;

use ArtisanBuild\BuiltForCloud\Exceptions\CredentialAuthorizationRefused;
use Illuminate\Http\Request;
use JsonException;
use stdClass;

final class ClosedRequestInput
{
    /**
     * @param  list<string>  $required
     * @param  list<string>  $optional
     * @return array<string, mixed>
     */
    public static function json(Request $request, array $required, array $optional = []): array
    {
        $mediaType = strtolower(trim(explode(';', (string) $request->header('Content-Type'), 2)[0]));

        if ($mediaType !== 'application/json') {
            throw CredentialAuthorizationRefused::invalidRequest();
        }

        $raw = $request->getContent();

        try {
            $decoded = json_decode($raw, false, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw CredentialAuthorizationRefused::invalidRequest();
        }

        if (! $decoded instanceof stdClass) {
            throw CredentialAuthorizationRefused::invalidRequest();
        }

        $values = get_object_vars($decoded);
        preg_match_all('/(?<!\\\\)"(?:\\\\.|[^"\\\\])*"\s*:/', $raw, $keys);

        if (count($keys[0]) !== count($values)) {
            throw CredentialAuthorizationRefused::invalidRequest();
        }

        self::assertKeys($values, $required, $optional);

        return $values;
    }

    /**
     * @param  list<string>  $required
     * @param  list<string>  $optional
     * @return array<string, string|null>
     */
    public static function query(Request $request, array $required, array $optional = []): array
    {
        return self::urlEncoded((string) $request->server->get('QUERY_STRING', ''), $required, $optional, false);
    }

    /**
     * @param  list<string>  $required
     * @param  list<string>  $optional
     * @return array<string, string|null>
     */
    public static function form(Request $request, array $required, array $optional = []): array
    {
        $mediaType = strtolower(trim(explode(';', (string) $request->header('Content-Type'), 2)[0]));

        if ($mediaType !== 'application/x-www-form-urlencoded'
            && ! ($mediaType === '' && $request->request->count() > 0)) {
            throw CredentialAuthorizationRefused::unavailable();
        }

        $raw = $request->getContent();

        if ($raw !== '') {
            return self::urlEncoded($raw, $required, [...$optional, '_token'], true);
        }

        $values = $request->request->all();

        foreach ($values as $value) {
            if (! is_string($value)) {
                throw CredentialAuthorizationRefused::unavailable();
            }
        }

        try {
            self::assertKeys($values, $required, [...$optional, '_token']);
        } catch (CredentialAuthorizationRefused) {
            throw CredentialAuthorizationRefused::unavailable();
        }

        return $values;
    }

    /**
     * @param  array<string, mixed>  $values
     * @param  list<string>  $required
     * @param  list<string>  $optional
     */
    private static function assertKeys(array $values, array $required, array $optional): void
    {
        $keys = array_keys($values);
        $allowed = [...$required, ...$optional];

        if (array_diff($required, $keys) !== [] || array_diff($keys, $allowed) !== []) {
            throw CredentialAuthorizationRefused::invalidRequest();
        }
    }

    /**
     * @param  list<string>  $required
     * @param  list<string>  $optional
     * @return array<string, string|null>
     */
    private static function urlEncoded(string $raw, array $required, array $optional, bool $form): array
    {
        $values = [];

        if ($raw !== '') {
            foreach (explode('&', $raw) as $member) {
                [$encodedKey, $encodedValue] = array_pad(explode('=', $member, 2), 2, '');
                $key = urldecode($encodedKey);

                if ($key === '' || isset($values[$key]) || str_contains($key, '[') || str_contains($key, ']')) {
                    throw $form ? CredentialAuthorizationRefused::unavailable() : CredentialAuthorizationRefused::invalidRequest();
                }

                $values[$key] = urldecode($encodedValue);
            }
        }

        try {
            self::assertKeys($values, $required, $optional);
        } catch (CredentialAuthorizationRefused) {
            throw $form ? CredentialAuthorizationRefused::unavailable() : CredentialAuthorizationRefused::invalidRequest();
        }

        return $values;
    }
}
