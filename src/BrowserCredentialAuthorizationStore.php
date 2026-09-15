<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Exceptions\CredentialAuthorizationRefused;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Crypt;
use Throwable;

final class BrowserCredentialAuthorizationStore
{
    private const string SESSION_KEY = 'bfc.credential_authorizations';

    private const int MAX_INTENTS = 10;

    /** @param array<string, string> $payload */
    public function put(Request $request, string $authorizationId, array $payload): void
    {
        $intents = $this->intents($request);

        if (! array_key_exists($authorizationId, $intents) && count($intents) >= self::MAX_INTENTS) {
            throw CredentialAuthorizationRefused::unavailable();
        }

        $intents[$authorizationId] = Crypt::encryptString(json_encode($payload, JSON_THROW_ON_ERROR));
        $request->session()->put(self::SESSION_KEY, $intents);
    }

    /** @return array<string, string>|null */
    public function get(Request $request, string $authorizationId): ?array
    {
        $encrypted = $this->intents($request)[$authorizationId] ?? null;

        if (! is_string($encrypted)) {
            return null;
        }

        try {
            $payload = json_decode(Crypt::decryptString($encrypted), true, flags: JSON_THROW_ON_ERROR);
        } catch (Throwable) {
            return null;
        }

        if (! is_array($payload)) {
            return null;
        }

        foreach ($payload as $key => $value) {
            if (! is_string($key) || ! is_string($value)) {
                return null;
            }
        }

        /** @var array<string, string> $payload */
        return $payload;
    }

    /** @return array{string, array<string, string>}|null */
    public function findDevice(Request $request, string $userCode): ?array
    {
        foreach (array_keys($this->intents($request)) as $authorizationId) {
            $payload = $this->get($request, (string) $authorizationId);

            if (($payload['flow'] ?? null) === CredentialAuthorizationFlow::Device->value
                && isset($payload['user_code'])
                && hash_equals($payload['user_code'], $userCode)) {
                return [(string) $authorizationId, $payload];
            }
        }

        return null;
    }

    public function forget(Request $request, string $authorizationId): void
    {
        $intents = $this->intents($request);
        unset($intents[$authorizationId]);
        $request->session()->put(self::SESSION_KEY, $intents);
    }

    /** @return array<string, string> */
    private function intents(Request $request): array
    {
        $intents = $request->session()->get(self::SESSION_KEY, []);

        if (! is_array($intents)) {
            return [];
        }

        return array_filter($intents, 'is_string');
    }
}
