<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Throwable;

/** Keeps reveal-once browser ceremony material sealed under the package encrypter. */
final readonly class BrowserCredentialAuthorizationStore
{
    public const int MAX_LIVE_BINDINGS = 8;

    private const string SESSION_KEY = 'bfc_credential_authorizations';

    private const string SELECTED_LOOPBACK_KEY = 'bfc_selected_loopback_authorization';

    public function __construct(private Encrypter $encrypter) {}

    public function hasCapacity(Request $request): bool
    {
        return count($this->live($request)) < self::MAX_LIVE_BINDINGS;
    }

    public function putDevice(
        Request $request,
        string $authorizationId,
        string $browserNonce,
        string $userCode,
    ): void {
        $this->put($request, [
            'flow' => CredentialAuthorizationFlow::Device->value,
            'authorization_id' => $authorizationId,
            'browser_nonce' => $browserNonce,
            'user_code' => $userCode,
        ]);
    }

    public function putLoopback(
        Request $request,
        string $authorizationId,
        string $browserNonce,
        string $state,
    ): void {
        $ciphertext = $this->put($request, [
            'flow' => CredentialAuthorizationFlow::Loopback->value,
            'authorization_id' => $authorizationId,
            'browser_nonce' => $browserNonce,
            'state' => $state,
        ]);
        $request->session()->put(self::SELECTED_LOOPBACK_KEY, $ciphertext);
    }

    /** @return list<array{payload: array<string, mixed>, authorization: object}> */
    public function deviceBindings(Request $request): array
    {
        return array_values(array_filter(
            $this->live($request),
            static fn (array $entry): bool => $entry['payload']['flow'] === CredentialAuthorizationFlow::Device->value,
        ));
    }

    /** @return array{payload: array<string, mixed>, authorization: object}|null */
    public function deviceBinding(Request $request, string $canonicalUserCode): ?array
    {
        foreach ($this->deviceBindings($request) as $entry) {
            $stored = $entry['payload']['user_code'] ?? null;

            if (is_string($stored) && hash_equals($stored, $canonicalUserCode)) {
                return $entry;
            }
        }

        return null;
    }

    /**
     * @param  array{app_purpose: string, redirect_uri: string, pkce_challenge: string, state: string, label: ?string}  $tuple
     * @return array{payload: array<string, mixed>, authorization: object}|null
     */
    public function loopbackBinding(Request $request, array $tuple): ?array
    {
        foreach ($this->live($request) as $entry) {
            $payload = $entry['payload'];

            if (($payload['flow'] ?? null) !== CredentialAuthorizationFlow::Loopback->value) {
                continue;
            }

            $matches = true;

            foreach ($tuple as $key => $value) {
                $stored = $key === 'state' ? ($payload[$key] ?? null) : ($entry['authorization']->{$key} ?? null);
                $matches = $value === null ? $stored === null : is_string($stored) && hash_equals($stored, $value);

                if (! $matches) {
                    break;
                }
            }

            if ($matches) {
                $request->session()->put(self::SELECTED_LOOPBACK_KEY, $entry['ciphertext']);

                return ['payload' => $payload, 'authorization' => $entry['authorization']];
            }
        }

        return null;
    }

    /** @return array{payload: array<string, mixed>, authorization: object}|null */
    public function selectedLoopbackBinding(Request $request): ?array
    {
        $selected = $request->session()->get(self::SELECTED_LOOPBACK_KEY);

        if (! is_string($selected)) {
            return null;
        }

        foreach ($this->live($request) as $entry) {
            if (hash_equals($entry['ciphertext'], $selected)
                && ($entry['payload']['flow'] ?? null) === CredentialAuthorizationFlow::Loopback->value) {
                return ['payload' => $entry['payload'], 'authorization' => $entry['authorization']];
            }
        }

        $request->session()->forget(self::SELECTED_LOOPBACK_KEY);

        return null;
    }

    public function forget(Request $request, string $authorizationId): void
    {
        $kept = [];
        $selected = $request->session()->get(self::SELECTED_LOOPBACK_KEY);

        foreach ($this->ciphertexts($request) as $ciphertext) {
            $payload = $this->decrypt($ciphertext);

            if (($payload['authorization_id'] ?? null) === $authorizationId) {
                if (is_string($selected) && hash_equals($selected, $ciphertext)) {
                    $request->session()->forget(self::SELECTED_LOOPBACK_KEY);
                }

                continue;
            }

            $kept[] = $ciphertext;
        }

        $this->replace($request, $kept);
    }

    public function clear(Request $request): void
    {
        $request->session()->forget([self::SESSION_KEY, self::SELECTED_LOOPBACK_KEY]);
    }

    /** Explicitly carries only still-live ciphertext across authentication session regeneration. */
    public function regenerate(Request $request): bool
    {
        $live = $this->live($request);
        $ciphertexts = array_column($live, 'ciphertext');
        $selected = $request->session()->get(self::SELECTED_LOOPBACK_KEY);
        $selected = is_string($selected) && in_array($selected, $ciphertexts, true) ? $selected : null;

        $this->clear($request);
        $regenerated = $request->session()->regenerate();
        $this->replace($request, $ciphertexts);

        if ($selected !== null) {
            $request->session()->put(self::SELECTED_LOOPBACK_KEY, $selected);
        }

        return $regenerated;
    }

    /** @return list<string> */
    public function serializedCiphertexts(Request $request): array
    {
        $this->live($request);

        return $this->ciphertexts($request);
    }

    /** @param array<string, mixed> $payload */
    private function put(Request $request, array $payload): string
    {
        $ciphertexts = array_column($this->live($request), 'ciphertext');

        if (count($ciphertexts) >= self::MAX_LIVE_BINDINGS) {
            throw new \OverflowException('The browser authorization map is full.');
        }

        $ciphertext = $this->encrypter->encrypt(json_encode($payload, JSON_THROW_ON_ERROR), false);
        $ciphertexts[] = $ciphertext;
        $this->replace($request, $ciphertexts);

        return $ciphertext;
    }

    /**
     * @return list<array{ciphertext: string, payload: array<string, mixed>, authorization: object}>
     */
    private function live(Request $request): array
    {
        $userId = $this->userId($request);
        $live = [];

        if ($userId === null) {
            $this->clear($request);

            return [];
        }

        foreach ($this->ciphertexts($request) as $ciphertext) {
            $payload = $this->decrypt($ciphertext);
            $authorizationId = $payload['authorization_id'] ?? null;
            $browserNonce = $payload['browser_nonce'] ?? null;
            $flow = $payload['flow'] ?? null;

            if (! is_string($authorizationId) || ! is_string($browserNonce) || ! is_string($flow)) {
                continue;
            }

            $authorization = DB::table('credential_authorizations')->where('id', $authorizationId)->first();

            if (! is_object($authorization)
                || $authorization->status !== CredentialAuthorizationStatus::Pending->value
                || $authorization->flow !== $flow
                || ! hash_equals((string) $authorization->initiating_user_id, $userId)
                || ! hash_equals((string) $authorization->browser_session_nonce_hash, hash('sha256', $browserNonce))
                || now()->greaterThanOrEqualTo($authorization->expires_at)) {
                continue;
            }

            $live[] = compact('ciphertext', 'payload', 'authorization');
        }

        $liveCiphertexts = array_column($live, 'ciphertext');
        $this->replace($request, $liveCiphertexts);

        $selected = $request->session()->get(self::SELECTED_LOOPBACK_KEY);

        if ($selected !== null
            && (! is_string($selected) || ! in_array($selected, $liveCiphertexts, true))) {
            $request->session()->forget(self::SELECTED_LOOPBACK_KEY);
        }

        return $live;
    }

    /** @return array<string, mixed> */
    private function decrypt(string $ciphertext): array
    {
        try {
            $json = $this->encrypter->decrypt($ciphertext, false);
            $payload = is_string($json) ? json_decode($json, true, flags: JSON_THROW_ON_ERROR) : null;

            return is_array($payload) ? $payload : [];
        } catch (Throwable) {
            return [];
        }
    }

    /** @return list<string> */
    private function ciphertexts(Request $request): array
    {
        $stored = $request->session()->get(self::SESSION_KEY, []);

        if (! is_array($stored)) {
            return [];
        }

        return array_values(array_filter($stored, 'is_string'));
    }

    /** @param list<string> $ciphertexts */
    private function replace(Request $request, array $ciphertexts): void
    {
        if ($ciphertexts === []) {
            $request->session()->forget(self::SESSION_KEY);

            return;
        }

        $request->session()->put(self::SESSION_KEY, $ciphertexts);
    }

    private function userId(Request $request): ?string
    {
        $user = $request->user();

        if (! $user instanceof Authenticatable) {
            return null;
        }

        $id = $user->getAuthIdentifier();

        return is_scalar($id) && (string) $id !== '' ? (string) $id : null;
    }
}
