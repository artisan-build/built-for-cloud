<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Exceptions\ManagedAuthRefused;
use Carbon\CarbonImmutable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

final class ManagedHandoff
{
    public const string SESSION_NONCE_KEY = 'bfc.managed_session_nonce';

    public function __construct(
        private readonly ManagedAuthClient $client,
        private readonly ManagedHandoffClaim $claim,
    ) {}

    public function begin(Request $request): string
    {
        $connection = ManagedAuthConnection::current();
        $state = $this->randomSecret();
        $sessionNonce = $this->randomSecret();
        $authorization = $this->client->createHandoff($connection, $state);
        $now = CarbonImmutable::now();
        $authorityExpiry = CarbonImmutable::instance($authorization->expiresAt);
        $expiresAt = $authorityExpiry->lessThan($now->addSeconds(300))
            ? $authorityExpiry
            : $now->addSeconds(300);

        if ($expiresAt->lessThanOrEqualTo($now)) {
            throw new ManagedAuthRefused;
        }

        DB::table('bfc_managed_handoffs')->insert([
            'state_hash' => hash('sha256', $state),
            'session_nonce_hash' => hash('sha256', $sessionNonce),
            'issuer' => $connection->issuer,
            'connection_id' => $connection->connectionId,
            'organization_id' => $connection->organizationId,
            'installation_id' => $connection->installationId,
            'authority_generation' => $connection->authorityGeneration,
            'expires_at' => $expiresAt,
            'consumed_at' => null,
            'created_at' => $now,
            'updated_at' => $now,
        ]);
        $request->session()->put(self::SESSION_NONCE_KEY, $sessionNonce);

        return $authorization->url.'?state='.rawurlencode($state);
    }

    public function exchange(Request $request): ManagedAuthExchange
    {
        $state = $request->query('state');
        $code = $request->query('code');
        $sessionNonce = $request->session()->get(self::SESSION_NONCE_KEY);

        if (! is_string($state)
            || preg_match('/^[A-Za-z0-9_-]{43}$/', $state) !== 1
            || ! is_string($code)
            || $code === ''
            || strlen($code) > 255
            || ! is_string($sessionNonce)
            || preg_match('/^[A-Za-z0-9_-]{43}$/', $sessionNonce) !== 1) {
            throw new ManagedAuthRefused;
        }

        $connection = ManagedAuthConnection::current();
        $now = CarbonImmutable::now();
        if (! $this->claim->consume($connection, $state, $sessionNonce, $now)) {
            throw new ManagedAuthRefused;
        }

        $exchange = $this->client->exchange($connection, $state, $code);
        $current = ManagedAuthConnection::current();

        if ($current->issuer !== $connection->issuer
            || $current->connectionId !== $connection->connectionId
            || $current->organizationId !== $connection->organizationId
            || $current->installationId !== $connection->installationId
            || $current->authorityGeneration !== $connection->authorityGeneration
            || $current->baseUrl !== $connection->baseUrl) {
            throw new ManagedAuthRefused;
        }

        return $exchange;
    }

    private function randomSecret(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }
}
