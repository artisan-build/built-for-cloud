<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use Illuminate\Support\Str;
use InvalidArgumentException;

/**
 * Mints the pending ownership claims that `POST /bfc/ownership/claim` exchanges
 * for an owner token. Shared by the initial-claim migration, the release/swap
 * flow, and the bootstrap CLI so every claim is minted the same way.
 */
final class OwnershipClaimMinter
{
    /**
     * Generate a claim token without touching the database, so a driver-mode
     * command can keep the plaintext local and send only the hash.
     */
    public function generate(): GeneratedToken
    {
        $plaintext = bin2hex(random_bytes(32));

        return new GeneratedToken(
            plaintext: $plaintext,
            hash: OwnershipClaim::hashToken($plaintext),
        );
    }

    /**
     * @return array{string, OwnershipClaim}
     */
    public function mint(): array
    {
        do {
            $generated = $this->generate();
        } while (OwnershipClaim::query()->where('token_hash', $generated->hash)->exists());

        return [$generated->plaintext, $this->mintFromHash($generated->hash)];
    }

    public function mintFromHash(string $tokenHash): OwnershipClaim
    {
        if (! preg_match('/^[0-9a-f]{64}$/', $tokenHash)) {
            throw new InvalidArgumentException('An ownership claim hash must be a sha256 hex digest.');
        }

        if (OwnershipClaim::query()->where('token_hash', $tokenHash)->exists()) {
            throw new InvalidArgumentException('An ownership claim already exists for that hash.');
        }

        /** @var OwnershipClaim $claim */
        $claim = OwnershipClaim::query()->create([
            'id' => (string) Str::uuid(),
            'token_hash' => $tokenHash,
        ]);

        return $claim;
    }
}
