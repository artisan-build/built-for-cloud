<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Contracts\DurableCredentialMinter;

/**
 * The default minter: durable credentials land in `api_tokens`, as exchange
 * always has. The plaintext never exists outside its {@see MintedSecret}
 * carrier — only the hash reaches storage.
 */
final class ApiTokenMinter implements DurableCredentialMinter
{
    public function __construct(private readonly TokenRegistry $registry) {}

    public function mint(string $name, string $scope): MintedDurableCredential
    {
        $secret = new MintedSecret(
            (string) config('built-for-cloud.token_prefix').bin2hex(random_bytes(32)),
        );

        $token = $this->registry->store($name, $secret->hash(), abilities: [$scope]);

        return new MintedDurableCredential($secret, $token);
    }
}
