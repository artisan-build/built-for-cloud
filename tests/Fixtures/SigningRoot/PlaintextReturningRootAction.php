<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures\SigningRoot;

use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\Hmac\HmacKeyring;

final class PlaintextReturningRootAction
{
    public function __construct(private HmacKeyring $keyring) {}

    public function reveal(): string
    {
        /** @var Credential $root */
        $root = Credential::query()->where('purpose', CredentialPurpose::SigningRoot->value)->firstOrFail();
        $plaintext = $this->keyring->decrypt((string) $root->secret_ciphertext, $root->secret_key_version);

        return $plaintext;
    }
}
