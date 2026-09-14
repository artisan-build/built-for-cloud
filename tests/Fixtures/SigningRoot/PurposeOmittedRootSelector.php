<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures\SigningRoot;

use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\Hmac\HmacKeyring;
use ArtisanBuild\BuiltForCloud\Hmac\SigningRootMac;
use ArtisanBuild\BuiltForCloud\SubjectType;

final class PurposeOmittedRootSelector
{
    public function __construct(private HmacKeyring $keyring) {}

    public function select(): string
    {
        /** @var Credential $root */
        $root = Credential::query()
            ->where('kind', CredentialKind::Hmac->value)
            ->where('subject_type', SubjectType::Installation->value)
            ->where('subject_ref', SigningRootMac::SUBJECT_REF)
            ->firstOrFail();

        return $this->keyring->decrypt((string) $root->secret_ciphertext, $root->secret_key_version);
    }
}
