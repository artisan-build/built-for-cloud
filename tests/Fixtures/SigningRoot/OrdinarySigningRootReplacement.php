<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures\SigningRoot;

use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\DeliveryShape;
use ArtisanBuild\BuiltForCloud\Hmac\HmacKeyring;
use ArtisanBuild\BuiltForCloud\Hmac\SigningRootMac;
use ArtisanBuild\BuiltForCloud\MintedSecret;
use ArtisanBuild\BuiltForCloud\MintResult;
use ArtisanBuild\BuiltForCloud\SubjectType;

final class OrdinarySigningRootReplacement
{
    public function __construct(private HmacKeyring $keyring) {}

    public function replace(): MintResult
    {
        $plaintext = bin2hex(random_bytes(32));
        $encrypted = $this->keyring->encrypt($plaintext);
        $replacement = new Credential;
        $replacement->forceFill([
            'kind' => CredentialKind::Hmac,
            'purpose' => CredentialPurpose::SigningRoot,
            'subject_type' => SubjectType::Installation,
            'subject_ref' => SigningRootMac::SUBJECT_REF,
            'status' => CredentialStatus::Pending,
            'secret_ciphertext' => $encrypted->ciphertext,
            'secret_key_version' => $encrypted->keyVersion,
        ])->save();

        return new MintResult(
            summary: throw new \LogicException('Positive-control fixture only.'),
            delivery: DeliveryShape::SigningKey,
            secret: new MintedSecret($plaintext),
        );
    }
}
