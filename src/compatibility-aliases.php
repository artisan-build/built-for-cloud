<?php

declare(strict_types=1);

$aliases = [
    ArtisanBuild\BfcClient\BoundCredentialScope::class => ArtisanBuild\BuiltForCloud\BoundCredentialScope::class,
    ArtisanBuild\BfcClient\ClaimedHmacCredential::class => ArtisanBuild\BuiltForCloud\ClaimedHmacCredential::class,
    ArtisanBuild\BfcClient\Contracts\HmacCredentialIssuerClient::class => ArtisanBuild\BuiltForCloud\Contracts\HmacCredentialIssuerClient::class,
    ArtisanBuild\BfcClient\CredentialKind::class => ArtisanBuild\BuiltForCloud\CredentialKind::class,
    ArtisanBuild\BfcClient\CredentialMaterialRole::class => ArtisanBuild\BuiltForCloud\CredentialMaterialRole::class,
    ArtisanBuild\BfcClient\CredentialPurpose::class => ArtisanBuild\BuiltForCloud\CredentialPurpose::class,
    ArtisanBuild\BfcClient\CredentialStatus::class => ArtisanBuild\BuiltForCloud\CredentialStatus::class,
    ArtisanBuild\BfcClient\Exceptions\HmacCredentialTransferRefused::class => ArtisanBuild\BuiltForCloud\Exceptions\HmacCredentialTransferRefused::class,
    ArtisanBuild\BfcClient\Exceptions\HmacKeyUnreadable::class => ArtisanBuild\BuiltForCloud\Exceptions\HmacKeyUnreadable::class,
    ArtisanBuild\BfcClient\Exceptions\HmacVerificationFailed::class => ArtisanBuild\BuiltForCloud\Exceptions\HmacVerificationFailed::class,
    ArtisanBuild\BfcClient\Hmac\EncryptedHmacKey::class => ArtisanBuild\BuiltForCloud\Hmac\EncryptedHmacKey::class,
    ArtisanBuild\BfcClient\Hmac\HmacEnvelope::class => ArtisanBuild\BuiltForCloud\Hmac\HmacEnvelope::class,
    ArtisanBuild\BfcClient\HmacCredentialTransfer::class => ArtisanBuild\BuiltForCloud\HmacCredentialTransfer::class,
    ArtisanBuild\BfcClient\ImportedHmacSecret::class => ArtisanBuild\BuiltForCloud\ImportedHmacSecret::class,
    ArtisanBuild\BfcClient\InstalledHmacCredential::class => ArtisanBuild\BuiltForCloud\InstalledHmacCredential::class,
    ArtisanBuild\BfcClient\IssuerHmacCutoverReceipt::class => ArtisanBuild\BuiltForCloud\IssuerHmacCutoverReceipt::class,
    ArtisanBuild\BfcClient\SensitiveString::class => ArtisanBuild\BuiltForCloud\SensitiveString::class,
    ArtisanBuild\BfcClient\Subject::class => ArtisanBuild\BuiltForCloud\Subject::class,
    ArtisanBuild\BfcClient\SubjectType::class => ArtisanBuild\BuiltForCloud\SubjectType::class,
    ArtisanBuild\BfcClient\VerifiedHmacCredential::class => ArtisanBuild\BuiltForCloud\VerifiedHmacCredential::class,
];

foreach ($aliases as $implementation => $compatibilityName) {
    if (! class_exists($compatibilityName, false) && ! interface_exists($compatibilityName, false)) {
        class_alias($implementation, $compatibilityName);
    }
}
