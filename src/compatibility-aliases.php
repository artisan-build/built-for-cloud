<?php

declare(strict_types=1);
use ArtisanBuild\BfcClient\BoundCredentialScope;
use ArtisanBuild\BfcClient\ClaimedHmacCredential;
use ArtisanBuild\BfcClient\Contracts\HmacCredentialIssuerClient;
use ArtisanBuild\BfcClient\CredentialKind;
use ArtisanBuild\BfcClient\CredentialMaterialRole;
use ArtisanBuild\BfcClient\CredentialPurpose;
use ArtisanBuild\BfcClient\CredentialStatus;
use ArtisanBuild\BfcClient\Exceptions\HmacCredentialTransferRefused;
use ArtisanBuild\BfcClient\Exceptions\HmacKeyUnreadable;
use ArtisanBuild\BfcClient\Hmac\EncryptedHmacKey;
use ArtisanBuild\BfcClient\Hmac\HmacEnvelope;
use ArtisanBuild\BfcClient\HmacCredentialTransfer;
use ArtisanBuild\BfcClient\ImportedHmacSecret;
use ArtisanBuild\BfcClient\InstalledHmacCredential;
use ArtisanBuild\BfcClient\IssuerHmacCutoverReceipt;
use ArtisanBuild\BfcClient\SensitiveString;
use ArtisanBuild\BfcClient\Subject;
use ArtisanBuild\BfcClient\SubjectType;
use ArtisanBuild\BfcClient\VerifiedHmacCredential;

$aliases = [
    BoundCredentialScope::class => ArtisanBuild\BuiltForCloud\BoundCredentialScope::class,
    ClaimedHmacCredential::class => ArtisanBuild\BuiltForCloud\ClaimedHmacCredential::class,
    HmacCredentialIssuerClient::class => ArtisanBuild\BuiltForCloud\Contracts\HmacCredentialIssuerClient::class,
    CredentialKind::class => ArtisanBuild\BuiltForCloud\CredentialKind::class,
    CredentialMaterialRole::class => ArtisanBuild\BuiltForCloud\CredentialMaterialRole::class,
    CredentialPurpose::class => ArtisanBuild\BuiltForCloud\CredentialPurpose::class,
    CredentialStatus::class => ArtisanBuild\BuiltForCloud\CredentialStatus::class,
    HmacCredentialTransferRefused::class => ArtisanBuild\BuiltForCloud\Exceptions\HmacCredentialTransferRefused::class,
    HmacKeyUnreadable::class => ArtisanBuild\BuiltForCloud\Exceptions\HmacKeyUnreadable::class,
    EncryptedHmacKey::class => ArtisanBuild\BuiltForCloud\Hmac\EncryptedHmacKey::class,
    HmacEnvelope::class => ArtisanBuild\BuiltForCloud\Hmac\HmacEnvelope::class,
    HmacCredentialTransfer::class => ArtisanBuild\BuiltForCloud\HmacCredentialTransfer::class,
    ImportedHmacSecret::class => ArtisanBuild\BuiltForCloud\ImportedHmacSecret::class,
    InstalledHmacCredential::class => ArtisanBuild\BuiltForCloud\InstalledHmacCredential::class,
    IssuerHmacCutoverReceipt::class => ArtisanBuild\BuiltForCloud\IssuerHmacCutoverReceipt::class,
    SensitiveString::class => ArtisanBuild\BuiltForCloud\SensitiveString::class,
    Subject::class => ArtisanBuild\BuiltForCloud\Subject::class,
    SubjectType::class => ArtisanBuild\BuiltForCloud\SubjectType::class,
    VerifiedHmacCredential::class => ArtisanBuild\BuiltForCloud\VerifiedHmacCredential::class,
];

foreach ($aliases as $implementation => $compatibilityName) {
    if (! class_exists($compatibilityName, false) && ! interface_exists($compatibilityName, false)) {
        class_alias($implementation, $compatibilityName);
    }
}
