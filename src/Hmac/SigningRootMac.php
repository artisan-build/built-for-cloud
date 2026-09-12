<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Hmac;

use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\Exceptions\SigningRootRefused;
use ArtisanBuild\BuiltForCloud\SigningRootMacResult;
use ArtisanBuild\BuiltForCloud\SubjectType;
use Throwable;

final class SigningRootMac
{
    public const string SUBJECT_REF = 'bfc:signing-root';

    public function __construct(private readonly HmacKeyring $keyring) {}

    public function mac(string $bytes): SigningRootMacResult
    {
        $roots = $this->rootQuery()
            ->whereNull('rotated_at')
            ->active()
            ->get();

        if ($roots->count() !== 1) {
            throw SigningRootRefused::unavailable();
        }

        /** @var Credential $root */
        $root = $roots->first();

        return new SigningRootMacResult(
            $root->id,
            hash_hmac('sha256', $bytes, $this->keyring->decrypt((string) $root->secret_ciphertext, $root->secret_key_version)),
        );
    }

    public function verify(string $keyId, string $bytes, string $presentedMac): bool
    {
        if (preg_match('/^[a-f0-9]{64}$/D', $presentedMac) !== 1) {
            return false;
        }

        /** @var Credential|null $root */
        $root = $this->rootQuery()->whereKey($keyId)->active()->first();

        if ($root === null) {
            return false;
        }

        try {
            $expected = hash_hmac(
                'sha256',
                $bytes,
                $this->keyring->decrypt((string) $root->secret_ciphertext, $root->secret_key_version),
            );
        } catch (Throwable) {
            return false;
        }

        return hash_equals($expected, $presentedMac);
    }

    private function rootQuery(): \Illuminate\Database\Eloquent\Builder
    {
        return Credential::query()
            ->where('kind', CredentialKind::Hmac->value)
            ->where('purpose', CredentialPurpose::SigningRoot->value)
            ->where('subject_type', SubjectType::Installation->value)
            ->where('subject_ref', self::SUBJECT_REF)
            ->whereNotNull('secret_ciphertext');
    }
}
