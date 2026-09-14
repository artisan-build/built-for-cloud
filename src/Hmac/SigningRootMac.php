<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Hmac;

use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\Exceptions\SigningRootRefused;
use ArtisanBuild\BuiltForCloud\SigningRootMacResult;
use ArtisanBuild\BuiltForCloud\SubjectType;
use Illuminate\Database\Eloquent\Builder;
use Throwable;

final class SigningRootMac
{
    public const string SUBJECT_REF = 'bfc:signing-root';

    public function __construct(private readonly HmacKeyring $keyring) {}

    public function mac(string $bytes): SigningRootMacResult
    {
        $root = $this->soleCurrentRoot();

        return new SigningRootMacResult(
            keyId: $root->id,
            lowercaseHexMac: hash_hmac(
                'sha256',
                $bytes,
                $this->keyring->decrypt((string) $root->secret_ciphertext, $root->secret_key_version),
            ),
        );
    }

    public function verify(string $keyId, string $bytes, string $presentedMac): bool
    {
        if (preg_match('/^[a-f0-9]{64}$/D', $presentedMac) !== 1) {
            return false;
        }

        try {
            $this->soleCurrentRoot();
        } catch (SigningRootRefused) {
            return false;
        }

        /** @var Credential|null $root */
        $root = $this->exactRootQuery()
            ->whereKey($keyId)
            ->active()
            ->first();

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

    public static function isReserved(Credential $credential): bool
    {
        return $credential->purpose === CredentialPurpose::SigningRoot
            || ($credential->subject_type === SubjectType::Installation
                && $credential->subject_ref === self::SUBJECT_REF);
    }

    private function soleCurrentRoot(): Credential
    {
        $current = self::currentCandidates()->get();

        if ($current->count() !== 1) {
            throw SigningRootRefused::unavailable();
        }

        $root = $current->first();

        if ($root === null || ! self::hasExactIdentity($root)) {
            throw SigningRootRefused::unavailable();
        }

        return $root;
    }

    /** @return Builder<Credential> */
    public static function currentCandidates(): Builder
    {
        return self::reservedCandidates()
            ->whereNull('rotated_at')
            ->active();
    }

    /** @return Builder<Credential> */
    public static function reservedCandidates(): Builder
    {
        return Credential::query()->where(function (Builder $query): void {
            $query->where('purpose', CredentialPurpose::SigningRoot->value)
                ->orWhere(function (Builder $query): void {
                    $query->where('subject_type', SubjectType::Installation->value)
                        ->where('subject_ref', self::SUBJECT_REF);
                });
        });
    }

    /**
     * @param  Builder<Credential>  $query
     * @return Builder<Credential>
     */
    public static function excludeReservedFrom(Builder $query): Builder
    {
        return $query
            ->where(function (Builder $query): void {
                $query->whereNull('purpose')
                    ->orWhere('purpose', '!=', CredentialPurpose::SigningRoot->value);
            })
            ->where(function (Builder $query): void {
                $query->where('subject_type', '!=', SubjectType::Installation->value)
                    ->orWhere('subject_ref', '!=', self::SUBJECT_REF);
            });
    }

    /** @return Builder<Credential> */
    private function exactRootQuery(): Builder
    {
        return Credential::query()
            ->where('kind', CredentialKind::Hmac->value)
            ->where('purpose', CredentialPurpose::SigningRoot->value)
            ->where('subject_type', SubjectType::Installation->value)
            ->where('subject_ref', self::SUBJECT_REF)
            ->whereNull('abilities')
            ->whereNull('user_id')
            ->whereNotNull('secret_ciphertext');
    }

    private static function hasExactIdentity(Credential $root): bool
    {
        return $root->kind === CredentialKind::Hmac
            && $root->purpose === CredentialPurpose::SigningRoot
            && $root->subject_type === SubjectType::Installation
            && $root->subject_ref === self::SUBJECT_REF
            && $root->abilities === null
            && $root->user_id === null
            && $root->secret_ciphertext !== null;
    }
}
