<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Database\Factories\CredentialFactory;
use Carbon\CarbonInterface;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use InvalidArgumentException;

/**
 * A row in the unified credential store.
 *
 * `name` is decorative: nullable, freely editable, deliberately NON-unique.
 * Renaming a credential changes nothing about authentication or identity, and
 * two credentials of the same name coexist and authenticate independently.
 * Tenancy lives in `subject_ref`, never in the name.
 *
 * Secrets at rest are sha256 hashes only. An `asymmetric` row carries a
 * public key and NEVER any secret material — persisting a `secret_hash` on
 * one throws. There is no column for private keys anywhere in this store.
 *
 * The model is Authenticatable so an unbound credential can be the request
 * principal on the `bfc` guard; a user-bound credential (`user_id` set)
 * resolves to its user instead.
 *
 * @property string $id
 * @property CredentialKind $kind
 * @property SubjectType $subject_type
 * @property string $subject_ref
 * @property string|null $name
 * @property array<int, string>|null $abilities
 * @property string|null $user_id
 * @property string|null $secret_hash
 * @property string|null $public_key
 * @property CredentialStatus $status
 * @property CarbonInterface|null $revoked_at
 * @property CarbonInterface|null $rotated_at
 * @property CarbonInterface|null $expires_at
 * @property CarbonInterface|null $last_used_at
 * @property CarbonInterface|null $created_at
 * @property CarbonInterface|null $updated_at
 *
 * @method static CredentialFactory factory($count = null, $state = [])
 */
final class Credential extends Model implements Authenticatable
{
    /** @use HasFactory<CredentialFactory> */
    use HasFactory;

    use HasUuids;

    public $incrementing = false;

    protected $keyType = 'string';

    /**
     * @var list<string>
     */
    protected $fillable = [
        'id',
        'kind',
        'subject_type',
        'subject_ref',
        'name',
        'abilities',
        'user_id',
        'secret_hash',
        'public_key',
        'status',
        'revoked_at',
        'rotated_at',
        'expires_at',
        'last_used_at',
    ];

    /**
     * @var list<string>
     */
    protected $hidden = [
        'secret_hash',
    ];

    /**
     * @var array<string, mixed>
     */
    protected $attributes = [
        'status' => 'active',
    ];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'kind' => CredentialKind::class,
            'subject_type' => SubjectType::class,
            'status' => CredentialStatus::class,
            'abilities' => 'array',
            'revoked_at' => 'datetime',
            'rotated_at' => 'datetime',
            'expires_at' => 'datetime',
            'last_used_at' => 'datetime',
        ];
    }

    /**
     * The model is the package's enforcement point for "public keys only":
     * raw query-builder writes bypass these checks, so every framework code
     * path persists credentials through the model.
     */
    protected static function booted(): void
    {
        self::saving(function (Credential $credential): void {
            if ($credential->kind === CredentialKind::Asymmetric && $credential->secret_hash !== null) {
                throw new InvalidArgumentException(
                    'An asymmetric credential carries a public key only and never stores secret material.',
                );
            }

            $publicKey = $credential->public_key;

            if ($publicKey === null) {
                return;
            }

            // On ANY kind: the public_key column never stores private-key
            // material (PEM private / encrypted-private markers).
            if (preg_match('/-----BEGIN[A-Z0-9 ]*PRIVATE KEY-----/i', $publicKey) === 1) {
                throw new InvalidArgumentException(
                    'The public_key column never stores private-key material.',
                );
            }

            if ($credential->kind !== CredentialKind::Asymmetric) {
                return;
            }

            // Inline PEM only. openssl_pkey_get_public() also accepts
            // file:// URLs and bare filesystem paths, which would let a row
            // persist a mutable locator instead of key material.
            $trimmed = trim($publicKey);

            if (! str_starts_with($trimmed, '-----BEGIN') || ! str_contains($trimmed, 'PUBLIC KEY-----')) {
                throw new InvalidArgumentException(
                    'An asymmetric credential requires inline PEM public-key material, never a file reference.',
                );
            }

            // And it must actually BE a public key.
            if (openssl_pkey_get_public($publicKey) === false) {
                throw new InvalidArgumentException(
                    'An asymmetric credential requires a parseable public key.',
                );
            }
        });
    }

    /**
     * Null or empty abilities grant NOTHING. Fails closed.
     */
    public function hasAbility(string $ability): bool
    {
        if ($this->abilities === null || $this->abilities === []) {
            return false;
        }

        return in_array($ability, $this->abilities, true);
    }

    public function subject(): Subject
    {
        return new Subject($this->subject_type, $this->subject_ref);
    }

    /**
     * Rows a presented secret may authenticate as: active status, not
     * revoked, not expired. Pending rows never authenticate.
     *
     * @param  Builder<Credential>  $query
     * @return Builder<Credential>
     */
    public function scopeActive(Builder $query): Builder
    {
        return $query
            ->where('status', CredentialStatus::Active->value)
            ->whereNull('revoked_at')
            ->where(function (Builder $query): void {
                $query->whereNull('expires_at')
                    ->orWhere('expires_at', '>', now());
            });
    }

    /**
     * The public-key custody query: every active public key enrolled for a
     * subject, for verifying grants signed by keypairs the subject holds.
     * The store never has the private halves.
     *
     * @return list<string>
     */
    public static function activePublicKeysFor(SubjectType $type, string $ref): array
    {
        /** @var list<string> */
        return self::query()
            ->where('kind', CredentialKind::Asymmetric->value)
            ->where('subject_type', $type->value)
            ->where('subject_ref', $ref)
            ->active()
            ->whereNotNull('public_key')
            ->orderBy('created_at')
            ->orderBy('id')
            ->pluck('public_key')
            ->values()
            ->all();
    }

    public function getAuthIdentifierName(): string
    {
        return $this->getKeyName();
    }

    public function getAuthIdentifier(): mixed
    {
        return $this->getKey();
    }

    public function getAuthPasswordName(): string
    {
        return 'secret_hash';
    }

    public function getAuthPassword(): string
    {
        return (string) $this->secret_hash;
    }

    public function getRememberToken(): ?string
    {
        return null;
    }

    /**
     * @param  string  $value
     */
    public function setRememberToken($value): void
    {
        // Credentials never carry remember tokens.
    }

    public function getRememberTokenName(): string
    {
        return '';
    }

    protected static function newFactory(): CredentialFactory
    {
        return CredentialFactory::new();
    }
}
