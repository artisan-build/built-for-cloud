<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use Illuminate\Database\Eloquent\Model;
use InvalidArgumentException;

/**
 * The exact protocol binding attached to one credential.
 *
 * @property string $credential_id
 * @property string $app_purpose
 * @property string $installation_ref
 * @property string $application_ref
 * @property string $audience
 * @property CredentialAlgorithm $algorithm
 * @property CredentialMaterialRole $material_role
 * @property string $scope_hash
 */
final class CredentialProtocolBinding extends Model
{
    protected $primaryKey = 'credential_id';

    public $incrementing = false;

    protected $keyType = 'string';

    /** @var list<string> */
    protected $fillable = [
        'credential_id',
        'app_purpose',
        'installation_ref',
        'application_ref',
        'audience',
        'algorithm',
        'material_role',
        'scope_hash',
    ];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'algorithm' => CredentialAlgorithm::class,
            'material_role' => CredentialMaterialRole::class,
        ];
    }

    protected static function booted(): void
    {
        self::saving(function (self $binding): void {
            $credential = Credential::query()->whereKey($binding->credential_id)->first();

            if ($credential === null) {
                throw new InvalidArgumentException('A protocol binding requires its credential.');
            }

            $scope = new BoundCredentialScope(
                $binding->app_purpose,
                $credential->subject(),
                $binding->installation_ref,
                $binding->application_ref,
                $binding->audience,
            );
            $purpose = app(AppPurposeRegistry::class)->purpose($scope->appPurpose);
            $expected = self::scopeHash(
                $scope,
                $purpose,
                $binding->algorithm,
                $binding->material_role,
            );

            if ($purpose !== $credential->purpose || ! hash_equals($expected, $binding->scope_hash)) {
                throw new InvalidArgumentException('A protocol binding must exactly match its credential and scope hash.');
            }
        });
    }

    public static function createOriginator(Credential $credential, BoundCredentialScope $scope): self
    {
        $purpose = app(AppPurposeRegistry::class)->purpose($scope->appPurpose);
        $algorithm = CredentialAlgorithm::forKind($credential->kind);

        /** @var self */
        return self::query()->create([
            'credential_id' => $credential->id,
            'app_purpose' => $scope->appPurpose,
            'installation_ref' => $scope->installation,
            'application_ref' => $scope->application,
            'audience' => $scope->audience,
            'algorithm' => $algorithm,
            'material_role' => CredentialMaterialRole::Originator,
            'scope_hash' => self::scopeHash($scope, $purpose, $algorithm, CredentialMaterialRole::Originator),
        ]);
    }

    public static function copyTo(self $source, Credential $replacement): self
    {
        /** @var self */
        return self::query()->create([
            'credential_id' => $replacement->id,
            'app_purpose' => $source->app_purpose,
            'installation_ref' => $source->installation_ref,
            'application_ref' => $source->application_ref,
            'audience' => $source->audience,
            'algorithm' => $source->algorithm,
            'material_role' => $source->material_role,
            'scope_hash' => $source->scope_hash,
        ]);
    }

    public function scopeFor(Credential $credential): BoundCredentialScope
    {
        return new BoundCredentialScope(
            $this->app_purpose,
            $credential->subject(),
            $this->installation_ref,
            $this->application_ref,
            $this->audience,
        );
    }

    public function exactlyMatches(
        Credential $credential,
        BoundCredentialScope $scope,
        CredentialPurpose $purpose,
        CredentialAlgorithm $algorithm,
        CredentialMaterialRole $role,
    ): bool {
        return $credential->subject_type === $scope->subject->type
            && hash_equals($credential->subject_ref, $scope->subject->ref)
            && $credential->purpose === $purpose
            && hash_equals($this->app_purpose, $scope->appPurpose)
            && hash_equals($this->installation_ref, $scope->installation)
            && hash_equals($this->application_ref, $scope->application)
            && hash_equals($this->audience, $scope->audience)
            && $this->algorithm === $algorithm
            && $this->material_role === $role
            && hash_equals($this->scope_hash, self::scopeHash($scope, $purpose, $algorithm, $role));
    }

    public static function scopeHash(
        BoundCredentialScope $scope,
        CredentialPurpose $purpose,
        CredentialAlgorithm $algorithm,
        CredentialMaterialRole $role,
    ): string {
        $preimage = "bfc-scope-v1\0";

        foreach ([
            $scope->subject->type->value,
            $scope->subject->ref,
            $scope->appPurpose,
            $purpose->value,
            $scope->installation,
            $scope->application,
            $scope->audience,
            $algorithm->value,
            $role->value,
        ] as $field) {
            $preimage .= pack('N', strlen($field)).$field;
        }

        return hash('sha256', $preimage);
    }
}
