<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Database\Factories;

use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\SubjectType;
use Illuminate\Database\Eloquent\Factories\Factory;
use RuntimeException;

/**
 * @extends Factory<Credential>
 */
final class CredentialFactory extends Factory
{
    protected $model = Credential::class;

    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'kind' => CredentialKind::Bearer,
            'subject_type' => SubjectType::Application,
            'subject_ref' => fake()->slug(2),
            'name' => fake()->word(),
            'abilities' => null,
            'status' => CredentialStatus::Active,
            'secret_hash' => hash('sha256', bin2hex(random_bytes(32))),
        ];
    }

    public function basic(): static
    {
        return $this->state(['kind' => CredentialKind::Basic]);
    }

    public function asymmetric(?string $publicKey = null): static
    {
        return $this->state(fn (): array => [
            'kind' => CredentialKind::Asymmetric,
            'secret_hash' => null,
            'public_key' => $publicKey ?? self::generatePublicKey(),
        ]);
    }

    /**
     * A real, parseable public key — the model rejects anything else on an
     * asymmetric row. The private half is discarded immediately: the store
     * never holds one, so neither does the factory.
     */
    public static function generatePublicKey(): string
    {
        $pair = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);

        if ($pair === false) {
            throw new RuntimeException('Could not generate a test keypair.');
        }

        $details = openssl_pkey_get_details($pair);

        if ($details === false || ! is_string($details['key'] ?? null)) {
            throw new RuntimeException('Could not extract the test public key.');
        }

        return $details['key'];
    }

    public function pending(): static
    {
        return $this->state(['status' => CredentialStatus::Pending]);
    }

    public function revoked(): static
    {
        return $this->state(['revoked_at' => now()]);
    }

    public function expired(): static
    {
        return $this->state(['expires_at' => now()->subMinute()]);
    }

    public function forUser(string $userId): static
    {
        return $this->state(['user_id' => $userId]);
    }
}
