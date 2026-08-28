<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Database\Factories;

use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\SubjectType;
use Illuminate\Database\Eloquent\Factories\Factory;

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
        return $this->state([
            'kind' => CredentialKind::Asymmetric,
            'secret_hash' => null,
            'public_key' => $publicKey ?? '-----BEGIN PUBLIC KEY-----'.PHP_EOL.base64_encode(random_bytes(32)).PHP_EOL.'-----END PUBLIC KEY-----',
        ]);
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
