<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Database\Factories;

use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\Hmac\HmacKeyring;
use ArtisanBuild\BuiltForCloud\SubjectType;
use Illuminate\Database\Eloquent\Factories\Factory;
use RuntimeException;
use SensitiveParameter;

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

    /**
     * An hmac signing-key row, encrypted through the real keyring so the
     * ciphertext and key-version are exactly what the verbs produce. The
     * kind starts PENDING and undelivered — the lifecycle the verbs walk;
     * use {@see delivered()} / {@see activated()} to advance it.
     */
    public function hmac(#[SensitiveParameter] ?string $signingKey = null): static
    {
        return $this->state(function () use ($signingKey): array {
            $encrypted = app(HmacKeyring::class)->encrypt($signingKey ?? bin2hex(random_bytes(32)));

            return [
                'kind' => CredentialKind::Hmac,
                'status' => CredentialStatus::Pending,
                'secret_hash' => null,
                'secret_ciphertext' => $encrypted->ciphertext,
                'secret_key_version' => $encrypted->keyVersion,
            ];
        });
    }

    public function delivered(): static
    {
        return $this->state(['delivered_at' => now()]);
    }

    public function activated(): static
    {
        return $this->state([
            'status' => CredentialStatus::Active,
            'delivered_at' => now(),
            'activated_at' => now(),
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
