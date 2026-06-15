<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Database\Factories;

use ArtisanBuild\BuiltForCloud\ApiToken;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<ApiToken>
 */
final class ApiTokenFactory extends Factory
{
    protected $model = ApiToken::class;

    /**
     * @return array{name: string, token_hash: string, expires_at: null}
     */
    public function definition(): array
    {
        $plaintext = bin2hex(random_bytes(32));

        return [
            'name' => fake()->word(),
            'token_hash' => hash('sha256', $plaintext),
            'expires_at' => null,
        ];
    }
}
