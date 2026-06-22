<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Database\Factories;

use ArtisanBuild\BuiltForCloud\Invitation;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;

/**
 * @extends Factory<Invitation>
 */
final class InvitationFactory extends Factory
{
    protected $model = Invitation::class;

    /**
     * @return array{email: string, token: string, expires_at: Carbon}
     */
    public function definition(): array
    {
        return [
            'email' => fake()->unique()->safeEmail(),
            'token' => Str::random(40),
            'expires_at' => now()->addDays(7),
        ];
    }
}
