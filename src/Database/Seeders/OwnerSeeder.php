<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Database\Seeders;

use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\Hash;

/**
 * The one person every freshly seeded development database starts with: an
 * active, verified Owner who can sign in straight away. Run by `php artisan
 * fresh`, which refuses to run in production.
 */
final class OwnerSeeder extends Seeder
{
    public const string EMAIL = 'owner@example.com';

    public const string PASSWORD = 'password';

    /** Create the Owner. */
    public function run(): void
    {
        (new User)->forceFill([
            'name' => 'Owner',
            'email' => self::EMAIL,
            'original_contact_email' => self::EMAIL,
            'password' => Hash::make(self::PASSWORD),
            'role' => UserRole::Owner->value,
            'status' => 'active',
            'email_verified_at' => Date::now(),
        ])->save();
    }
}
