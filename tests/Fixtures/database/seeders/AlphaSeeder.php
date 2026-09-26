<?php

declare(strict_types=1);

namespace Database\Seeders;

use Illuminate\Database\Seeder;

/** An app seeder fixture for FreshCommandTest; it records that it ran. */
final class AlphaSeeder extends Seeder
{
    /** Record this seeder in the run log the test reads. */
    public function run(): void
    {
        $GLOBALS['bfc_fresh_seeders'][] = self::class;
    }
}
