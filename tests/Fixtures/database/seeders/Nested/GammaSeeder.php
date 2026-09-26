<?php

declare(strict_types=1);

namespace Database\Seeders\Nested;

use Illuminate\Database\Seeder;

/** An app seeder fixture in a subdirectory, so discovery must follow the PSR-4 path. */
final class GammaSeeder extends Seeder
{
    /** Record this seeder in the run log the test reads. */
    public function run(): void
    {
        $GLOBALS['bfc_fresh_seeders'][] = self::class;
    }
}
