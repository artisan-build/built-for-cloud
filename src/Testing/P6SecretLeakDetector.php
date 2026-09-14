<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use InvalidArgumentException;
use RuntimeException;

/** Checks every required live-harness sink for test-created secret material. */
final class P6SecretLeakDetector
{
    /** @var list<string> */
    public const array SURFACES = [
        'process_arguments',
        'files',
        'logs',
        'exception_text',
        'response_bodies',
        'response_headers',
        'queue_payloads',
        'database_plaintext',
        'cache_state',
        'session_state',
        'subsequent_output',
    ];

    /**
     * @param  array<string, mixed>  $surfaces
     * @param  list<string>  $forbiddenMaterials
     */
    public static function assertAbsent(array $surfaces, array $forbiddenMaterials): void
    {
        if (array_keys($surfaces) !== self::SURFACES) {
            throw new InvalidArgumentException('The P6c secret-sink inventory is incomplete or out of order.');
        }

        foreach ($surfaces as $surface => $value) {
            $encoded = json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
            foreach ($forbiddenMaterials as $material) {
                if ($material !== '' && str_contains($encoded, $material)) {
                    throw new RuntimeException("The P6c secret detector found forbidden material in {$surface}.");
                }
            }
        }
    }
}
