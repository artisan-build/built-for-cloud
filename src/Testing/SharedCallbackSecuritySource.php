<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use RuntimeException;

final class SharedCallbackSecuritySource
{
    public static function rootFor(string $builtForCloudSourceRoot): string
    {
        $packageRoot = dirname($builtForCloudSourceRoot);
        $candidates = [
            $packageRoot.'/vendor/artisan-build/bfc-client/src',
            dirname($packageRoot).'/bfc-client/src',
        ];

        foreach ($candidates as $candidate) {
            if (is_dir($candidate)) {
                return realpath($candidate) ?: $candidate;
            }
        }

        throw new RuntimeException('Could not locate the installed bfc-client source required by the callback-security inventory.');
    }
}
