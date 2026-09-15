<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use InvalidArgumentException;

/** Validates that Composer installed the exact candidate artifact archive. */
final class P6ArchiveProof
{
    /** @param array<string, mixed> $lock */
    public static function assertInstalled(array $lock, string $candidateSha, string $archivePath): string
    {
        $version = '0.0.0+p6c.'.$candidateSha;
        $packages = $lock['packages'] ?? null;

        if (preg_match('/^[a-f0-9]{40}$/D', $candidateSha) !== 1
            || ! is_file($archivePath)
            || ! is_array($packages)) {
            throw new InvalidArgumentException('The exact P6c archive installation evidence is invalid.');
        }

        $matches = array_values(array_filter(
            $packages,
            static fn (mixed $package): bool => is_array($package)
                && ($package['name'] ?? null) === 'artisan-build/built-for-cloud',
        ));

        if (count($matches) !== 1) {
            throw new InvalidArgumentException('The fresh host did not install exactly one Built for Cloud package.');
        }

        $package = $matches[0];
        $dist = $package['dist'] ?? null;
        $url = is_array($dist) ? ($dist['url'] ?? null) : null;
        $resolvedUrl = is_string($url) && str_starts_with($url, 'file://')
            ? rawurldecode((string) parse_url($url, PHP_URL_PATH))
            : $url;

        if (($package['version'] ?? null) !== $version
            || ! is_array($dist)
            || ($dist['type'] ?? null) !== 'zip'
            || ! is_string($url)
            || ! is_string($resolvedUrl)
            || realpath($resolvedUrl) !== realpath($archivePath)
            || isset($package['source'])) {
            throw new InvalidArgumentException('The fresh host package source was not the exact candidate artifact archive.');
        }

        return $version;
    }
}
