<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\Auth\CredentialResolver;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialAuthenticator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use RuntimeException;
use SplFileInfo;

final class ManagedIngressManifest
{
    /**
     * @param  list<string>  $additionalAuthenticatorRoots
     * @return list<class-string>
     */
    public static function discover(string $sourceRoot, array $additionalAuthenticatorRoots = []): array
    {
        $provider = self::contents($sourceRoot.'/BuiltForCloudServiceProvider.php');
        $ownership = self::contents($sourceRoot.'/StandaloneRouteOwnership.php');
        $components = [CredentialResolver::class];

        $providerImports = self::imports($provider);
        preg_match_all(
            '/\$auth->extend\((?:(?!\$auth->extend).)*?return\s+new\s+([A-Z][A-Za-z0-9_]*)\s*\(/s',
            $provider,
            $guardMatches,
        );
        if (count($guardMatches[1]) !== substr_count($provider, '$auth->extend(')) {
            throw new RuntimeException('Not every guard extension resolved to a concrete guard class.');
        }

        foreach ($guardMatches[1] as $guard) {
            $components[] = self::imported($providerImports, $guard);
        }

        preg_match_all('/aliasMiddleware\([^,]+,\s*([A-Z][A-Za-z0-9_]*)::class\)/', $provider, $aliasMatches);
        if (count($aliasMatches[1]) !== substr_count($provider, 'aliasMiddleware(')) {
            throw new RuntimeException('Not every middleware alias resolved to a concrete middleware class.');
        }

        foreach ($aliasMatches[1] as $middleware) {
            $components[] = self::imported($providerImports, $middleware);
        }

        if (! str_contains($provider, 'StandaloneRouteOwnership::operatorGateForAction')) {
            throw new RuntimeException('The provider no longer binds its operator middleware by class through the ownership inventory.');
        }

        $ownershipImports = self::imports($ownership);
        preg_match_all('/=>\s*([A-Z][A-Za-z0-9_]*)::class(?:\.|,)/', $ownership, $classMatches);
        foreach ($classMatches[1] as $middleware) {
            $class = self::imported($ownershipImports, $middleware);

            if (str_starts_with($class, 'ArtisanBuild\\BuiltForCloud\\Http\\Middleware\\')) {
                $components[] = $class;
            }
        }

        foreach ([$sourceRoot, ...$additionalAuthenticatorRoots] as $root) {
            array_push($components, ...self::credentialAuthenticators($root));
        }

        $components = array_values(array_unique($components));
        sort($components);

        return $components;
    }

    /**
     * @param  list<class-string>  $discovered
     * @param  array<class-string, string>  $manifest
     * @return list<class-string>
     */
    public static function unexpected(array $discovered, array $manifest): array
    {
        return self::difference($discovered, array_keys($manifest));
    }

    /**
     * @param  list<class-string>  $discovered
     * @param  array<class-string, string>  $manifest
     * @return list<class-string>
     */
    public static function missing(array $discovered, array $manifest): array
    {
        return self::difference(array_keys($manifest), $discovered);
    }

    /**
     * @return array<string, class-string>
     */
    private static function imports(string $contents): array
    {
        preg_match_all('/^use\s+([^;]+);$/m', $contents, $matches);
        $imports = [];

        foreach ($matches[1] as $class) {
            $short = strrchr($class, '\\');
            $imports[$short === false ? $class : substr($short, 1)] = $class;
        }

        return $imports;
    }

    /**
     * @param  array<string, class-string>  $imports
     * @return class-string
     */
    private static function imported(array $imports, string $short): string
    {
        return $imports[$short] ?? throw new RuntimeException("Could not resolve imported class [{$short}].");
    }

    /**
     * @return list<class-string>
     */
    private static function credentialAuthenticators(string $root): array
    {
        $classes = [];
        $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root));

        foreach ($files as $file) {
            if (! $file instanceof SplFileInfo || ! $file->isFile() || $file->getExtension() !== 'php') {
                continue;
            }

            $contents = self::contents($file->getPathname());

            if (preg_match('/^namespace\s+([^;]+);/m', $contents, $namespace) !== 1
                || preg_match('/\bclass\s+([A-Z][A-Za-z0-9_]*)\b/', $contents, $class) !== 1) {
                continue;
            }

            $candidate = $namespace[1].'\\'.$class[1];

            if (is_subclass_of($candidate, CredentialAuthenticator::class)) {
                $classes[] = $candidate;
            }
        }

        return $classes;
    }

    /**
     * @param  list<class-string>  $left
     * @param  list<class-string>  $right
     * @return list<class-string>
     */
    private static function difference(array $left, array $right): array
    {
        $difference = array_values(array_diff($left, $right));
        sort($difference);

        return $difference;
    }

    private static function contents(string $path): string
    {
        $contents = file_get_contents($path);

        return is_string($contents) ? $contents : throw new RuntimeException("Could not read [{$path}].");
    }
}
