<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use ArtisanBuild\BuiltForCloud\Console\ConsoleGuardConfiguration;
use ArtisanBuild\BuiltForCloud\User;
use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 * A conventional-path drift detector, not a complete proof that arbitrary
 * application code cannot implement authentication indirectly.
 */
final class ThinHostConformance
{
    /** @return array<string, string> */
    public static function sourceArtifacts(string $root): array
    {
        $artifacts = [];

        foreach (self::phpAndBladeFiles($root) as $relativePath => $file) {
            $path = strtolower(str_replace('\\', '/', $relativePath));
            $basename = strtolower($file->getBasename());
            $kind = match (true) {
                $path === 'app/models/user.php' => 'app-user-model',
                str_starts_with($path, 'database/migrations/')
                    && str_contains($basename, 'create_users_table') => 'users-migration',
                str_starts_with($path, 'app/http/controllers/auth/')
                    || (str_starts_with($path, 'app/http/controllers/')
                        && str_contains($basename, 'authcontroller')) => 'auth-controller',
                str_starts_with($path, 'resources/views/auth/') => 'copied-auth-ui',
                str_starts_with($path, 'app/console/commands/')
                    && str_contains($basename, 'token') => 'token-command',
                default => null,
            };

            if ($kind !== null) {
                $artifacts[$relativePath] = $kind;
            }
        }

        ksort($artifacts);

        return $artifacts;
    }

    /** @param array<string, mixed> $auth
     *  @return list<string>
     */
    public static function configurationArtifacts(array $auth): array
    {
        $artifacts = [];
        $provider = $auth['providers']['users'] ?? null;

        if (! is_array($provider)
            || ($provider['driver'] ?? null) !== 'eloquent'
            || ($provider['model'] ?? null) !== User::class) {
            $artifacts[] = 'human-provider';
        }

        $default = $auth['defaults']['guard'] ?? null;
        $guard = is_string($default) ? ($auth['guards'][$default] ?? null) : null;

        if (! is_array($guard)
            || ($guard['driver'] ?? null) !== 'session'
            || ($guard['provider'] ?? null) !== 'users') {
            $artifacts[] = 'human-guard';
        }

        $allowedGuards = ['web', 'bfc', ConsoleGuardConfiguration::GUARD];

        foreach (array_keys(is_array($auth['guards'] ?? null) ? $auth['guards'] : []) as $name) {
            if (is_string($name) && ! in_array($name, $allowedGuards, true)) {
                $artifacts[] = 'custom-guard:'.$name;
            }
        }

        return $artifacts;
    }

    /** @return iterable<string, SplFileInfo> */
    private static function phpAndBladeFiles(string $root): iterable
    {
        if (! is_dir($root)) {
            return;
        }

        $files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
        );

        /** @var SplFileInfo $file */
        foreach ($files as $file) {
            if ($file->isFile() && ($file->getExtension() === 'php' || str_ends_with($file->getFilename(), '.blade.php'))) {
                yield substr($file->getPathname(), strlen($root) + 1) => $file;
            }
        }
    }
}
