<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 * Derives requestless package entry points and reports human-authority use.
 *
 * Limit: this is a PHP source inventory, not runtime call-graph analysis. It
 * recognizes the package's explicit provider, interface, and scheduler forms.
 */
final class SystemAuthorityInventory
{
    /**
     * @param  list<string>  $providerFiles
     * @param  list<string>  $roots
     * @return array{
     *   commands: list<string>,
     *   queued: list<string>,
     *   scheduled: list<string>,
     *   violations: array{commands: list<string>, queued: list<string>, scheduled: list<string>}
     * }
     */
    public static function discover(array $providerFiles, array $roots): array
    {
        $sources = self::sources($roots);
        $commands = self::registeredCommands($providerFiles);
        $queued = [];
        $scheduled = [];

        foreach ($sources as $class => $source) {
            if (preg_match('/\bimplements\s+[^\{]*\bShouldQueue\b/s', $source) === 1) {
                $queued[] = $class;
            }

            if (preg_match('/function\s+schedule\s*\([^)]*\bSchedule\b[^)]*\).*?->(?:call|command|job|exec)\s*\(/s', $source) === 1) {
                $scheduled[] = $class.'::schedule';
            }
        }

        sort($commands);
        sort($queued);
        sort($scheduled);

        return [
            'commands' => $commands,
            'queued' => $queued,
            'scheduled' => $scheduled,
            'violations' => [
                'commands' => self::violations($commands, $sources, false),
                'queued' => self::violations($queued, $sources, true),
                'scheduled' => self::violations(array_map(
                    static fn (string $entry): string => strstr($entry, '::', true) ?: $entry,
                    $scheduled,
                ), $sources, true),
            ],
        ];
    }

    /** @param list<string> $providerFiles @return list<string> */
    private static function registeredCommands(array $providerFiles): array
    {
        $commands = [];

        foreach ($providerFiles as $providerFile) {
            $source = (string) file_get_contents($providerFile);
            preg_match('/\bnamespace\s+([^;]+);/', $source, $namespace);
            preg_match_all('/^use\s+([^;]+);/m', $source, $uses);
            $imports = [];
            foreach ($uses[1] as $import) {
                $imports[substr((string) $import, strrpos((string) $import, '\\') + 1)] = (string) $import;
            }

            preg_match_all('/(?:\$this->|self::)commands\s*\(\s*\[(.*?)\]\s*\)/s', $source, $blocks);
            foreach ($blocks[1] as $block) {
                preg_match_all('/\b([A-Za-z_][A-Za-z0-9_]*)::class\b/', (string) $block, $classes);
                foreach ($classes[1] as $short) {
                    $commands[] = $imports[$short] ?? (($namespace[1] ?? '').'\\'.$short);
                }
            }
        }

        return array_values(array_unique($commands));
    }

    /** @param list<string> $roots @return array<class-string|string, string> */
    private static function sources(array $roots): array
    {
        $sources = [];

        foreach ($roots as $root) {
            $files = is_file($root)
                ? [new SplFileInfo($root)]
                : iterator_to_array(new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root)));

            foreach ($files as $file) {
                if (! $file instanceof SplFileInfo || ! $file->isFile() || $file->getExtension() !== 'php') {
                    continue;
                }

                $source = (string) file_get_contents($file->getPathname());
                if (preg_match('/\bnamespace\s+([^;]+);/', $source, $namespace) !== 1
                    || preg_match('/\b(?:final\s+|abstract\s+)?class\s+([A-Za-z_][A-Za-z0-9_]*)\b/', $source, $class) !== 1) {
                    continue;
                }

                $sources[$namespace[1].'\\'.$class[1]] = $source;
            }
        }

        return $sources;
    }

    /**
     * @param  list<string>  $entries
     * @param  array<string, string>  $sources
     * @return list<string>
     */
    private static function violations(array $entries, array $sources, bool $requestless): array
    {
        $violations = [];

        foreach ($entries as $class) {
            $source = $sources[$class] ?? '';
            $isInstallBootstrap = str_ends_with($class, '\\CreateAdminCommand');

            if (preg_match('/\bAuth::(?:login|user|check)\s*\(|\b(?:auth|request)\s*\(\s*\)->user\s*\(/', $source) === 1
                || (! $isInstallBootstrap && preg_match('/\bUser::(?:query|where|find)\s*\(/', $source) === 1)) {
                $violations[] = 'human-principal:'.$class;
            }

            if (! $isInstallBootstrap && preg_match('/\bUserRole::/', $source) === 1) {
                $violations[] = 'human-role:'.$class;
            }

            if ($requestless && preg_match('/\bAuditActor::boundUser\s*\(|\bnew\s+User\b|\bUser::(?:query|where|find)\s*\(/', $source) === 1) {
                $violations[] = 'synthesized-human:'.$class;
            }
        }

        sort($violations);

        return array_values(array_unique($violations));
    }
}
