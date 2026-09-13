<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Queue\ShouldQueue;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 * Derives requestless package entry points and reports human-authority use.
 *
 * Limits: registered commands are read from explicit provider commands([...])
 * lists. Queue membership uses the framework interface at runtime, but the
 * authority checks inspect declared source rather than transitive call graphs.
 * Schedules come from the framework registry; an event whose display summary
 * cannot identify a class in the scanned roots is reported as uninspectable.
 * Dynamically generated code and calls into unscanned consumer/vendor code are
 * outside this source-level instrument.
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

        foreach (array_keys($sources) as $class) {
            if (is_a($class, ShouldQueue::class, true)) {
                $queued[] = $class;
            }
        }

        $scheduled = array_map(
            static fn ($event): string => (string) $event->getSummaryForDisplay(),
            app(Schedule::class)->events(),
        );

        sort($commands);
        sort($queued);
        sort($scheduled);

        return [
            'commands' => $commands,
            'queued' => $queued,
            'scheduled' => $scheduled,
            'violations' => [
                'commands' => self::violations($commands, $sources),
                'queued' => self::violations($queued, $sources),
                'scheduled' => self::scheduledViolations($scheduled, $sources),
            ],
        ];
    }

    /**
     * @param  list<string>  $providerFiles
     * @return list<string>
     */
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

    /**
     * @param  list<string>  $roots
     * @return array<string, string>
     */
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
                foreach (self::declaredClasses($source) as $class) {
                    $sources[$class] = $source;
                }
            }
        }

        return $sources;
    }

    /**
     * @param  list<string>  $entries
     * @param  array<string, string>  $sources
     * @return list<string>
     */
    private static function violations(array $entries, array $sources): array
    {
        $violations = [];

        foreach ($entries as $class) {
            $source = $sources[$class] ?? '';

            if (preg_match('/\bAuth::(?:login|user|check)\s*\(|\b(?:auth|request)\s*\(\s*\)->user\s*\(/', $source) === 1
                || preg_match('/\bUser::(?:find|findOrFail|first|firstOrFail|sole)\s*\(/', $source) === 1
                || preg_match('/\bUser::(?:query|where)\s*\([^;]*?->(?:first|firstOrFail|find|findOrFail|sole|get)\s*\(/s', $source) === 1) {
                $violations[] = 'human-principal:'.$class;
            }

            if (self::derivesHumanRole($source)) {
                $violations[] = 'human-role:'.$class;
            }

            if (preg_match('/\bAuditActor::boundUser\s*\(|\bAuth::login\s*\(/', $source) === 1) {
                $violations[] = 'synthesized-human:'.$class;
            }
        }

        sort($violations);

        return array_values(array_unique($violations));
    }

    private static function derivesHumanRole(string $source): bool
    {
        if (! str_contains($source, 'UserRole::')) {
            return false;
        }

        // Creating a user may inspect whether an Owner row exists and persist
        // enum values. Those operations write membership; they do not grant
        // the command authority from the membership they inspect.
        $withoutUserWrites = preg_replace([
            '/\bUser::query\(\)\s*->where\(\s*[\'\"]role[\'\"]\s*,\s*UserRole::[A-Za-z_][A-Za-z0-9_]*->value\s*\)\s*->exists\(\)/s',
            '/[\'\"]role[\'\"]\s*=>[^,\n]*\bUserRole::[^,\n]*/',
        ], '', $source);

        return is_string($withoutUserWrites) && str_contains($withoutUserWrites, 'UserRole::');
    }

    /**
     * @param  list<string>  $entries
     * @param  array<string, string>  $sources
     * @return list<string>
     */
    private static function scheduledViolations(array $entries, array $sources): array
    {
        $violations = [];

        foreach ($entries as $entry) {
            $class = strstr($entry, '::', true) ?: $entry;
            if (! isset($sources[$class])) {
                $violations[] = 'uninspectable-schedule:'.$entry;

                continue;
            }

            array_push($violations, ...self::violations([$class], $sources));
        }

        sort($violations);

        return array_values(array_unique($violations));
    }

    /** @return list<class-string> */
    private static function declaredClasses(string $source): array
    {
        $tokens = token_get_all($source);
        $namespace = '';
        $classes = [];

        foreach ($tokens as $index => $token) {
            if (! is_array($token)) {
                continue;
            }

            if ($token[0] === T_NAMESPACE) {
                $namespace = '';
                for ($cursor = $index + 1; isset($tokens[$cursor]); $cursor++) {
                    $part = $tokens[$cursor];
                    if ($part === ';' || $part === '{') {
                        break;
                    }
                    if (is_array($part) && in_array($part[0], [T_STRING, T_NAME_QUALIFIED, T_NS_SEPARATOR], true)) {
                        $namespace .= $part[1];
                    }
                }

                continue;
            }

            if ($token[0] !== T_CLASS) {
                continue;
            }

            for ($previous = $index - 1; $previous >= 0; $previous--) {
                if (is_array($tokens[$previous]) && in_array($tokens[$previous][0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                    continue;
                }
                if (is_array($tokens[$previous]) && in_array($tokens[$previous][0], [T_NEW, T_DOUBLE_COLON], true)) {
                    continue 2;
                }
                break;
            }

            for ($cursor = $index + 1; isset($tokens[$cursor]); $cursor++) {
                if (is_array($tokens[$cursor]) && $tokens[$cursor][0] === T_STRING) {
                    $classes[] = ltrim($namespace.'\\'.$tokens[$cursor][1], '\\');

                    break;
                }
            }
        }

        return $classes;
    }
}
