<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use Closure;
use Illuminate\Console\Command;
use Illuminate\Console\Scheduling\CallbackEvent;
use Illuminate\Console\Scheduling\Event;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Support\Facades\Facade;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use ReflectionFunction;
use ReflectionNamedType;
use ReflectionProperty;
use ReflectionUnionType;
use SplFileInfo;
use Throwable;

/**
 * Derives requestless package entry points and reports human-authority use.
 *
 * Limits: registered commands are read from explicit provider commands([...])
 * lists. Queue membership uses the framework interface at runtime, but the
 * authority checks inspect declared source rather than transitive call graphs.
 * Schedules combine the framework registry's actual callable/command identity
 * with a tokenized scheduling-reference tripwire across scanned roots. A real
 * callable or command outside those roots is reported as uninspectable, while
 * conditional registrations remain visible to the tripwire. Dynamically
 * generated registrations, transitive calls, and unscanned consumer/vendor
 * code remain outside this source-level instrument.
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

        [$scheduled, $scheduleSources] = self::scheduledEntries(
            app(Schedule::class)->events(),
            $commands,
            $sources,
            $roots,
        );
        $sources = $scheduleSources + $sources;

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
                'scheduled' => self::scheduledViolations($scheduled, $sources, $roots),
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
            $authoritySource = self::withoutPermittedUserWriteRoles($source);
            $authenticatesHuman = self::authenticatesHuman($source);

            if ($authenticatesHuman
                || preg_match('/\bAuth::(?:user|check)\s*\(|\b(?:auth|request)\s*\(\s*\)->user\s*\(/', $source) === 1
                || preg_match('/\bUser::(?:find|findOrFail|first|firstOrFail|sole)\s*\(/', $authoritySource) === 1
                || preg_match('/\bUser::(?:query|where)\s*\([^;]*?->(?:first|firstOrFail|find|findOrFail|sole|get|exists|count)\s*\(/s', $authoritySource) === 1) {
                $violations[] = 'human-principal:'.$class;
            }

            if (str_contains($authoritySource, 'UserRole::')) {
                $violations[] = 'human-role:'.$class;
            }

            if ($authenticatesHuman || preg_match('/\bAuditActor::boundUser\s*\(/', $source) === 1) {
                $violations[] = 'synthesized-human:'.$class;
            }
        }

        sort($violations);

        return array_values(array_unique($violations));
    }

    private static function authenticatesHuman(string $source): bool
    {
        $tokens = self::significantTokens($source);
        $imports = self::imports($source);
        $authVariables = [];

        foreach ($tokens as $index => $token) {
            if (is_array($token) && $token[0] === T_VARIABLE && ($tokens[$index + 1] ?? null) === '=') {
                $end = self::expressionEnd($tokens, $index + 2);
                if (self::authReceiver(array_slice($tokens, $index + 2, $end - $index - 2), $imports, $authVariables)) {
                    $authVariables[$token[1]] = true;
                }
            }

            if (! is_array($token) || $token[0] !== T_STRING
                || ! in_array($token[1], ['login', 'loginUsingId', 'once', 'setUser'], true)) {
                continue;
            }

            $operator = $tokens[$index - 1] ?? null;
            if ($operator === '::') {
                $receiver = $tokens[$index - 2] ?? null;
                if (is_array($receiver) && self::authClass(self::resolveClass($receiver[1], $imports))) {
                    return true;
                }
            }

            if ($operator === '->') {
                $start = self::receiverStart($tokens, $index - 2);
                if (self::authReceiver(array_slice($tokens, $start, $index - 1 - $start), $imports, $authVariables)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * @param  list<array{int, string, int}|string>  $tokens
     * @param  array<string, class-string>  $imports
     * @param  array<string, true>  $authVariables
     */
    private static function authReceiver(array $tokens, array $imports, array $authVariables): bool
    {
        if ($tokens === []) {
            return false;
        }

        $last = array_key_last($tokens);
        $tail = $tokens[$last];

        if (is_array($tail) && $tail[0] === T_VARIABLE) {
            return isset($authVariables[$tail[1]]);
        }

        if ($tail !== ')') {
            return false;
        }

        $open = self::matchingOpenParenthesis($tokens, $last);
        if ($open === null || $open === 0 || ! is_array($tokens[$open - 1])) {
            return false;
        }

        $call = $tokens[$open - 1][1];
        $operator = $tokens[$open - 2] ?? null;

        if ($operator === '::' || $operator === '->') {
            if ($call !== 'guard') {
                return false;
            }

            $receiver = array_slice($tokens, 0, $open - 2);

            return $operator === '::'
                ? count($receiver) === 1 && is_array($receiver[0]) && self::authClass(self::resolveClass($receiver[0][1], $imports))
                : self::authReceiver($receiver, $imports, $authVariables);
        }

        if (! function_exists($call)) {
            return false;
        }

        $returnType = (new ReflectionFunction($call))->getReturnType();
        $types = $returnType instanceof ReflectionUnionType ? $returnType->getTypes() : [$returnType];

        foreach ($types as $type) {
            if ($type instanceof ReflectionNamedType && ! $type->isBuiltin() && self::authClass($type->getName())) {
                return true;
            }
        }

        return false;
    }

    /** @param array<string, class-string> $imports */
    private static function resolveClass(string $name, array $imports): string
    {
        return $imports[$name] ?? ltrim($name, '\\');
    }

    private static function authClass(string $class): bool
    {
        if (is_a($class, AuthFactory::class, true) || is_a($class, Guard::class, true)) {
            return true;
        }

        if (! is_a($class, Facade::class, true)) {
            return false;
        }

        try {
            $root = $class::getFacadeRoot();

            return $root instanceof AuthFactory || $root instanceof Guard;
        } catch (Throwable) {
            return false;
        }
    }

    /** @param list<array{int, string, int}|string> $tokens */
    private static function expressionEnd(array $tokens, int $start): int
    {
        $depth = 0;

        for ($index = $start; isset($tokens[$index]); $index++) {
            if (in_array($tokens[$index], ['(', '['], true)) {
                $depth++;
            } elseif (in_array($tokens[$index], [')', ']'], true)) {
                $depth--;
            } elseif ($tokens[$index] === ';' && $depth === 0) {
                return $index;
            }
        }

        return count($tokens);
    }

    /** @param list<array{int, string, int}|string> $tokens */
    private static function receiverStart(array $tokens, int $end): int
    {
        $depth = 0;

        for ($index = $end; $index >= 0; $index--) {
            if (in_array($tokens[$index], [')', ']'], true)) {
                $depth++;
            } elseif (in_array($tokens[$index], ['(', '['], true)) {
                $depth--;
            }

            if ($depth === 0 && in_array($tokens[$index - 1] ?? null, ['=', ';', '{', '}', ','], true)) {
                return $index;
            }
        }

        return 0;
    }

    /** @param list<array{int, string, int}|string> $tokens */
    private static function matchingOpenParenthesis(array $tokens, int $close): ?int
    {
        $depth = 0;

        for ($index = $close; $index >= 0; $index--) {
            if ($tokens[$index] === ')') {
                $depth++;
            } elseif ($tokens[$index] === '(' && --$depth === 0) {
                return $index;
            }
        }

        return null;
    }

    /** @return list<array{int, string, int}|string> */
    private static function significantTokens(string $source): array
    {
        $tokens = array_values(array_filter(
            token_get_all($source),
            static fn (array|string $token): bool => ! is_array($token)
                || ! in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true),
        ));

        return array_map(
            static fn (array|string $token): array|string => is_array($token)
                && in_array($token[0], [T_DOUBLE_COLON, T_OBJECT_OPERATOR], true)
                    ? $token[1]
                    : $token,
            $tokens,
        );
    }

    /** @return array<string, class-string> */
    private static function imports(string $source): array
    {
        preg_match_all('/^use\s+([^;]+);/m', $source, $uses);
        $imports = [];

        foreach ($uses[1] as $import) {
            preg_match('/^(.+?)(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?$/i', trim((string) $import), $parts);
            $class = (string) ($parts[1] ?? '');
            $alias = (string) ($parts[2] ?? substr($class, strrpos($class, '\\') + 1));
            $imports[$alias] = $class;
        }

        return $imports;
    }

    private static function withoutPermittedUserWriteRoles(string $source): string
    {
        preg_match_all('/(\$[A-Za-z_][A-Za-z0-9_]*)\s*=\s*new\s+User\b/', $source, $createdUsers);
        $receivers = ['User::'];

        foreach ($createdUsers[1] as $variable) {
            $receivers[] = preg_quote((string) $variable, '/').'->';
        }

        $writePattern = '/(?:'.implode('|', $receivers).')(?:create|forceFill|fill|update)\s*\(\s*\[(.*?)\]\s*\)/s';
        $roleInputs = [];
        $withoutWriteRoles = preg_replace_callback($writePattern, static function (array $matches) use (&$roleInputs): string {
            $arguments = preg_replace_callback(
                '/([\'\"]role[\'\"]\s*=>\s*)(.*?)(?=,\s*[\'\"][A-Za-z_][A-Za-z0-9_]*[\'\"]\s*=>|$)/s',
                static function (array $role) use (&$roleInputs): string {
                    if (! str_contains((string) $role[2], 'UserRole::')) {
                        return (string) $role[0];
                    }

                    preg_match_all('/\$[A-Za-z_][A-Za-z0-9_]*/', (string) $role[2], $variables);
                    array_push($roleInputs, ...$variables[0]);

                    return '';
                },
                (string) $matches[1],
            );

            return str_replace(
                (string) $matches[1],
                is_string($arguments) ? $arguments : (string) $matches[1],
                (string) $matches[0],
            );
        }, $source);

        if (! is_string($withoutWriteRoles)) {
            return $source;
        }

        foreach (array_unique($roleInputs) as $variable) {
            $withoutWriteRoles = (string) preg_replace(
                '/'.preg_quote((string) $variable, '/').'\s*=\s*User::query\(\)\s*->where\(\s*[\'\"]role[\'\"]\s*,\s*UserRole::[A-Za-z_][A-Za-z0-9_]*->value\s*\)\s*->(?:exists|count)\(\)\s*;/',
                '',
                $withoutWriteRoles,
            );
        }

        return $withoutWriteRoles;
    }

    /**
     * @param  list<string>  $entries
     * @param  array<string, string>  $sources
     * @param  list<string>  $roots
     * @return list<string>
     */
    private static function scheduledViolations(array $entries, array $sources, array $roots): array
    {
        $violations = self::scheduleReferenceViolations($roots);

        foreach ($entries as $entry) {
            if (! isset($sources[$entry])) {
                $violations[] = 'uninspectable-schedule:'.$entry;

                continue;
            }

            array_push($violations, ...self::violations([$entry], $sources));
        }

        sort($violations);

        return array_values(array_unique($violations));
    }

    /**
     * @param  list<Event>  $events
     * @param  list<string>  $commands
     * @param  array<string, string>  $sources
     * @param  list<string>  $roots
     * @return array{list<string>, array<string, string>}
     */
    private static function scheduledEntries(array $events, array $commands, array $sources, array $roots): array
    {
        $entries = [];
        $scheduleSources = [];

        foreach ($events as $event) {
            $entry = $event instanceof CallbackEvent
                ? self::callbackEntry($event, $roots)
                : self::commandEntry($event, $commands);
            $entries[] = $entry['name'];

            if ($entry['source'] !== null) {
                $scheduleSources[$entry['name']] = $entry['source'];
            } elseif (isset($sources[$entry['name']])) {
                $scheduleSources[$entry['name']] = $sources[$entry['name']];
            }
        }

        return [array_values(array_unique($entries)), $scheduleSources];
    }

    /**
     * @param  list<string>  $roots
     * @return array{name: string, source: string|null}
     */
    private static function callbackEntry(CallbackEvent $event, array $roots): array
    {
        $callback = (new ReflectionProperty(CallbackEvent::class, 'callback'))->getValue($event);

        if ($callback instanceof Closure) {
            $reflection = new ReflectionFunction($callback);
            $file = $reflection->getFileName();
            $name = is_string($file) ? 'Closure@'.$file.':'.$reflection->getStartLine() : 'Closure';

            return [
                'name' => $name,
                'source' => is_string($file) && self::fileIsInRoots($file, $roots)
                    ? (string) file_get_contents($file)
                    : null,
            ];
        }

        if (is_string($callback)) {
            return ['name' => strstr($callback, '::', true) ?: $callback, 'source' => null];
        }

        if (is_array($callback) && isset($callback[0])) {
            return [
                'name' => is_object($callback[0]) ? $callback[0]::class : (string) $callback[0],
                'source' => null,
            ];
        }

        return ['name' => is_object($callback) ? $callback::class : 'Callback', 'source' => null];
    }

    /**
     * @param  list<string>  $commands
     * @return array{name: string, source: null}
     */
    private static function commandEntry(Event $event, array $commands): array
    {
        $commandLine = (string) $event->command;

        foreach ($commands as $class) {
            try {
                $command = app($class);
                $name = $command instanceof Command ? $command->getName() : null;
            } catch (Throwable) {
                $name = null;
            }

            if (is_string($name) && preg_match('/(?:^|\s)'.preg_quote($name, '/').'(?:\s|$)/', $commandLine) === 1) {
                return ['name' => $class, 'source' => null];
            }
        }

        return ['name' => $commandLine, 'source' => null];
    }

    /**
     * @param  list<string>  $roots
     * @return list<string>
     */
    private static function scheduleReferenceViolations(array $roots): array
    {
        $violations = [];

        foreach (self::phpFiles($roots) as $file) {
            if (realpath($file->getPathname()) === realpath(__FILE__)) {
                continue;
            }

            $source = (string) file_get_contents($file->getPathname());
            foreach (token_get_all($source) as $token) {
                if (! is_array($token) || ! in_array($token[0], [T_NAME_FULLY_QUALIFIED, T_NAME_QUALIFIED], true)) {
                    continue;
                }

                $reference = ltrim($token[1], '\\');
                if ($reference === 'Illuminate\\Console\\Scheduling'
                    || str_starts_with($reference, 'Illuminate\\Console\\Scheduling\\')) {
                    $classes = self::declaredClasses($source);
                    $violations[] = 'schedule-reference:'.($classes[0] ?? $file->getBasename());

                    break;
                }
            }
        }

        return $violations;
    }

    /**
     * @param  list<string>  $roots
     * @return list<SplFileInfo>
     */
    private static function phpFiles(array $roots): array
    {
        $files = [];

        foreach ($roots as $root) {
            $candidates = is_file($root)
                ? [new SplFileInfo($root)]
                : iterator_to_array(new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root)));

            foreach ($candidates as $file) {
                if ($file instanceof SplFileInfo && $file->isFile() && $file->getExtension() === 'php') {
                    $files[] = $file;
                }
            }
        }

        return $files;
    }

    /** @param list<string> $roots */
    private static function fileIsInRoots(string $file, array $roots): bool
    {
        $file = realpath($file);

        foreach ($roots as $root) {
            $root = realpath($root);
            if (is_string($file) && is_string($root)
                && ($file === $root || str_starts_with($file, rtrim($root, DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR))) {
                return true;
            }
        }

        return false;
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
