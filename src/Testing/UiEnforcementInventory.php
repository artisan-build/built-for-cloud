<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 * Lexically inventories direct human, authority-mode, and route-ownership
 * enforcement members. Behavioral tests own the refusal semantics.
 *
 * This is deliberately a source inventory, not whole-program data-flow
 * analysis. Dynamic class names, wrappers, runtime rebinding, generated code,
 * and host application code remain review concerns.
 */
final class UiEnforcementInventory
{
    /**
     * @param  list<string>  $additionalRoots
     * @return list<array{member: string, path: string, line: int, kind: string}>
     */
    public static function discover(string $sourceRoot, array $additionalRoots = []): array
    {
        $members = [];

        foreach ([$sourceRoot, ...$additionalRoots] as $root) {
            foreach (self::phpFiles($root) as $file) {
                $source = file_get_contents($file->getPathname());

                if (! is_string($source)) {
                    continue;
                }

                $code = self::withoutComments($source);
                $class = self::className($code);

                if ($class === null) {
                    continue;
                }

                foreach (self::publicMethods($source) as $method) {
                    $kind = self::kind($code, $method['name'], $method['static']);

                    if ($kind === null) {
                        continue;
                    }

                    $members[] = [
                        'member' => $class.'::'.$method['name'],
                        'path' => self::displayPath($file->getPathname(), $sourceRoot),
                        'line' => $method['line'],
                        'kind' => $kind,
                    ];
                }
            }
        }

        usort($members, static fn (array $left, array $right): int => $left['member'] <=> $right['member']);

        return $members;
    }

    private static function kind(string $code, string $method, bool $static): ?string
    {
        if ($method === 'handle'
            && ((str_contains($code, 'ActingPrincipalResolver')
                    && (str_contains($code, 'RolePolicy') || str_contains($code, 'ManagedAccountAccess')))
                || str_contains($code, 'InstallationAuthority::current')
                || (str_contains($code, 'built-for-cloud.ui.') && str_contains($code, 'abort(')))) {
            return 'human-or-mode-gate';
        }

        if ($method === 'allows'
            && preg_match('/public\s+function\s+allows\s*\(\s*User\b/', $code) === 1
            && (str_contains($code, 'ManagedFreshness') || str_contains($code, 'allowsBoundSubject'))) {
            return 'managed-human-gate';
        }

        if ($static
            && str_starts_with($method, 'assert')
            && ! str_contains($method, 'Operator')
            && str_contains($code, 'Router')
            && str_contains($code, 'RuntimeException')) {
            return 'route-ownership-assertion';
        }

        return null;
    }

    /**
     * @return list<array{name: string, static: bool, line: int}>
     */
    private static function publicMethods(string $source): array
    {
        preg_match_all(
            '/\bpublic\s+(?:(static)\s+)?function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/',
            $source,
            $matches,
            PREG_SET_ORDER | PREG_OFFSET_CAPTURE,
        );

        return array_map(static function (array $match) use ($source): array {
            $offset = $match[0][1];

            return [
                'name' => $match[2][0],
                'static' => $match[1][1] >= 0 && $match[1][0] !== '',
                'line' => substr_count(substr($source, 0, $offset), "\n") + 1,
            ];
        }, $matches);
    }

    private static function className(string $code): ?string
    {
        if (preg_match('/\bnamespace\s+([^;]+);/', $code, $namespace) !== 1
            || preg_match('/\b(?:final\s+|abstract\s+)?(?:readonly\s+)?class\s+([A-Z][A-Za-z0-9_]*)\b/', $code, $class) !== 1) {
            return null;
        }

        return trim($namespace[1]).'\\'.$class[1];
    }

    private static function withoutComments(string $source): string
    {
        $code = '';

        foreach (token_get_all($source) as $token) {
            if (is_array($token) && in_array($token[0], [T_COMMENT, T_DOC_COMMENT], true)) {
                continue;
            }

            $code .= is_array($token) ? $token[1] : $token;
        }

        return $code;
    }

    private static function displayPath(string $path, string $sourceRoot): string
    {
        if (str_starts_with($path, $sourceRoot.DIRECTORY_SEPARATOR)) {
            return 'src/'.str_replace(DIRECTORY_SEPARATOR, '/', substr($path, strlen($sourceRoot) + 1));
        }

        return str_replace(DIRECTORY_SEPARATOR, '/', $path);
    }

    /** @return iterable<SplFileInfo> */
    private static function phpFiles(string $root): iterable
    {
        if (is_file($root)) {
            yield new SplFileInfo($root);

            return;
        }

        $files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
        );

        /** @var SplFileInfo $file */
        foreach ($files as $file) {
            $relative = substr($file->getPathname(), strlen($root) + 1);

            if ($file->isFile() && $file->getExtension() === 'php'
                && ! str_starts_with($relative, 'Testing'.DIRECTORY_SEPARATOR)) {
                yield $file;
            }
        }
    }
}
