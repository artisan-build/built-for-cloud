<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use RuntimeException;
use SplFileInfo;

/**
 * Lexically inventories package-owned credential row creation syntax.
 *
 * The scanner derives literal `Credential::query()->create([...])` calls and
 * `new Credential; ... forceFill([...])->save()` pairs. It cannot see dynamic
 * class names, aliases assembled at runtime, host-application writes, raw SQL,
 * query-builder writes, generated non-PHP code, or writes hidden behind an
 * unrecognized helper. Those remain review concerns.
 */
final class CredentialWriterInventory
{
    /** @var list<string> */
    public const array EXCLUDED_PRODUCTION_CLASSES = [
        'ArtisanBuild\BuiltForCloud\Hmac\SigningRootLifecycle',
    ];

    /** @var list<string> */
    public const array LIMITS = [
        'dynamic class names and runtime aliases',
        'host-application and raw SQL/query-builder writes',
        'generated non-PHP code and unrecognized helper indirection',
    ];

    /**
     * @param  list<string>  $additionalRoots
     * @return array{
     *   writers: list<array{member: string, has_purpose: bool}>,
     *   violations: list<string>,
     *   excluded_classes: list<string>,
     *   limits: list<string>
     * }
     */
    public static function discover(string $sourceRoot, array $additionalRoots = []): array
    {
        $writers = [];

        foreach (self::phpFiles($sourceRoot, true) as $file) {
            array_push($writers, ...self::writersIn($file));
        }

        foreach ($additionalRoots as $root) {
            foreach (self::phpFiles($root, false) as $file) {
                array_push($writers, ...self::writersIn($file));
            }
        }

        usort($writers, static fn (array $left, array $right): int => $left['member'] <=> $right['member']);

        return [
            'writers' => $writers,
            'violations' => array_values(array_map(
                static fn (array $writer): string => 'missing-purpose:'.$writer['member'],
                array_filter($writers, static fn (array $writer): bool => ! $writer['has_purpose']),
            )),
            'excluded_classes' => self::EXCLUDED_PRODUCTION_CLASSES,
            'limits' => self::LIMITS,
        ];
    }

    /**
     * @return list<array{member: string, has_purpose: bool}>
     */
    private static function writersIn(string $file): array
    {
        $code = file_get_contents($file);

        if (! is_string($code)
            || preg_match('/^namespace\s+([^;]+);/m', $code, $namespace) !== 1
            || preg_match('/\b(?:final\s+|abstract\s+)?(?:readonly\s+)?class\s+([A-Z][A-Za-z0-9_]*)\b/', $code, $class) !== 1) {
            return [];
        }

        $className = $namespace[1].'\\'.$class[1];

        if (in_array($className, self::EXCLUDED_PRODUCTION_CLASSES, true)) {
            return [];
        }

        $matches = [];
        preg_match_all(
            '/Credential::query\(\)->create\(\s*\[(.*?)\]\s*\)/s',
            $code,
            $creates,
            PREG_SET_ORDER | PREG_OFFSET_CAPTURE,
        );
        preg_match_all(
            '/\$([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*new\s+Credential\s*;\s*\$\1->forceFill\(\s*\[(.*?)\]\s*\)->save\(\)/s',
            $code,
            $forceFills,
            PREG_SET_ORDER | PREG_OFFSET_CAPTURE,
        );

        foreach ($creates as $match) {
            $matches[] = ['body' => $match[1][0], 'offset' => $match[0][1]];
        }

        foreach ($forceFills as $match) {
            $matches[] = ['body' => $match[2][0], 'offset' => $match[0][1]];
        }

        $writers = [];

        foreach ($matches as $match) {
            $method = self::methodAt($code, $match['offset']);
            $writers[] = [
                'member' => $className.'::'.$method,
                'has_purpose' => preg_match('/[\'\"]purpose[\'\"]\s*=>/', $match['body']) === 1,
            ];
        }

        return $writers;
    }

    private static function methodAt(string $code, int $offset): string
    {
        preg_match_all(
            '/\bfunction\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/',
            substr($code, 0, $offset),
            $methods,
        );

        $method = end($methods[1]);

        return is_string($method) ? $method : throw new RuntimeException('Could not derive credential writer method.');
    }

    /** @return iterable<string> */
    private static function phpFiles(string $root, bool $productionRoot): iterable
    {
        if (is_file($root)) {
            yield $root;

            return;
        }

        $files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
        );

        /** @var SplFileInfo $file */
        foreach ($files as $file) {
            if (! $file->isFile() || $file->getExtension() !== 'php') {
                continue;
            }

            $relative = substr($file->getPathname(), strlen($root) + 1);

            if ($productionRoot && str_starts_with($relative, 'Testing'.DIRECTORY_SEPARATOR)) {
                continue;
            }

            yield $file->getPathname();
        }
    }
}
