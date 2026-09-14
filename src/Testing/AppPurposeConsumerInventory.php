<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 * Lexically inventories direct literal reads of the app-purpose map.
 *
 * This intentionally does not claim data-flow analysis. Dynamic keys,
 * runtime aliases, wrappers, reflection, generated code, and host-application
 * consumers remain review concerns.
 */
final class AppPurposeConsumerInventory
{
    /** @var list<string> */
    public const array LIMITS = [
        'dynamic or concatenated config keys',
        'runtime aliases, wrappers, and reflection',
        'generated non-PHP code and host-application consumers',
        'only class declarations under src; traits, enums, interfaces, and class-less files are not scanned',
        'data flow beyond one lexical method body',
    ];

    /**
     * @param  list<string>  $additionalRoots
     * @return array{
     *   consumers: list<array{member: string, reads: int, scalar_entry: bool, enum_parse: bool}>,
     *   violations: list<string>,
     *   limits: list<string>
     * }
     */
    public static function discover(string $sourceRoot, array $additionalRoots = []): array
    {
        $consumers = [];

        foreach (self::phpFiles($sourceRoot, true) as $file) {
            array_push($consumers, ...self::consumersIn($file));
        }

        foreach ($additionalRoots as $root) {
            foreach (self::phpFiles($root, false) as $file) {
                array_push($consumers, ...self::consumersIn($file));
            }
        }

        usort($consumers, static fn (array $left, array $right): int => $left['member'] <=> $right['member']);

        $violations = [];

        foreach ($consumers as $consumer) {
            if (! $consumer['scalar_entry']) {
                $violations[] = 'non-scalar-entry:'.$consumer['member'];
            }

            if (! $consumer['enum_parse']) {
                $violations[] = 'missing-credential-purpose-parse:'.$consumer['member'];
            }
        }

        return [
            'consumers' => $consumers,
            'violations' => $violations,
            'limits' => self::LIMITS,
        ];
    }

    /**
     * @return list<array{member: string, reads: int, scalar_entry: bool, enum_parse: bool}>
     */
    private static function consumersIn(string $file): array
    {
        $code = file_get_contents($file);

        if (! is_string($code)
            || preg_match('/^namespace\s+([^;]+);/m', $code, $namespace) !== 1
            || preg_match('/\b(?:final\s+|abstract\s+)?(?:readonly\s+)?class\s+([A-Z][A-Za-z0-9_]*)\b/', $code, $class) !== 1) {
            return [];
        }

        preg_match_all(
            '/\bfunction\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)[^{;]*\{/s',
            $code,
            $methods,
            PREG_SET_ORDER | PREG_OFFSET_CAPTURE,
        );

        $consumers = [];

        foreach ($methods as $index => $method) {
            $offset = $method[0][1];
            $end = $methods[$index + 1][0][1] ?? strlen($code);
            $body = substr($code, $offset, $end - $offset);
            $readPattern = '/(?:\bconfig\s*\(|(?:->|::)\s*(?:get|string|integer|float|boolean|array)\s*\()\s*([\'\"])built-for-cloud\.credentials\.app_purposes\1/';
            $reads = preg_match_all($readPattern, $body);

            if ($reads === false || $reads === 0) {
                continue;
            }

            $scalarEntry = false;
            $enumParse = preg_match('/\bCredentialPurpose::(?:tryFrom|from)\s*\(/', $body) === 1;

            if (preg_match('/\$([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*\[[^]]+\]\s*;/', $body, $extraction) === 1) {
                $value = preg_quote($extraction[1], '/');
                $scalarEntry = preg_match('/\bis_string\s*\(\s*\$'.$value.'\s*\)/', $body) === 1;
            }

            $consumers[] = [
                'member' => $namespace[1].'\\'.$class[1].'::'.$method[1][0],
                'reads' => $reads,
                'scalar_entry' => $scalarEntry,
                'enum_parse' => $enumParse,
            ];
        }

        return $consumers;
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
