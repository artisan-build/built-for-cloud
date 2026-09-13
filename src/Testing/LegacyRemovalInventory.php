<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use RuntimeException;
use SplFileInfo;

/**
 * P5-AC2's installed-tree absence scanner. Callers supply the package root so
 * the same instrument can run in a development checkout or a lockless archive
 * install. Results name the offending file, line and rule; comments and
 * docblocks are excluded from executable-code rules.
 *
 * This is a lexical PHP/document scan, not whole-program analysis. It sees
 * literal declarations, references, keys and route registrations in shipped
 * files; dynamically assembled identifiers and host-registered surfaces are
 * outside its bound.
 */
final class LegacyRemovalInventory
{
    /** @return list<string> */
    public static function productionOffences(string $packageRoot): array
    {
        $root = self::packageRoot($packageRoot);
        $offences = [];

        foreach (['src', 'database/migrations', 'config'] as $directory) {
            foreach (self::phpFiles($root.'/'.$directory) as $file) {
                $path = $directory.'/'.substr($file->getPathname(), strlen($root.'/'.$directory) + 1);
                $contents = self::contents($file->getPathname());

                array_push($offences, ...self::phpOffences($path, $contents));
            }
        }

        sort($offences);

        return array_values(array_unique($offences));
    }

    /** @return list<string> */
    public static function publicDocumentOffences(string $packageRoot): array
    {
        $root = self::packageRoot($packageRoot);
        $offences = [];

        foreach (['README.md', 'docs/http-contract.md'] as $path) {
            $contents = self::contents($root.'/'.$path);

            foreach (self::documentMarkers() as $rule => $marker) {
                foreach (self::matchingLines($contents, static fn (string $line): bool => str_contains($line, $marker)) as $line) {
                    $offences[] = "{$path}:{$line} [{$rule}]";
                }
            }
        }

        sort($offences);

        return array_values(array_unique($offences));
    }

    /**
     * @return array<string, list<string>> file => marker@line
     */
    public static function testFilesWithRemovalMarkers(string $packageRoot): array
    {
        $root = self::packageRoot($packageRoot);
        $files = [];

        foreach (self::phpFiles($root.'/tests') as $file) {
            $relative = 'tests/'.substr($file->getPathname(), strlen($root.'/tests') + 1);
            $contents = self::contents($file->getPathname());
            $hits = [];

            foreach (self::testMarkers() as $rule => $marker) {
                foreach (self::matchingLines($contents, static fn (string $line): bool => str_contains($line, $marker)) as $line) {
                    $hits[] = "{$rule}@{$line}";
                }
            }

            if ($hits !== []) {
                sort($hits);
                $files[$relative] = array_values(array_unique($hits));
            }
        }

        ksort($files);

        return $files;
    }

    /** @return list<string> */
    private static function phpOffences(string $path, string $contents): array
    {
        $offences = [];
        $code = self::withoutComments($contents);
        $forbiddenSymbols = [
            self::joined('Api', 'Token'),
            self::joined('Api', 'Token', 'Minter'),
            self::joined('Token', 'Registry'),
            self::joined('Durable', 'Store'),
            self::joined('Declares', 'Durable', 'Store'),
            self::joined('Ensure', 'Admin', 'Token'),
            self::joined('Manage', 'Tokens'),
            self::joined('Legacy', 'Rotation', 'Result'),
        ];

        $tokens = token_get_all($contents, TOKEN_PARSE);

        foreach ($tokens as $index => $token) {
            if (! is_array($token) || in_array($token[0], [T_COMMENT, T_DOC_COMMENT], true)) {
                continue;
            }

            if ($token[0] === T_CONSTANT_ENCAPSED_STRING) {
                array_push($offences, ...self::stringSymbolOffences($path, $token[1], $token[2], $forbiddenSymbols));

                continue;
            }

            $parts = preg_split('/\\\\/', $token[1]) ?: [];

            foreach ($parts as $part) {
                if (! in_array($part, $forbiddenSymbols, true)) {
                    continue;
                }

                if ($part === self::joined('Api', 'Token')
                    && self::isAllowedAuditCase($path, $contents, $tokens, $index, $token[2])) {
                    continue;
                }

                $offences[] = "{$path}:{$token[2]} [symbol:{$part}]";
            }
        }

        $adminToken = self::joined('Admin', 'Token');
        $legacyApiToken = self::joined('Legacy', 'Api', 'Token');
        $ownerTokenId = implode('_', ['owner', 'token', 'id']);
        $durableTokenId = implode('_', ['durable', 'token', 'id']);
        $durableStore = implode('_', ['durable', 'store']);
        $fallbackToken = implode('_', ['fallback', 'token']);
        $fallbackEnv = implode('_', ['FALLBACK', 'TOKEN']);
        $credentialApi = implode('_', ['credential', 'api']);
        $auditActorType = self::enumReferences($code, implode('\\', ['ArtisanBuild', 'BuiltForCloud', 'AuditActorType']));
        $appActorType = self::enumReferences($code, implode('\\', ['ArtisanBuild', 'BuiltForCloud', 'Audit', 'AppActorType']));
        $lineRules = [
            'enum:AuditActorType::'.$adminToken => '/(?:'.$auditActorType.')::'.$adminToken.'\b|\bcase\s+'.$adminToken.'\b|::(?:from|tryFrom)\s*\(\s*[\'\"]'.implode('_', ['admin', 'token']).'[\'\"]\s*\)/',
            'enum:Audit\\AppActorType::'.$legacyApiToken => '/(?:'.$appActorType.')::'.$legacyApiToken.'\b|\bcase\s+'.$legacyApiToken.'\b|::(?:from|tryFrom)\s*\(\s*[\'\"]'.implode('_', ['legacy', 'api', 'token']).'[\'\"]\s*\)/',
            'identifier:'.$ownerTokenId => '/\b'.$ownerTokenId.'\b/',
            'identifier:'.$durableTokenId => '/\b'.$durableTokenId.'\b/',
            'identifier:'.$durableStore => '/\b'.$durableStore.'\b/',
            'config:built-for-cloud.'.$fallbackToken => '/built-for-cloud\\.'.$fallbackToken.'|[\'\"]'.$fallbackToken.'[\'\"]\s*=>/',
            'env:'.$fallbackEnv => '/\b'.$fallbackEnv.'\b/',
            'config:built-for-cloud.'.$credentialApi => '/built-for-cloud\\.'.$credentialApi.'|[\'\"]'.$credentialApi.'[\'\"]\s*=>/',
            'middleware:'.implode('.', ['bfc', 'token', 'admin']) => '/'.implode('\\.', ['bfc', 'token', 'admin']).'/',
            'method:'.implode('', ['is', 'Fallback']) => '/\bfunction\s+'.implode('', ['is', 'Fallback']).'\s*\(/',
            'schema:'.implode('_', ['api', 'tokens']) => '/\b'.implode('_', ['api', 'tokens']).'\b/',
        ];

        foreach ($lineRules as $rule => $pattern) {
            foreach (self::matchingLines($code, static fn (string $line): bool => preg_match($pattern, $line) === 1) as $line) {
                $offences[] = "{$path}:{$line} [{$rule}]";
            }
        }

        foreach (self::legacyFileNames() as $fileName) {
            if (str_ends_with($path, '/'.$fileName) || $path === 'src/'.$fileName) {
                $offences[] = "{$path}:1 [legacy-file]";
            }
        }

        return $offences;
    }

    /**
     * @param  list<string>  $forbiddenSymbols
     * @return list<string>
     */
    private static function stringSymbolOffences(string $path, string $literal, int $line, array $forbiddenSymbols): array
    {
        if (! str_contains($literal, '\\')) {
            return [];
        }

        $offences = [];

        foreach ($forbiddenSymbols as $symbol) {
            if (preg_match('/(?:^|\\\\+)'.preg_quote($symbol, '/').'(?:$|[^A-Za-z0-9_\\\\])/', trim($literal, "'\"")) === 1) {
                $offences[] = "{$path}:{$line} [symbol:{$symbol}]";
            }
        }

        return $offences;
    }

    private static function enumReferences(string $code, string $class): string
    {
        $short = substr($class, strrpos($class, '\\') + 1);
        $references = [$short, $class, '\\'.$class];

        preg_match_all('/^use\s+([^;\s]+)(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?\s*;/mi', $code, $imports, PREG_SET_ORDER);

        foreach ($imports as $import) {
            if (ltrim($import[1], '\\') === $class) {
                $references[] = $import[2] ?? $short;
            }
        }

        return implode('|', array_map(static fn (string $reference): string => preg_quote($reference, '/'), array_unique($references)));
    }

    /** @param list<array{int, string, int}|string> $tokens */
    private static function isAllowedAuditCase(string $path, string $contents, array $tokens, int $index, int $line): bool
    {
        $lines = preg_split('/\R/', $contents) ?: [];
        $source = trim($lines[$line - 1] ?? '');

        if ($path === 'src/Audit/AppActorType.php'
            && $source === 'case '.self::joined('Api', 'Token')." = '".implode('_', ['api', 'token'])."';") {
            return true;
        }

        $separatorIndex = self::previousCodeTokenIndex($tokens, $index - 1);
        $classIndex = $separatorIndex === null ? null : self::previousCodeTokenIndex($tokens, $separatorIndex - 1);
        $classToken = $classIndex === null ? null : $tokens[$classIndex];

        if ($separatorIndex === null || ($tokens[$separatorIndex][0] ?? null) !== T_DOUBLE_COLON || ! is_array($classToken)) {
            return false;
        }

        $class = ltrim($classToken[1], '\\');
        $allowed = implode('\\', ['ArtisanBuild', 'BuiltForCloud', 'Audit', 'AppActorType']);

        if ($class === $allowed) {
            return true;
        }

        preg_match('/^namespace\s+([^;]+);/m', self::withoutComments($contents), $namespace);

        return $class === 'AppActorType'
            && ($namespace[1] ?? null) === implode('\\', ['ArtisanBuild', 'BuiltForCloud', 'Audit']);
    }

    /**
     * @param  list<array{int, string, int}|string>  $tokens
     */
    private static function previousCodeTokenIndex(array $tokens, int $index): ?int
    {
        for (; $index >= 0; $index--) {
            $token = $tokens[$index];

            if (is_string($token) || ! in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                return $index;
            }
        }

        return null;
    }

    /** @return array<string, string> */
    private static function documentMarkers(): array
    {
        return [
            'legacy-store' => implode('_', ['api', 'tokens']),
            'fallback-env' => implode('_', ['FALLBACK', 'TOKEN']),
            'fallback-config' => implode('_', ['fallback', 'token']),
            'credential-api-config' => implode('_', ['credential', 'api']),
            'credential-api-route' => '/api/'.implode('', ['credentials']),
            'legacy-admin-actor' => implode('_', ['admin', 'token']),
            'legacy-app-actor' => implode('_', ['legacy', 'api', 'token']),
            'legacy-registry' => self::joined('Token', 'Registry'),
            ...self::commandMarkers(),
        ];
    }

    /** @return array<string, string> */
    private static function testMarkers(): array
    {
        $legacyTable = implode('_', ['api', 'tokens']);

        return [
            self::joined('Api', 'Token') => self::joined('Api', 'Token'),
            self::joined('Api', 'Token', 'Minter') => self::joined('Api', 'Token', 'Minter'),
            self::joined('Token', 'Registry') => self::joined('Token', 'Registry'),
            self::joined('Durable', 'Store') => self::joined('Durable', 'Store'),
            self::joined('Declares', 'Durable', 'Store') => self::joined('Declares', 'Durable', 'Store'),
            self::joined('Ensure', 'Admin', 'Token') => self::joined('Ensure', 'Admin', 'Token'),
            self::joined('Manage', 'Tokens') => self::joined('Manage', 'Tokens'),
            self::joined('Admin', 'Token') => self::joined('Admin', 'Token'),
            self::joined('Legacy', 'Api', 'Token') => self::joined('Legacy', 'Api', 'Token'),
            implode('_', ['owner', 'token', 'id']) => implode('_', ['owner', 'token', 'id']),
            implode('_', ['durable', 'token', 'id']) => implode('_', ['durable', 'token', 'id']),
            implode('_', ['durable', 'store']) => implode('_', ['durable', 'store']),
            implode('_', ['fallback', 'token']) => implode('_', ['fallback', 'token']),
            implode('_', ['FALLBACK', 'TOKEN']) => implode('_', ['FALLBACK', 'TOKEN']),
            implode('_', ['credential', 'api']) => implode('_', ['credential', 'api']),
            $legacyTable => $legacyTable,
            ...self::commandMarkers(),
        ];
    }

    /** @return array<string, string> */
    private static function commandMarkers(): array
    {
        return [
            'command-token-create' => implode(':', ['token', 'create']),
            'command-token-list' => implode(':', ['token', 'list']),
            'command-token-revoke' => implode(':', ['token', 'revoke']),
            'command-token-rotate' => implode(':', ['token', 'rotate']),
            'command-token-usage' => implode(':', ['token', 'usage']),
            'command-token-revoke-self' => implode(':', ['bfc', 'token', 'revoke-self']),
            'command-fallback-generate' => implode(':', ['fallback-token', 'generate']),
        ];
    }

    /** @return list<string> */
    private static function legacyFileNames(): array
    {
        return [
            self::joined('Api', 'Token').'.php',
            self::joined('Api', 'Token', 'Minter').'.php',
            self::joined('Token', 'Registry').'.php',
            self::joined('Legacy', 'Rotation', 'Result').'.php',
            self::joined('Durable', 'Store').'.php',
            self::joined('Declares', 'Durable', 'Store').'.php',
            self::joined('Ensure', 'Admin', 'Token').'.php',
            self::joined('Manage', 'Tokens').'.php',
            self::joined('Fallback', 'Token', 'Generate', 'Command').'.php',
            self::joined('Token', 'Create', 'Command').'.php',
            self::joined('Token', 'List', 'Command').'.php',
            self::joined('Token', 'Revoke', 'Command').'.php',
            self::joined('Token', 'Revoke', 'Self', 'Command').'.php',
            self::joined('Token', 'Rotate', 'Command').'.php',
            self::joined('Token', 'Usage', 'Command').'.php',
            self::joined('Api', 'Token', 'Factory').'.php',
            '0001_01_01_000000_create_'.implode('_', ['api', 'tokens']).'_table.php',
            '2026_07_08_000001_add_abilities_to_'.implode('_', ['api', 'tokens']).'_table.php',
            '2026_08_24_000001_add_client_identity_to_'.implode('_', ['api', 'tokens']).'_table.php',
            '2026_08_28_100002_add_rotated_at_to_'.implode('_', ['api', 'tokens']).'_table.php',
            '2026_08_28_300001_add_subject_to_'.implode('_', ['api', 'tokens']).'_table.php',
            '2026_08_28_400001_add_'.implode('_', ['durable', 'store']).'_to_onboarding_tokens_table.php',
        ];
    }

    private static function joined(string ...$parts): string
    {
        return implode('', $parts);
    }

    /** @return list<int> */
    private static function matchingLines(string $contents, callable $matches): array
    {
        $result = [];

        foreach (preg_split('/\R/', $contents) ?: [] as $index => $line) {
            if ($matches($line)) {
                $result[] = $index + 1;
            }
        }

        return $result;
    }

    private static function withoutComments(string $contents): string
    {
        return implode('', array_map(
            static fn (array|string $token): string => is_string($token)
                ? $token
                : (in_array($token[0], [T_COMMENT, T_DOC_COMMENT], true)
                    ? str_repeat("\n", substr_count($token[1], "\n"))
                    : $token[1]),
            token_get_all($contents, TOKEN_PARSE),
        ));
    }

    private static function packageRoot(string $root): string
    {
        $root = rtrim($root, DIRECTORY_SEPARATOR);

        foreach (['composer.json', 'src/BuiltForCloudServiceProvider.php'] as $anchor) {
            if (! is_file($root.'/'.$anchor)) {
                throw new RuntimeException("Package root [{$root}] is missing [{$anchor}].");
            }
        }

        return $root;
    }

    private static function contents(string $path): string
    {
        $contents = file_get_contents($path);

        return is_string($contents) ? $contents : throw new RuntimeException("Could not read [{$path}].");
    }

    /** @return iterable<SplFileInfo> */
    private static function phpFiles(string $root): iterable
    {
        $files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
        );

        /** @var SplFileInfo $file */
        foreach ($files as $file) {
            if ($file->isFile() && $file->getExtension() === 'php') {
                yield $file;
            }
        }
    }
}
