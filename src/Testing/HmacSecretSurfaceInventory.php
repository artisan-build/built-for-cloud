<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/** Lexically inventories direct HMAC plaintext access and egress syntax. */
final class HmacSecretSurfaceInventory
{
    /** @var list<string> */
    public const array LIMITS = [
        'lexical PHP syntax only, not whole-program data flow',
        'dynamic calls, aliases, reflection, debugger and memory capture',
        'raw model/query-builder writes, generated code and custom encodings',
        'host code, malicious bindings and consumer code after carrier reveal',
    ];

    /** @var list<string> */
    private const array ALLOWED_EGRESS = [
        'ArtisanBuild\\BuiltForCloud\\Http\\Controllers\\ManageOnboarding::deliverPendingSigningKey',
        'ArtisanBuild\\BuiltForCloud\\HttpHmacCredentialIssuerClient::claim',
        'ArtisanBuild\\BuiltForCloud\\ImportedHmacSecret::reveal',
        'ArtisanBuild\\BuiltForCloud\\MintedSecret::reveal',
    ];

    /**
     * @param  list<string>  $additionalRoots
     * @return array{plaintext_access: list<string>, allowed_egress: list<string>, reported_egress: list<string>, process_arguments: list<string>, violations: list<string>, limits: list<string>}
     */
    public static function discover(string $sourceRoot, array $additionalRoots = []): array
    {
        $access = [];
        $allowed = [];
        $reported = [];
        $arguments = [];

        foreach (self::files($sourceRoot, $additionalRoots) as $source) {
            if (preg_match('/^namespace\s+([^;]+);/m', $source, $namespace) !== 1
                || preg_match('/\b(?:final\s+|abstract\s+)?(?:readonly\s+)?class\s+([A-Z][A-Za-z0-9_]*)\b/', $source, $class) !== 1) {
                continue;
            }

            foreach (self::methods($source) as $method => $code) {
                $member = $namespace[1].'\\'.$class[1].'::'.$method;

                if (preg_match('/->(?:decrypt|reveal)\s*\(/', $code) === 1
                    && preg_match('/Hmac|hmac|signing_key|signingKey|plaintext|ImportedHmacSecret/', $source.$code) === 1) {
                    $access[] = $member;
                }

                $egress = preg_match('/return\s+\$(?:plaintext|secret|signingKey)\s*;/', $code) === 1
                    || preg_match('/(?:Log::|logger\s*\(|json_encode\s*\(|serialize\s*\(|file_put_contents\s*\()[^;]*(?:\$plaintext|\$secret|\$signingKey)/s', $code) === 1
                    || preg_match('/[\'\"]signing_key[\'\"]\s*=>\s*\$(?:plaintext|secret|signingKey|signingKeyBytes)/', $code) === 1
                    || str_contains($code, "ImportedHmacSecret::fromIssuerResponse(\$payload['signing_key'])");

                if ($egress) {
                    if (in_array($member, self::ALLOWED_EGRESS, true)) {
                        $allowed[] = $member;
                    } else {
                        $reported[] = $member;
                    }
                }

                if (preg_match('/new\s+Process\s*\([^;]*(?:\$plaintext|\$secret|\$signingKey)/s', $code) === 1) {
                    $arguments[] = $member;
                }
            }
        }

        $access = self::sortedUnique($access);
        $allowed = self::sortedUnique($allowed);
        $reported = self::sortedUnique($reported);
        $arguments = self::sortedUnique($arguments);

        return [
            'plaintext_access' => $access,
            'allowed_egress' => $allowed,
            'reported_egress' => $reported,
            'process_arguments' => $arguments,
            'violations' => self::sortedUnique([
                ...array_map(static fn (string $member): string => 'plaintext-egress:'.$member, $reported),
                ...array_map(static fn (string $member): string => 'plaintext-process-argument:'.$member, $arguments),
            ]),
            'limits' => self::LIMITS,
        ];
    }

    /**
     * @param  list<string>  $additionalRoots
     * @return array<string, string>
     */
    private static function files(string $sourceRoot, array $additionalRoots): array
    {
        $sources = [];

        foreach ([[$sourceRoot, true], ...array_map(static fn (string $root): array => [$root, false], $additionalRoots)] as [$root, $production]) {
            $files = is_file($root)
                ? [new SplFileInfo($root)]
                : iterator_to_array(new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS)));

            foreach ($files as $file) {
                if (! $file instanceof SplFileInfo || ! $file->isFile() || $file->getExtension() !== 'php') {
                    continue;
                }

                $relative = is_file($root) ? $file->getBasename() : substr($file->getPathname(), strlen($root) + 1);

                if ($production && (str_starts_with($relative, 'Testing'.DIRECTORY_SEPARATOR)
                    || str_starts_with($relative, 'Database'.DIRECTORY_SEPARATOR.'Factories'.DIRECTORY_SEPARATOR))) {
                    continue;
                }

                $sources[$file->getPathname()] = self::withoutComments((string) file_get_contents($file->getPathname()));
            }
        }

        return $sources;
    }

    /** @return array<string, string> */
    private static function methods(string $source): array
    {
        preg_match_all('/\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/', $source, $matches, PREG_OFFSET_CAPTURE);
        $methods = [];

        foreach ($matches[1] as $index => [$name]) {
            $start = $matches[0][$index][1];
            $end = $matches[0][$index + 1][1] ?? strlen($source);
            $methods[$name] = substr($source, $start, $end - $start);
        }

        return $methods;
    }

    private static function withoutComments(string $source): string
    {
        return implode('', array_map(
            static fn (array|string $token): string => is_string($token)
                ? $token
                : (in_array($token[0], [T_COMMENT, T_DOC_COMMENT], true) ? ' ' : $token[1]),
            token_get_all($source, TOKEN_PARSE),
        ));
    }

    /**
     * @param  list<string>  $items
     * @return list<string>
     */
    private static function sortedUnique(array $items): array
    {
        $items = array_values(array_unique($items));
        sort($items);

        return $items;
    }
}
