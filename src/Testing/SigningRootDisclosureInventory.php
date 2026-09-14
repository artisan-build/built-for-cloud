<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 * Derives the supported signing-root delivery, summary, list, audit, command,
 * and return surfaces from package-owned PHP source.
 *
 * This lexical instrument recognizes this package's direct constructors,
 * method calls, enum cases, and array keys. Dynamic aliases, reflection,
 * runtime rebinding, generated or host code, indirect serialization, and
 * custom encodings remain outside its claim. Arbitrary in-process code with
 * model ciphertext access and HmacKeyring::decrypt() is explicitly outside
 * the supported-surface secrecy boundary.
 */
final class SigningRootDisclosureInventory
{
    /** @var list<string> */
    public const array LIMITS = [
        'dynamic aliases, reflection, runtime rebinding, and indirect serialization',
        'generated code, host code, and custom encodings',
        'hostile in-process code with ciphertext and HmacKeyring access',
    ];

    /**
     * @param  list<string>  $additionalRoots
     * @return array{
     *   delivery_shapes: list<string>,
     *   root_returns: list<string>,
     *   summary_fields: list<string>,
     *   list_exclusions: list<string>,
     *   audit_writes: list<string>,
     *   command_surfaces: list<string>,
     *   http_surfaces: list<string>,
     *   surface_leaks: list<string>,
     *   violations: list<string>,
     *   limits: list<string>
     * }
     */
    public static function discover(string $sourceRoot, array $additionalRoots = []): array
    {
        $files = self::files($sourceRoot, $additionalRoots);
        $deliveryShapes = self::enumCases($files[$sourceRoot.DIRECTORY_SEPARATOR.'DeliveryShape.php'] ?? '');
        $summaryFields = self::arrayKeysInMethod(
            $files[$sourceRoot.DIRECTORY_SEPARATOR.'CredentialSummary.php'] ?? '',
            'toArray',
        );
        $rootReturns = [];
        $listExclusions = [];
        $auditWrites = [];
        $commandSurfaces = [];
        $httpSurfaces = [];
        $surfaceLeaks = [];
        $violations = [];

        foreach ($files as $path => $source) {
            if (preg_match('/^namespace\s+([^;]+);/m', $source, $namespace) !== 1
                || preg_match('/\b(?:final\s+|abstract\s+)?(?:readonly\s+)?class\s+([A-Z][A-Za-z0-9_]*)\b/', $source, $class) !== 1) {
                continue;
            }

            $className = $namespace[1].'\\'.$class[1];

            foreach (self::methods($source) as $method => $code) {
                $member = $className.'::'.$method;

                if (str_contains($code, 'SigningRootMac::excludeReservedFrom(')) {
                    $listExclusions[] = $member;
                }

                if ($className === 'ArtisanBuild\\BuiltForCloud\\Hmac\\SigningRootLifecycle'
                    && in_array($method, ['provision', 'rotate'], true)) {
                    $safe = str_contains($code, 'DeliveryShape::None')
                        && ! str_contains($code, 'new MintedSecret')
                        && ! str_contains($code, 'deliveryFingerprint:')
                        && ! str_contains($code, 'secret:');
                    $rootReturns[] = $member.'|delivery='.($safe ? 'none' : 'exporting');

                    if (! $safe) {
                        $violations[] = 'root-return-export:'.$member;
                    }

                    $recordCount = preg_match_all('/->record\s*\(/', $code);
                    $auditWrites[] = $member.'|writes='.$recordCount.'|note='.(str_contains($code, 'note:') ? 'present' : 'absent');

                    if (str_contains($code, 'note:')) {
                        $violations[] = 'root-audit-note:'.$member;
                    }
                }

                if (self::rootRelated($className, $code) && self::returnsForbiddenMaterial($member, $code)) {
                    $surfaceLeaks[] = $member;
                    $violations[] = 'root-surface-leak:'.$member;
                }
            }

            if (preg_match('/protected\s+\$signature\s*=\s*[\'"]([^\s\'"]+)/', $source, $signature) === 1
                && str_contains($signature[1], 'signing-root')) {
                $commandSurfaces[] = $className.'='.$signature[1];
            }

            if (str_contains($path, DIRECTORY_SEPARATOR.'Http'.DIRECTORY_SEPARATOR)
                && (str_contains($source, 'SigningRootLifecycle') || str_contains($source, 'bfc:signing-root'))) {
                $httpSurfaces[] = $className;
            }
        }

        foreach (['secret', 'secret_ciphertext', 'delivery_fingerprint', 'lowercase_hex_mac'] as $forbidden) {
            if (in_array($forbidden, $summaryFields, true)) {
                $violations[] = 'root-summary-field:'.$forbidden;
            }
        }

        $expectedReturns = [
            'ArtisanBuild\\BuiltForCloud\\Hmac\\SigningRootLifecycle::provision|delivery=none',
            'ArtisanBuild\\BuiltForCloud\\Hmac\\SigningRootLifecycle::rotate|delivery=none',
        ];
        $expectedLists = [
            'ArtisanBuild\\BuiltForCloud\\Actions\\ListCredentials::__invoke',
            'ArtisanBuild\\BuiltForCloud\\CredentialManagementScope::apply',
        ];

        foreach (array_diff($expectedReturns, $rootReturns) as $missing) {
            $violations[] = 'missing-root-return:'.$missing;
        }

        foreach (array_diff($expectedLists, $listExclusions) as $missing) {
            $violations[] = 'missing-root-list-exclusion:'.$missing;
        }

        if ($commandSurfaces !== ['ArtisanBuild\\BuiltForCloud\\Commands\\SigningRootProvisionCommand=bfc:signing-root:provision']) {
            $violations[] = 'root-command-surface-set';
        }

        if ($httpSurfaces !== []) {
            $violations[] = 'root-http-surface-set';
        }

        return [
            'delivery_shapes' => self::sortedUnique($deliveryShapes),
            'root_returns' => self::sortedUnique($rootReturns),
            'summary_fields' => $summaryFields,
            'list_exclusions' => self::sortedUnique($listExclusions),
            'audit_writes' => self::sortedUnique($auditWrites),
            'command_surfaces' => self::sortedUnique($commandSurfaces),
            'http_surfaces' => self::sortedUnique($httpSurfaces),
            'surface_leaks' => self::sortedUnique($surfaceLeaks),
            'violations' => self::sortedUnique($violations),
            'limits' => self::LIMITS,
        ];
    }

    private static function rootRelated(string $class, string $code): bool
    {
        return $class === 'ArtisanBuild\\BuiltForCloud\\Hmac\\SigningRootMac'
            || $class === 'ArtisanBuild\\BuiltForCloud\\Hmac\\SigningRootLifecycle'
            || str_contains($code, 'CredentialPurpose::SigningRoot')
            || str_contains($code, 'SigningRootMac::SUBJECT_REF');
    }

    private static function returnsForbiddenMaterial(string $member, string $code): bool
    {
        if ($member === 'ArtisanBuild\\BuiltForCloud\\Hmac\\SigningRootMac::mac'
            || $member === 'ArtisanBuild\\BuiltForCloud\\Hmac\\SigningRootMac::verify') {
            return false;
        }

        return preg_match('/return\s+\$(?:plaintext|secret|signingKey)\s*;/', $code) === 1
            || preg_match('/return\s+[^;]*->decrypt\s*\(/s', $code) === 1
            || str_contains($code, 'new MintedSecret(')
            || preg_match('/DeliveryShape::(?!None\b)[A-Za-z_][A-Za-z0-9_]*/', $code) === 1
            || str_contains($code, 'deliveryFingerprint:')
            || str_contains($code, 'secret:');
    }

    /** @return list<string> */
    private static function enumCases(string $source): array
    {
        preg_match_all('/\bcase\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*[\'"]([^\'"]+)[\'"]/', $source, $matches);

        return $matches[1];
    }

    /** @return list<string> */
    private static function arrayKeysInMethod(string $source, string $method): array
    {
        $code = self::methods($source)[$method] ?? '';
        preg_match_all('/[\'"]([a-z_]+)[\'"]\s*=>/', $code, $matches);

        return array_values(array_unique($matches[1]));
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

        ksort($sources);

        return $sources;
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
