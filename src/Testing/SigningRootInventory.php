<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use RuntimeException;
use SplFileInfo;

/**
 * Derives the signing-root producer, selectors, decrypt dispositions, and
 * public rotation delegation from package-owned PHP source.
 *
 * This is a lexical inventory, not whole-program data-flow analysis. It sees
 * direct HmacKeyring dependencies, method calls, credential writes, and the
 * literal root identity predicates used by this package. Dynamic aliases,
 * runtime rebinding, reflection, generated code, host code, raw SQL writes,
 * and unrecognized helper indirection remain outside its claim.
 */
final class SigningRootInventory
{
    /** @var list<string> */
    public const array LIMITS = [
        'dynamic aliases, runtime rebinding, and reflection',
        'generated code, host code, and raw SQL writes',
        'unrecognized helper indirection and whole-program data flow',
    ];

    /** @var list<string> */
    private const array EXPECTED_ROOT_DECRYPTS = [
        'ArtisanBuild\\BuiltForCloud\\Commands\\HmacRewrapCommand::rewrap',
        'ArtisanBuild\\BuiltForCloud\\Hmac\\SigningRootMac::mac',
        'ArtisanBuild\\BuiltForCloud\\Hmac\\SigningRootMac::verify',
    ];

    /**
     * @param  list<string>  $additionalRoots
     * @return array{
     *   producers: list<string>,
     *   producer_dispositions: list<string>,
     *   selectors: list<string>,
     *   selector_dispositions: list<string>,
     *   hmac_decrypt_sites: list<string>,
     *   root_decrypt_sites: list<string>,
     *   delegations: list<string>,
     *   violations: list<string>,
     *   limits: list<string>
     * }
     */
    public static function discover(string $sourceRoot, array $additionalRoots = []): array
    {
        $classes = self::classes($sourceRoot, $additionalRoots);
        $producers = [];
        $producerDispositions = [];
        $selectors = [];
        $selectorDispositions = [];
        $decryptSites = [];
        $rootDecryptSites = [];
        $delegations = [];
        $violations = [];

        foreach ($classes as $class => $record) {
            foreach ($record['methods'] as $method => $code) {
                $member = $class.'::'.$method;

                if (self::writesSigningRoot($code)) {
                    $producers[] = $member;
                    $disposition = self::producerDisposition($member, $code);
                    $producerDispositions[] = $member.'|'.$disposition;

                    if ($member !== 'ArtisanBuild\\BuiltForCloud\\Hmac\\SigningRootLifecycle::createRoot') {
                        $violations[] = 'unexpected-root-producer:'.$member;
                    }

                    if ($disposition !== 'direct-active-encrypted') {
                        $violations[] = 'root-producer-disposition:'.$member.'|'.$disposition;
                    }
                }

                if (str_contains($record['code'], 'HmacKeyring') && preg_match('/->decrypt\s*\(/', $code) === 1) {
                    $decryptSites[] = $member;

                    if (self::rootReachable($class, $code)) {
                        $rootDecryptSites[] = $member;

                        if (! in_array($member, self::EXPECTED_ROOT_DECRYPTS, true)) {
                            $violations[] = 'unexpected-root-decrypt:'.$member;
                        }

                        if ($class !== 'ArtisanBuild\\BuiltForCloud\\Commands\\HmacRewrapCommand') {
                            $selectors[] = $member;
                            $disposition = self::selectorDisposition($member, $code, $record['methods']);
                            $selectorDispositions[] = $member.'|'.$disposition;

                            if ($disposition === 'unapproved') {
                                $violations[] = 'root-selector-order:'.$member;
                            }
                        }
                    }
                }

                if (str_contains($code, 'SigningRootLifecycle::class)->rotate(')) {
                    $delegations[] = $member;

                    if ($member !== 'ArtisanBuild\\BuiltForCloud\\Actions\\RotateCredential::__invoke'
                        || ! self::delegatesBeforeOrdinaryPath($code)) {
                        $violations[] = 'root-delegation-disposition:'.$member;
                    }
                }
            }
        }

        foreach (array_diff(self::EXPECTED_ROOT_DECRYPTS, $rootDecryptSites) as $missing) {
            $violations[] = 'missing-root-decrypt:'.$missing;
        }

        if (! in_array('ArtisanBuild\\BuiltForCloud\\Hmac\\SigningRootLifecycle::createRoot', $producers, true)) {
            $violations[] = 'missing-root-producer:ArtisanBuild\\BuiltForCloud\\Hmac\\SigningRootLifecycle::createRoot';
        }

        if (! in_array('ArtisanBuild\\BuiltForCloud\\Actions\\RotateCredential::__invoke', $delegations, true)) {
            $violations[] = 'missing-root-delegation:ArtisanBuild\\BuiltForCloud\\Actions\\RotateCredential::__invoke';
        }

        return [
            'producers' => self::sortedUnique($producers),
            'producer_dispositions' => self::sortedUnique($producerDispositions),
            'selectors' => self::sortedUnique($selectors),
            'selector_dispositions' => self::sortedUnique($selectorDispositions),
            'hmac_decrypt_sites' => self::sortedUnique($decryptSites),
            'root_decrypt_sites' => self::sortedUnique($rootDecryptSites),
            'delegations' => self::sortedUnique($delegations),
            'violations' => self::sortedUnique($violations),
            'limits' => self::LIMITS,
        ];
    }

    private static function writesSigningRoot(string $code): bool
    {
        return str_contains($code, 'CredentialPurpose::SigningRoot')
            && (str_contains($code, 'new Credential') || str_contains($code, 'Credential::query()->create'));
    }

    private static function producerDisposition(string $member, string $code): string
    {
        if ($member === 'ArtisanBuild\\BuiltForCloud\\Hmac\\SigningRootLifecycle::createRoot'
            && str_contains($code, 'CredentialKind::Hmac')
            && str_contains($code, 'SubjectType::Installation')
            && str_contains($code, 'SigningRootMac::SUBJECT_REF')
            && str_contains($code, "'abilities' => null")
            && str_contains($code, 'CredentialStatus::Active')
            && str_contains($code, '$this->keyring->encrypt(')
            && ! str_contains($code, 'MintedSecret')) {
            return 'direct-active-encrypted';
        }

        return 'ordinary-or-unclassified';
    }

    /** @param array<string, string> $methods */
    private static function selectorDisposition(string $member, string $code, array $methods): string
    {
        $identity = implode("\n", [
            $methods['reservedCandidates'] ?? '',
            $methods['exactRootQuery'] ?? '',
            $methods['hasExactIdentity'] ?? '',
        ]);
        $hasIdentity = str_contains($identity, 'CredentialPurpose::SigningRoot')
            && str_contains($identity, 'CredentialKind::Hmac')
            && str_contains($identity, 'SubjectType::Installation')
            && str_contains($identity, 'self::SUBJECT_REF');
        $decrypt = strpos($code, '->decrypt(');

        if ($member === 'ArtisanBuild\\BuiltForCloud\\Hmac\\SigningRootMac::mac'
            && $hasIdentity
            && ($selection = strpos($code, 'soleCurrentRoot()')) !== false
            && $decrypt !== false
            && $selection < $decrypt
            && preg_match('/function\s+mac\s*\(string\s+\$bytes\)/', $code) === 1
            && str_contains($code, 'new SigningRootMacResult(')) {
            return 'current-only|identity-before-decrypt|input=bytes|result={keyId,lowercaseHexMac}';
        }

        if ($member === 'ArtisanBuild\\BuiltForCloud\\Hmac\\SigningRootMac::verify'
            && $hasIdentity
            && ($current = strpos($code, 'soleCurrentRoot()')) !== false
            && ($named = strpos($code, 'exactRootQuery()')) !== false
            && $decrypt !== false
            && $current < $named
            && $named < $decrypt
            && str_contains($code, '->whereKey($keyId)')
            && str_contains($code, '->active()')
            && str_contains($code, 'hash_equals($expected, $presentedMac)')) {
            return 'named-current-or-grace|identity-before-decrypt|result=bool';
        }

        return 'unapproved';
    }

    private static function rootReachable(string $class, string $code): bool
    {
        return $class === 'ArtisanBuild\\BuiltForCloud\\Hmac\\SigningRootMac'
            || $class === 'ArtisanBuild\\BuiltForCloud\\Commands\\HmacRewrapCommand'
            || str_contains($code, 'CredentialPurpose::SigningRoot')
            || str_contains($code, 'SigningRootMac::SUBJECT_REF');
    }

    private static function delegatesBeforeOrdinaryPath(string $code): bool
    {
        $reserved = strpos($code, 'SigningRootMac::isReserved(');
        $change = strpos($code, '$options->requestsChange()');
        $delegation = strpos($code, 'SigningRootLifecycle::class)->rotate(');
        $ordinary = strpos($code, '$phaseOne =');

        return $reserved !== false
            && $change !== false
            && $delegation !== false
            && $ordinary !== false
            && $reserved < $change
            && $change < $delegation
            && $delegation < $ordinary;
    }

    /**
     * @param  list<string>  $additionalRoots
     * @return array<string, array{code: string, methods: array<string, string>}>
     */
    private static function classes(string $sourceRoot, array $additionalRoots): array
    {
        $classes = [];

        foreach ([[$sourceRoot, true], ...array_map(static fn (string $root): array => [$root, false], $additionalRoots)] as [$root, $production]) {
            foreach (self::phpFiles($root, $production) as $file) {
                $code = self::withoutComments((string) file_get_contents($file));

                if (preg_match('/^namespace\s+([^;]+);/m', $code, $namespace) !== 1
                    || preg_match('/\b(?:final\s+|abstract\s+)?(?:readonly\s+)?class\s+([A-Z][A-Za-z0-9_]*)\b/', $code, $class) !== 1) {
                    continue;
                }

                $classes[$namespace[1].'\\'.$class[1]] = [
                    'code' => $code,
                    'methods' => self::methods($code),
                ];
            }
        }

        return $classes;
    }

    /** @return array<string, string> */
    private static function methods(string $code): array
    {
        preg_match_all('/\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/', $code, $matches, PREG_OFFSET_CAPTURE);
        $methods = [];

        foreach ($matches[1] as $index => [$name]) {
            $start = $matches[0][$index][1];
            $end = $matches[0][$index + 1][1] ?? strlen($code);
            $methods[$name] = substr($code, $start, $end - $start);
        }

        return $methods;
    }

    /** @return iterable<string> */
    private static function phpFiles(string $root, bool $production): iterable
    {
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

            yield $file->getPathname();
        }
    }

    private static function withoutComments(string $code): string
    {
        try {
            return implode('', array_map(
                static fn (array|string $token): string => is_string($token)
                    ? $token
                    : (in_array($token[0], [T_COMMENT, T_DOC_COMMENT], true) ? ' ' : $token[1]),
                token_get_all($code, TOKEN_PARSE),
            ));
        } catch (\ParseError $failure) {
            throw new RuntimeException('Could not parse an inventoried PHP source file.', previous: $failure);
        }
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
