<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

/**
 * Compares P5UI-AC8's inherited finite protocol sets with the P5-purpose
 * inventories that established them. UI reads are checked at class
 * granularity, which is deliberately stronger than the member-level ban.
 */
final class ProtocolUiGuardInventory
{
    /** @var list<string> */
    private const array RESOLVER_CALLERS = [
        'ArtisanBuild\\BuiltForCloud\\Auth\\BasicAuthenticator::credential|expressions=1',
        'ArtisanBuild\\BuiltForCloud\\Auth\\BearerAuthenticator::credential|expressions=1',
        'ArtisanBuild\\BuiltForCloud\\Auth\\CredentialGuard::validate|expressions=2',
        'ArtisanBuild\\BuiltForCloud\\BoundBearerCredentialAuthenticator::authenticate|expressions=1',
        'ArtisanBuild\\BuiltForCloud\\Http\\Controllers\\ManageOnboarding::verifyUnifiedDurable|expressions=1',
        'ArtisanBuild\\BuiltForCloud\\Http\\Middleware\\AuthenticateMcp::handle|expressions=1',
        'ArtisanBuild\\BuiltForCloud\\Http\\Middleware\\EnsureCredentialAdmin::handle|expressions=1',
    ];

    /** @var list<string> */
    private const array ORDINARY_HMAC_SELECTORS = [
        'ArtisanBuild\\BuiltForCloud\\Hmac\\HmacSigner::sign',
        'ArtisanBuild\\BuiltForCloud\\Hmac\\HmacVerifier::verify',
    ];

    /** @var list<string> */
    private const array APP_PURPOSE_CONSUMERS = [
        'ArtisanBuild\\BuiltForCloud\\AppPurposeRegistry::purpose',
    ];

    /** @var list<string> */
    private const array ROOT_SELECTORS = [
        'ArtisanBuild\\BuiltForCloud\\Hmac\\SigningRootMac::mac',
        'ArtisanBuild\\BuiltForCloud\\Hmac\\SigningRootMac::verify',
    ];

    /** @var list<string> */
    private const array DIRECT_MEMBERS = [
        'ArtisanBuild\\BuiltForCloud\\Auth\\CredentialResolver::resolve',
        'ArtisanBuild\\BuiltForCloud\\ManagedAccountAccess::allowsCredential',
        'ArtisanBuild\\BuiltForCloud\\Hmac\\HmacVerifier::verify',
        'ArtisanBuild\\BuiltForCloud\\Console\\AssertionVerifier::verify',
    ];

    /**
     * @param  list<string>  $additionalRoots
     * @param  list<string>  $additionalForbiddenMembers
     * @return array{
     *   resolver_callers: list<string>,
     *   resolver_expression_count: int,
     *   ordinary_hmac_selectors: list<string>,
     *   app_purpose_consumers: list<string>,
     *   root_selectors: list<string>,
     *   direct_members: list<string>,
     *   forbidden_members: list<string>,
     *   ui_reads: list<string>,
     *   violations: list<string>
     * }
     */
    public static function compare(
        string $sourceRoot,
        array $additionalRoots = [],
        array $additionalForbiddenMembers = [],
    ): array {
        $purpose = CredentialPathInventory::comparePurposePolicy($sourceRoot);
        $appPurpose = AppPurposeConsumerInventory::discover($sourceRoot);
        $root = SigningRootInventory::discover($sourceRoot);

        $ordinarySelectors = array_map(
            static fn (string $class): string => $class.(str_ends_with($class, '\\HmacSigner') ? '::sign' : '::verify'),
            $purpose['hmac_selectors'],
        );
        $appPurposeConsumers = array_column($appPurpose['consumers'], 'member');
        $violations = [
            ...$purpose['violations'],
            ...$appPurpose['violations'],
            ...$root['violations'],
            ...self::setViolations('resolver-caller', self::RESOLVER_CALLERS, $purpose['resolver_callers']),
            ...self::setViolations('ordinary-hmac-selector', self::ORDINARY_HMAC_SELECTORS, $ordinarySelectors),
            ...self::setViolations('app-purpose-consumer', self::APP_PURPOSE_CONSUMERS, $appPurposeConsumers),
            ...self::setViolations('root-selector', self::ROOT_SELECTORS, $root['selectors']),
        ];

        if ($purpose['resolver_expression_count'] !== 8) {
            $violations[] = 'resolver-expression-count:expected=8 actual='.$purpose['resolver_expression_count'];
        }

        foreach (self::DIRECT_MEMBERS as $member) {
            if (! self::memberExists($sourceRoot, $member)) {
                $violations[] = 'missing-direct-member:'.$member;
            }
        }

        $forbiddenMembers = self::sortedUnique([
            ...array_map(static fn (string $caller): string => explode('|', $caller, 2)[0], self::RESOLVER_CALLERS),
            ...self::ORDINARY_HMAC_SELECTORS,
            ...self::APP_PURPOSE_CONSUMERS,
            ...self::ROOT_SELECTORS,
            ...self::DIRECT_MEMBERS,
            ...$additionalForbiddenMembers,
        ]);
        $forbiddenConsumers = self::sortedUnique(array_map(
            static fn (string $member): string => explode('::', $member, 2)[0],
            $forbiddenMembers,
        ));
        $uiReads = UiConfigReadScan::forbiddenConsumerReads($sourceRoot, $forbiddenConsumers, $additionalRoots);

        foreach ($uiReads as $read) {
            $violations[] = 'forbidden-ui-read:'.$read;
        }

        return [
            'resolver_callers' => $purpose['resolver_callers'],
            'resolver_expression_count' => $purpose['resolver_expression_count'],
            'ordinary_hmac_selectors' => $ordinarySelectors,
            'app_purpose_consumers' => $appPurposeConsumers,
            'root_selectors' => $root['selectors'],
            'direct_members' => self::DIRECT_MEMBERS,
            'forbidden_members' => $forbiddenMembers,
            'ui_reads' => $uiReads,
            'violations' => self::sortedUnique($violations),
        ];
    }

    /**
     * @param  list<string>  $expected
     * @param  list<string>  $actual
     * @return list<string>
     */
    private static function setViolations(string $set, array $expected, array $actual): array
    {
        return [
            ...array_map(static fn (string $member): string => 'missing-'.$set.':'.$member, array_diff($expected, $actual)),
            ...array_map(static fn (string $member): string => 'unexpected-'.$set.':'.$member, array_diff($actual, $expected)),
        ];
    }

    private static function memberExists(string $sourceRoot, string $member): bool
    {
        [$class, $method] = explode('::', $member, 2);
        $prefix = 'ArtisanBuild\\BuiltForCloud\\';

        if (! str_starts_with($class, $prefix)) {
            return false;
        }

        $file = $sourceRoot.'/'.str_replace('\\', '/', substr($class, strlen($prefix))).'.php';
        $code = is_file($file) ? file_get_contents($file) : false;

        return is_string($code)
            && preg_match('/\\bfunction\\s+'.preg_quote($method, '/').'\\s*\\(/', $code) === 1;
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
