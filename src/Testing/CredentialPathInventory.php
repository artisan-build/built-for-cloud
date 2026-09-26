<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use RuntimeException;
use SplFileInfo;

/**
 * P5-AC1's five-root static inventory for credential paths, lifecycle,
 * enrollment, authority classification and HMAC key selection. It derives
 * named classes, provider registrations, direct dependencies/calls, action
 * methods, minter targets, literal routes, enum cases and command signatures
 * from installed PHP source. The nine discoverable path identities and transitional oracles
 * deliberately live in the test, not here, so discovery cannot edit its own
 * expected answer. Stable path identities do not embed transitional resolver
 * choices, so P5-AC12 can use the same five roots and positive controls.
 *
 * This is source classification, not whole-program data-flow analysis. It
 * cannot see dynamic class names, container bindings assembled outside the
 * provider, routes registered through an unknown wrapper, runtime rebinding,
 * direct model writes, host code or non-PHP generated code. The emitted device
 * and loopback rows prove only that the literal package route/action chains,
 * exact-bound selector and containment participant are present. They do not
 * prove browser/session binding, transaction order or runtime scope equality.
 * Fixture controls prove rogue device exchange and loopback selector shapes in
 * addition to the ordinary bypass, second-store resolver, extra enrollment-route
 * and indirect class-bound gate shapes this instrument claims to report. Hidden
 * dynamic/container/host/generated-code equivalents remain review/live concerns;
 * hostile host reconfiguration is outside the package boundary.
 */
final class CredentialPathInventory
{
    /**
     * Derive and compare P5P-AC2's direct resolver callers and ordinary HMAC
     * selectors. This is a syntax inventory, not data-flow analysis: it sees
     * literal CredentialResolver dependencies/calls and ordinary query-builder
     * HMAC selectors in PHP source. The reserved SigningRootMac selectors are
     * excluded here and independently compared by SigningRootInventory. This
     * scanner cannot see aliases assembled dynamically,
     * container calls hidden behind wrappers, runtime rebinding, generated
     * code, or host application code. Required purpose tokens are checked at
     * named method or selector-class granularity; this does not prove that
     * every resolve expression, enforcement predicate, or selection query is
     * individually guarded. Behavioral tests own those per-path order claims.
     *
     * @param  list<string>  $additionalRoots
     * @return array{
     *   resolver_callers: list<string>,
     *   resolver_expression_count: int,
     *   hmac_selectors: list<string>,
     *   dispositions: list<string>,
     *   violations: list<string>
     * }
     */
    public static function comparePurposePolicy(string $sourceRoot, array $additionalRoots = []): array
    {
        $classes = self::classes(self::sourceFiles([$sourceRoot, ...$additionalRoots]));
        $expectedCallers = [
            'ArtisanBuild\\BuiltForCloud\\Auth\\BasicAuthenticator::credential' => 1,
            'ArtisanBuild\\BuiltForCloud\\Auth\\BearerAuthenticator::credential' => 1,
            'ArtisanBuild\\BuiltForCloud\\Auth\\CredentialGuard::validate' => 2,
            'ArtisanBuild\\BuiltForCloud\\BoundBearerCredentialAuthenticator::authenticate' => 1,
            'ArtisanBuild\\BuiltForCloud\\Http\\Controllers\\ManageOnboarding::verifyUnifiedDurable' => 1,
            'ArtisanBuild\\BuiltForCloud\\Http\\Middleware\\AuthenticateMcp::handle' => 1,
            'ArtisanBuild\\BuiltForCloud\\Http\\Middleware\\EnsureCredentialAdmin::handle' => 1,
            'ArtisanBuild\\BuiltForCloud\\Http\\Middleware\\EnsureCurrentOwnerCredential::handle' => 1,
        ];
        $expectedSelectors = [
            'ArtisanBuild\\BuiltForCloud\\Hmac\\HmacSigner',
            'ArtisanBuild\\BuiltForCloud\\Hmac\\HmacVerifier',
        ];
        $callers = [];
        $selectors = [];
        $violations = [];

        foreach ($classes as $class => $record) {
            if (str_contains($record['code'], 'CredentialResolver')) {
                preg_match_all(
                    '/->(?:resolve\s*\(\s*CredentialKind::(?:Bearer|Basic)\b|resolveBoundBearer\s*\()/',
                    $record['code'],
                    $expressions,
                    PREG_OFFSET_CAPTURE,
                );

                foreach ($expressions[0] as [, $offset]) {
                    $method = self::methodAtOffset($record['code'], $offset);
                    $identity = $class.'::'.$method;
                    $callers[$identity] = ($callers[$identity] ?? 0) + 1;
                }
            }

            if (str_contains($record['code'], 'Credential::query()')
                && str_contains($record['code'], 'CredentialKind::Hmac')
                && preg_match('/\$this->keyring->decrypt\s*\(/', $record['code']) === 1
                && $class !== 'ArtisanBuild\\BuiltForCloud\\Hmac\\SigningRootMac') {
                $selectors[] = $class;
            }
        }

        ksort($callers);
        $selectors = self::sortedUnique($selectors);

        foreach (array_diff(array_keys($expectedCallers), array_keys($callers)) as $missing) {
            $violations[] = 'missing-resolver-caller:'.$missing;
        }

        foreach (array_diff(array_keys($callers), array_keys($expectedCallers)) as $unexpected) {
            $violations[] = 'unexpected-resolver-caller:'.$unexpected;
            $violations[] = 'missing-purpose-rule:'.$unexpected;
        }

        foreach ($expectedCallers as $caller => $count) {
            if (isset($callers[$caller]) && $callers[$caller] !== $count) {
                $violations[] = 'resolver-expression-count:'.$caller.' expected='.$count.' actual='.$callers[$caller];
            }
        }

        foreach (array_diff($expectedSelectors, $selectors) as $missing) {
            $violations[] = 'missing-hmac-selector:'.$missing;
        }

        foreach (array_diff($selectors, $expectedSelectors) as $unexpected) {
            $violations[] = 'unexpected-hmac-selector:'.$unexpected;
        }

        $dispositions = self::purposeDispositions($classes, $violations);

        foreach ($selectors as $selector) {
            $code = $classes[$selector]['code'];

            if (preg_match('/->where\s*\(\s*[\'"]purpose[\'"]\s*,\s*CredentialPurpose::Signing->value\s*\)/', $code) !== 1) {
                $violations[] = 'missing-signing-purpose:'.$selector;
            }
        }

        return [
            'resolver_callers' => array_map(
                static fn (string $caller, int $count): string => $caller.'|expressions='.$count,
                array_keys($callers),
                array_values($callers),
            ),
            'resolver_expression_count' => array_sum($callers),
            'hmac_selectors' => $selectors,
            'dispositions' => self::sortedUnique($dispositions),
            'violations' => self::sortedUnique($violations),
        ];
    }

    /**
     * @param  list<string>  $additionalRoots
     * @return array{
     *   mechanisms: list<string>,
     *   lifecycle: list<string>,
     *   enrollment: list<string>,
     *   enrollment_properties: list<string>,
     *   classification: list<string>,
     *   key_selection: list<string>,
     *   resolution_choke_points: list<string>,
     *   operator_ingresses: list<string>,
     *   managed_containment: list<string>,
     *   paths: list<string>,
     *   transitional: list<string>,
     *   transition_members: list<string>,
     *   violations: list<string>
     * }
     */
    public static function discover(string $sourceRoot, array $additionalRoots = []): array
    {
        $files = self::sourceFiles([$sourceRoot, ...$additionalRoots]);
        $classes = self::classes($files);
        $provider = self::requiredContents($sourceRoot.'/BuiltForCloudServiceProvider.php');
        $providerCode = self::withoutComments($provider);
        $providerImports = self::imports($provider);
        $routeFiles = self::routeFiles($sourceRoot);
        $routeDeclarations = implode("\n", [$providerCode, ...array_values($routeFiles)]);

        $authenticators = self::implementations($classes, 'CredentialAuthenticator');
        $minters = self::implementations($classes, 'DurableCredentialMinter');
        $middleware = self::registeredMiddleware($classes, $providerCode, $providerImports, $routeFiles);

        preg_match_all(
            '/\$auth->extend\((?:(?!\$auth->extend).)*?return\s+new\s+([A-Z][A-Za-z0-9_]*)\s*\(/s',
            $providerCode,
            $guardMatches,
        );

        $mechanisms = [];

        foreach ($guardMatches[1] as $guard) {
            $mechanisms[] = 'guard:'.self::imported($providerImports, $guard);
        }

        array_push($mechanisms, ...$middleware);

        foreach ($authenticators as $class) {
            $mechanisms[] = 'authenticator:'.$class;
        }

        $presentedGates = array_values(array_unique([
            ...$authenticators,
            ...array_map(static fn (string $item): string => substr($item, strlen('middleware:')), $middleware),
        ]));
        $operatorIngresses = [];
        $violations = [];
        array_push($violations, ...self::authorizationPathViolations($classes));
        $legacyRegistry = implode('\\', ['ArtisanBuild', 'BuiltForCloud', implode('', ['Token', 'Registry'])]);

        foreach ($presentedGates as $gate) {
            $record = $classes[$gate] ?? null;

            if ($record === null || ! self::presentsSecret($record['code'])) {
                continue;
            }

            $dependencies = self::resolutionDependencies($gate, $record['code'], $record['imports']);

            foreach ($dependencies as $dependency) {
                $mechanisms[] = 'resolver-service:'.$dependency;
                $dependencyCode = $classes[$dependency]['code'] ?? '';

                if ($dependency !== $legacyRegistry
                    && self::readsSecondCredentialStore($dependencyCode)) {
                    $violations[] = 'second-store-resolver:'.$gate.'=>'.$dependency;
                }
            }

            if (self::presentsStoreSecret($record['code'])) {
                if (in_array('ArtisanBuild\\BuiltForCloud\\Auth\\CredentialResolver', $dependencies, true)
                    && ! self::readsCredentialStoreByHash($record['code'])) {
                    $operatorIngresses[] = 'operator-ingress:'.$gate.'=>ArtisanBuild\\BuiltForCloud\\Auth\\CredentialResolver::resolve';
                } else {
                    $violations[] = 'unchoked-operator-ingress:'.$gate;
                }
            }
        }

        foreach ($authenticators as $authenticator) {
            $code = $classes[$authenticator]['code'];

            if (! str_contains($code, 'CredentialResolver') && ! str_contains($code, 'HmacVerifier')) {
                $violations[] = 'unchoked-authenticator:'.$authenticator;
            }
        }

        $lifecycle = self::lifecycle($classes, $minters);
        $enrollment = self::enrollment([...$files, ...$routeFiles], $classes, $providerImports);
        $enrollmentProperties = self::enrollmentProperties($classes);
        $classification = self::classification($classes, $providerCode, $providerImports);
        $keySelection = self::keySelection($classes);
        $transitionMembers = self::transitionMembers($classification);
        $resolutionChokePoints = [];
        $managedContainment = [];

        foreach ($keySelection as $selection) {
            $mechanisms[] = 'key-sink:'.substr($selection, strlen('key-selection:'));
        }

        $credentialResolver = 'ArtisanBuild\\BuiltForCloud\\Auth\\CredentialResolver';
        if (isset($classes[$credentialResolver])
            && str_contains($classes[$credentialResolver]['code'], 'public function resolve(')
            && in_array('resolver-service:'.$credentialResolver, $mechanisms, true)) {
            $mechanisms[] = 'resolver:'.$credentialResolver;
            $resolutionChokePoints[] = 'choke-point:'.$credentialResolver.'::resolve';

            if (preg_match(
                '/private\s+readonly\s+ManagedAccountAccess\s+\$([A-Za-z_][A-Za-z0-9_]*)/',
                $classes[$credentialResolver]['code'],
                $managedAccess,
            ) === 1
                && preg_match(
                    '/\$this->'.preg_quote($managedAccess[1], '/').'->allowsCredential\(\$credential\)/',
                    $classes[$credentialResolver]['code'],
                ) === 1) {
                $managedContainment[] = 'managed-containment:'.$credentialResolver.'::resolve=>ArtisanBuild\\BuiltForCloud\\ManagedAccountAccess::allowsCredential';
            }
        }

        $hmacVerifier = 'ArtisanBuild\\BuiltForCloud\\Hmac\\HmacVerifier';
        if (in_array('key-selection:'.$hmacVerifier, $keySelection, true)
            && str_contains($classes[$hmacVerifier]['code'], 'public function verify(')) {
            $resolutionChokePoints[] = 'choke-point:'.$hmacVerifier.'::verify';
        }

        $asymmetricKeys = 'ArtisanBuild\\BuiltForCloud\\AsymmetricVerificationKeys';
        if (in_array('key-selection:'.$asymmetricKeys, $keySelection, true)) {
            $resolutionChokePoints[] = 'choke-point:'.$asymmetricKeys.'::for';
        }

        $paths = self::paths(
            $classes,
            $routeDeclarations,
            $authenticators,
            $enrollment,
            $classification,
            $keySelection,
            $resolutionChokePoints,
        );
        $transitional = self::transitional(
            $mechanisms,
            $lifecycle,
            $providerCode,
            $providerImports,
            $classification,
            $transitionMembers,
        );

        $expectedEnrollmentRoutes = [
            'route:POST /bfc/asymmetric-enrollments/{application}=>ArtisanBuild\\BuiltForCloud\\Http\\Controllers\\AsymmetricEnrollments::__invoke',
            'route:POST /bfc/claim=>ArtisanBuild\\BuiltForCloud\\Http\\Controllers\\ManageOnboarding::claim',
            'route:POST /bfc/onboarding/exchange=>ArtisanBuild\\BuiltForCloud\\Http\\Controllers\\ManageOnboarding::exchange',
            'route:POST /bfc/onboarding/issue=>ArtisanBuild\\BuiltForCloud\\Http\\Controllers\\ManageOnboarding::issue',
            'route:POST /bfc/onboarding/verify=>ArtisanBuild\\BuiltForCloud\\Http\\Controllers\\ManageOnboarding::verify',
        ];

        foreach ($enrollment as $item) {
            if (str_starts_with($item, 'route:') && ! in_array($item, $expectedEnrollmentRoutes, true)) {
                $violations[] = 'unlisted-enrollment-route:'.$item;
            }
        }

        $mechanisms = self::sortedUnique($mechanisms);
        $lifecycle = self::sortedUnique($lifecycle);
        $enrollment = self::sortedUnique($enrollment);
        $enrollmentProperties = self::sortedUnique($enrollmentProperties);
        $classification = self::sortedUnique($classification);
        $keySelection = self::sortedUnique($keySelection);
        $resolutionChokePoints = self::sortedUnique($resolutionChokePoints);
        $operatorIngresses = self::sortedUnique($operatorIngresses);
        $managedContainment = self::sortedUnique($managedContainment);
        $paths = self::sortedUnique($paths);
        $transitional = self::sortedUnique($transitional);
        $transitionMembers = self::sortedUnique($transitionMembers);
        $violations = self::sortedUnique($violations);

        return [
            'mechanisms' => $mechanisms,
            'lifecycle' => $lifecycle,
            'enrollment' => $enrollment,
            'enrollment_properties' => $enrollmentProperties,
            'classification' => $classification,
            'key_selection' => $keySelection,
            'resolution_choke_points' => $resolutionChokePoints,
            'operator_ingresses' => $operatorIngresses,
            'managed_containment' => $managedContainment,
            'paths' => $paths,
            'transitional' => $transitional,
            'transition_members' => $transitionMembers,
            'violations' => $violations,
        ];
    }

    /**
     * @param  array<string, array{code: string, imports: array<string, string>}>  $classes
     * @param  list<string>  $minters
     * @return list<string>
     */
    private static function lifecycle(array $classes, array $minters): array
    {
        $items = [];
        $actions = [
            'ActivateCredential',
            'CompleteAsymmetricEnrollment',
            'ListCredentials',
            'MintCredential',
            'OffboardSubject',
            'RevokeCredential',
            'RotateCredential',
        ];

        foreach ($classes as $class => $record) {
            if (! str_starts_with($class, 'ArtisanBuild\\BuiltForCloud\\Actions\\')
                || ! in_array(self::shortName($class), $actions, true)) {
                continue;
            }

            preg_match_all('/\bpublic\s+function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/', $record['code'], $methods);

            foreach ($methods[1] as $method) {
                if ($method !== '__construct') {
                    $items[] = 'action:'.$class.'::'.$method;
                }
            }

            if ($class === 'ArtisanBuild\\BuiltForCloud\\Actions\\MintCredential'
                && str_contains($record['code'], 'function mintEnrollment(')) {
                $items[] = 'action:'.$class.'::mintEnrollment';
            }
        }

        foreach ($minters as $minter) {
            $code = $classes[$minter]['code'];
            $legacyTable = implode('_', ['api', 'tokens']);
            $target = str_contains($code, 'Credential::query()->create')
                ? 'Credential(credentials)'
                : (str_contains($code, implode('', ['Token', 'Registry'])) && str_contains($code, '->store(')
                    ? implode('', ['Api', 'Token']).'('.$legacyTable.')'
                    : 'unknown');
            $items[] = 'minter:'.$minter.'=>'.$target;
        }

        return $items;
    }

    /**
     * @param  array<string, array{code: string, imports: array<string, string>}>  $classes
     * @param  list<string>  $violations
     * @return list<string>
     */
    private static function purposeDispositions(array $classes, array &$violations): array
    {
        $checks = [
            'ArtisanBuild\\BuiltForCloud\\Auth\\BasicAuthenticator::credential' => [
                'source' => 'ArtisanBuild\\BuiltForCloud\\Auth\\CredentialGuard::user',
                'tokens' => ['CredentialPurpose::Consumption', 'CredentialPurpose::SystemDeployment', 'credentialForPurposes'],
                'rule' => 'guard:{consumption,system_deployment}',
            ],
            'ArtisanBuild\\BuiltForCloud\\Auth\\BearerAuthenticator::credential' => [
                'source' => 'ArtisanBuild\\BuiltForCloud\\Auth\\CredentialGuard::user',
                'tokens' => ['CredentialPurpose::Consumption', 'CredentialPurpose::SystemDeployment', 'credentialForPurposes'],
                'rule' => 'guard:{consumption,system_deployment}',
            ],
            'ArtisanBuild\\BuiltForCloud\\Auth\\CredentialGuard::validate' => [
                'source' => 'ArtisanBuild\\BuiltForCloud\\Auth\\CredentialGuard::validate',
                'tokens' => ['CredentialPurpose::Consumption', 'CredentialPurpose::SystemDeployment', 'in_array'],
                'rule' => '{consumption,system_deployment}',
            ],
            'ArtisanBuild\\BuiltForCloud\\BoundBearerCredentialAuthenticator::authenticate' => [
                'source' => 'ArtisanBuild\\BuiltForCloud\\BoundBearerCredentialAuthenticator::authenticate',
                'tokens' => ['forUse', 'resolveBoundBearer', '$purpose'],
                'rule' => 'app-purpose-registry+exact-bound-bearer',
            ],
            'ArtisanBuild\\BuiltForCloud\\Http\\Controllers\\ManageOnboarding::verifyUnifiedDurable' => [
                'source' => 'ArtisanBuild\\BuiltForCloud\\Http\\Controllers\\ManageOnboarding::verifyUnifiedDurable',
                'tokens' => ['CredentialPurpose::Consumption', 'CredentialPurpose::OperatorManagement', 'CredentialPurpose::Enrollment', 'recordUsage'],
                'rule' => '{consumption,operator_management,enrollment}->scope',
            ],
            'ArtisanBuild\\BuiltForCloud\\Http\\Middleware\\AuthenticateMcp::handle' => [
                'source' => 'ArtisanBuild\\BuiltForCloud\\Http\\Middleware\\AuthenticateMcp::handle',
                'tokens' => ['CredentialPurpose::Mcp', 'CredentialPurpose::OperatorManagement', 'SubjectType::Operator', 'OperatorAbility::Admin', 'recordUsage'],
                'rule' => 'mcp|{operator_management+operator+credential:admin}',
            ],
            'ArtisanBuild\\BuiltForCloud\\Http\\Middleware\\EnsureCredentialAdmin::handle' => [
                'source' => 'ArtisanBuild\\BuiltForCloud\\Http\\Middleware\\EnsureCredentialAdmin::handle',
                'tokens' => ['CredentialPurpose::OperatorManagement', 'recordUsage'],
                'rule' => 'operator_management',
            ],
            'ArtisanBuild\\BuiltForCloud\\Http\\Middleware\\EnsureCurrentOwnerCredential::handle' => [
                'source' => 'ArtisanBuild\\BuiltForCloud\\Http\\Middleware\\EnsureCurrentOwnerCredential::handle',
                'tokens' => ['CredentialPurpose::OperatorManagement', 'recordUsage'],
                'rule' => 'operator_management+current-owner',
            ],
        ];
        $dispositions = [];

        foreach ($checks as $caller => $check) {
            [$class, $method] = explode('::', $check['source'], 2);
            $code = isset($classes[$class]) ? self::methodCode($classes[$class]['code'], $method) : '';

            foreach ($check['tokens'] as $token) {
                if (! str_contains($code, $token)) {
                    $violations[] = 'missing-purpose-rule:'.$caller;

                    continue 2;
                }
            }

            $dispositions[] = 'resolver-caller:'.$caller.'|purpose='.$check['rule'];
        }

        return $dispositions;
    }

    private static function methodAtOffset(string $code, int $offset): string
    {
        preg_match_all('/\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/', substr($code, 0, $offset), $methods);

        return $methods[1] === [] ? '<class-scope>' : (string) end($methods[1]);
    }

    private static function methodCode(string $code, string $method): string
    {
        preg_match_all('/\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/', $code, $methods, PREG_OFFSET_CAPTURE);

        foreach ($methods[1] as $index => [$name]) {
            if ($name !== $method) {
                continue;
            }

            $start = $methods[0][$index][1];
            $end = $methods[0][$index + 1][1] ?? strlen($code);

            return substr($code, $start, $end - $start);
        }

        return '';
    }

    /**
     * @param  array<string, string>  $files
     * @param  array<string, array{code: string, imports: array<string, string>}>  $classes
     * @param  array<string, string>  $providerImports
     * @return list<string>
     */
    private static function enrollment(array $files, array $classes, array $providerImports): array
    {
        $items = [];

        foreach ($files as $code) {
            $imports = self::imports($code) + $providerImports;

            preg_match_all(
                '/(?:\$router->|Route::)(get|post|put|patch|delete)\(\s*[\'\"]([^\'\"]+)[\'\"]\s*,\s*\[\s*([A-Z][A-Za-z0-9_]*)::class\s*,\s*[\'\"]([^\'\"]+)[\'\"]\s*\]/i',
                $code,
                $routes,
                PREG_SET_ORDER,
            );

            foreach ($routes as $route) {
                $controller = $imports[$route[3]] ?? $route[3];

                if ($controller === 'ArtisanBuild\\BuiltForCloud\\Http\\Controllers\\ManageOnboarding') {
                    $items[] = 'route:'.strtoupper($route[1]).' '.$route[2].'=>'.$controller.'::'.$route[4];
                }
            }

            preg_match_all(
                '/(?:\$router->|Route::)(get|post|put|patch|delete)\(\s*[\'"]([^\'"]+)[\'"]\s*,\s*([A-Z][A-Za-z0-9_]*)::class\s*\)/i',
                $code,
                $invokableRoutes,
                PREG_SET_ORDER,
            );

            foreach ($invokableRoutes as $route) {
                $controller = $imports[$route[3]] ?? $route[3];

                if ($controller === 'ArtisanBuild\\BuiltForCloud\\Http\\Controllers\\AsymmetricEnrollments') {
                    $items[] = 'route:'.strtoupper($route[1]).' '.$route[2].'=>'.$controller.'::__invoke';
                }
            }
        }

        $model = 'ArtisanBuild\\BuiltForCloud\\OnboardingToken';
        $controller = 'ArtisanBuild\\BuiltForCloud\\Http\\Controllers\\ManageOnboarding';

        if (isset($classes[$model], $classes[$controller])
            && str_contains($classes[$controller]['code'], 'OnboardingToken')) {
            $items[] = 'model:'.$model;
        }

        return $items;
    }

    /**
     * @param  array<string, array{code: string, imports: array<string, string>}>  $classes
     * @return list<string>
     */
    private static function enrollmentProperties(array $classes): array
    {
        $properties = [];
        $token = $classes['ArtisanBuild\\BuiltForCloud\\OnboardingToken']['code'] ?? '';
        $mint = $classes['ArtisanBuild\\BuiltForCloud\\Actions\\MintCredential']['code'] ?? '';
        $exchange = $classes['ArtisanBuild\\BuiltForCloud\\Http\\Controllers\\ManageOnboarding']['code'] ?? '';
        $revoke = $classes['ArtisanBuild\\BuiltForCloud\\Actions\\RevokeCredential']['code'] ?? '';
        $declaration = $classes['ArtisanBuild\\BuiltForCloud\\DefaultCredentialDeclaration']['code'] ?? '';
        $usage = $classes['ArtisanBuild\\BuiltForCloud\\CredentialUsageRecorder']['code'] ?? '';

        if (str_contains($mint, "'token_hash' => \$code->hash()")
            && str_contains($token, "return hash('sha256', \$token)")
            && str_contains($token, "->where('token_hash', self::hashToken(\$plainTextToken))")) {
            $properties[] = 'enrollment-code:hash-only';
        }

        if (preg_match('/\$ttlSeconds\s*===\s*null\s*\|\|\s*\$ttlSeconds\s*<\s*self::CODE_TTL_MIN_SECONDS\s*\|\|\s*\$ttlSeconds\s*>\s*self::CODE_TTL_MAX_SECONDS/', $mint) === 1
            && str_contains($mint, "'expires_at' => now()->addSeconds(\$ttlSeconds)")) {
            $properties[] = 'enrollment-code:short-lived';
        }

        if (str_contains($token, "return \$query->whereNull('consumed_at')")
            && str_contains($exchange, 'if ($code->consumed_at !== null)')
            && str_contains($exchange, 'if ($this->burnMode() === BurnMode::AtExchange)')
            && str_contains($exchange, "->whereNull('consumed_at')")
            && str_contains($exchange, "->update(['consumed_at' => now()])")
            && str_contains($declaration, 'return BurnMode::FirstUse')
            && str_contains($usage, 'return $this->burnFirstUse($credential)')
            && str_contains($usage, "->where('durable_credential_id', \$credential->getKey())")
            && str_contains($usage, "->whereNull('consumed_at')")
            && str_contains($usage, "->update(['consumed_at' => now()])")) {
            $properties[] = 'enrollment-code:single-use';
        }

        if (str_contains($revoke, 'OnboardingToken::query()')
            && str_contains($revoke, "->where('durable_credential_id', \$id)")
            && str_contains($revoke, "->whereNull('consumed_at')")
            && str_contains($revoke, "->update(['consumed_at' => \$now])")) {
            $properties[] = 'enrollment-code:revocable';
        }

        return $properties;
    }

    /**
     * @param  array<string, array{code: string, imports: array<string, string>}>  $classes
     * @param  array<string, string>  $providerImports
     * @return list<string>
     */
    private static function classification(array $classes, string $providerCode, array $providerImports): array
    {
        $items = [];

        foreach (['ArtisanBuild\\BuiltForCloud\\AuditActorType', 'ArtisanBuild\\BuiltForCloud\\Audit\\AppActorType', 'ArtisanBuild\\BuiltForCloud\\SubjectType'] as $enum) {
            $code = $classes[$enum]['code'] ?? '';
            preg_match_all('/\bcase\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[\'\"]([^\'\"]+)[\'\"]/', $code, $cases, PREG_SET_ORDER);

            foreach ($cases as $case) {
                $items[] = 'enum:'.$enum.'::'.$case[1].'='.$case[2];
            }
        }

        if (preg_match('/\$this->commands\(\s*\[(.*?)\]\s*\);/s', $providerCode, $registered) !== 1) {
            throw new RuntimeException('Could not derive the provider command registration.');
        }

        preg_match_all('/([A-Z][A-Za-z0-9_]*)::class/', $registered[1], $commands);

        foreach ($commands[1] as $short) {
            $class = self::imported($providerImports, $short);
            $code = $classes[$class]['code'] ?? throw new RuntimeException("Could not find registered command [{$class}].");

            if (preg_match('/protected\s+\$signature\s*=\s*[\'\"]([^\s\'\"]+)/', $code, $signature) !== 1) {
                throw new RuntimeException("Could not derive the signature for [{$class}].");
            }

            $items[] = 'command:'.$class.'='.$signature[1];
        }

        return $items;
    }

    /**
     * @param  array<string, array{code: string, imports: array<string, string>}>  $classes
     * @return list<string>
     */
    private static function keySelection(array $classes): array
    {
        $items = [];

        foreach (['ArtisanBuild\\BuiltForCloud\\Hmac\\HmacSigner', 'ArtisanBuild\\BuiltForCloud\\Hmac\\HmacVerifier'] as $sink) {
            $code = $classes[$sink]['code'] ?? '';

            if (str_contains($code, 'Credential::query()')
                && str_contains($code, 'CredentialKind::Hmac')) {
                $items[] = 'key-selection:'.$sink;
            }
        }

        $asymmetric = 'ArtisanBuild\\BuiltForCloud\\AsymmetricVerificationKeys';
        $code = $classes[$asymmetric]['code'] ?? '';

        if (str_contains($code, 'credential_protocol_bindings')
            && str_contains($code, 'CredentialKind::Asymmetric')
            && str_contains($code, 'public function for(')) {
            $items[] = 'key-selection:'.$asymmetric;
        }

        return $items;
    }

    /**
     * @param  array<string, array{code: string, imports: array<string, string>}>  $classes
     * @param  string  $routeDeclarations  the provider and the package route files, comments removed
     * @param  list<string>  $authenticators
     * @param  list<string>  $enrollment
     * @param  list<string>  $classification
     * @param  list<string>  $keySelection
     * @param  list<string>  $resolutionChokePoints
     * @return list<string>
     */
    private static function paths(
        array $classes,
        string $routeDeclarations,
        array $authenticators,
        array $enrollment,
        array $classification,
        array $keySelection,
        array $resolutionChokePoints,
    ): array {
        $paths = [];

        foreach ($authenticators as $authenticator) {
            $code = $classes[$authenticator]['code'];

            if (preg_match('/CredentialKind::(Basic|Bearer)/', $code, $kind) === 1
                && str_contains($code, 'CredentialResolver')
                && in_array('choke-point:ArtisanBuild\\BuiltForCloud\\Auth\\CredentialResolver::resolve', $resolutionChokePoints, true)) {
                $paths[] = sprintf(
                    'path:%s|%s',
                    $kind[1],
                    $authenticator,
                );
            }
        }

        $mcp = $classes['ArtisanBuild\\BuiltForCloud\\Http\\Middleware\\AuthenticateMcp']['code'] ?? '';
        if (str_contains($mcp, 'bearerToken()')
            && str_contains($mcp, 'AssertionVerifier::HEADER')
            && str_contains($mcp, 'authenticateAssertion(')
            && (str_contains($mcp, '->resolveModel($bearer)')
                || (str_contains($mcp, 'CredentialKind::Bearer') && str_contains($mcp, '->resolve(')))) {
            $paths[] = 'path:MCP|Http\\Middleware\\AuthenticateMcp:store-bearer+v4.public';
        }

        if (array_diff([
            'key-selection:ArtisanBuild\\BuiltForCloud\\Hmac\\HmacSigner',
            'key-selection:ArtisanBuild\\BuiltForCloud\\Hmac\\HmacVerifier',
        ], $keySelection) === []) {
            $paths[] = 'path:HMAC|Http\\Middleware\\VerifyHmacSignature+Hmac\\HmacVerifier';
        }

        $mint = $classes['ArtisanBuild\\BuiltForCloud\\Actions\\MintCredential']['code'] ?? '';
        $complete = $classes['ArtisanBuild\\BuiltForCloud\\Actions\\CompleteAsymmetricEnrollment']['code'] ?? '';
        $asymmetricKeys = $classes['ArtisanBuild\\BuiltForCloud\\AsymmetricVerificationKeys']['code'] ?? '';
        if (str_contains($mint, 'CredentialKind::Asymmetric => $this->mintEnrollment(')
            && ! str_contains($mint, "'public_key'")
            && str_contains($mint, 'status\' => CredentialStatus::Pending')
            && str_contains($complete, 'public function __invoke(')
            && str_contains($asymmetricKeys, 'public function for(')) {
            $paths[] = 'path:asymmetric|Actions\\MintCredential::mintEnrollment+CompleteAsymmetricEnrollment+AsymmetricVerificationKeys';
        }

        $expectedEnrollmentRoutes = [
            'route:POST /bfc/asymmetric-enrollments/{application}=>ArtisanBuild\\BuiltForCloud\\Http\\Controllers\\AsymmetricEnrollments::__invoke',
            'route:POST /bfc/claim=>ArtisanBuild\\BuiltForCloud\\Http\\Controllers\\ManageOnboarding::claim',
            'route:POST /bfc/onboarding/exchange=>ArtisanBuild\\BuiltForCloud\\Http\\Controllers\\ManageOnboarding::exchange',
            'route:POST /bfc/onboarding/issue=>ArtisanBuild\\BuiltForCloud\\Http\\Controllers\\ManageOnboarding::issue',
            'route:POST /bfc/onboarding/verify=>ArtisanBuild\\BuiltForCloud\\Http\\Controllers\\ManageOnboarding::verify',
        ];
        $actualRoutes = array_values(array_filter($enrollment, static fn (string $item): bool => str_starts_with($item, 'route:')));
        sort($actualRoutes);

        if (array_diff($expectedEnrollmentRoutes, $actualRoutes) === []) {
            $paths[] = 'path:enrollment|OnboardingToken+POST:/bfc/claim,/bfc/onboarding/issue,/exchange,/verify';
        }

        $requiredSystem = [
            'enum:ArtisanBuild\\BuiltForCloud\\AuditActorType::CliOperator=cli_operator',
            'enum:ArtisanBuild\\BuiltForCloud\\SubjectType::Application=application',
            'enum:ArtisanBuild\\BuiltForCloud\\SubjectType::Installation=installation',
            'enum:ArtisanBuild\\BuiltForCloud\\SubjectType::Operator=operator',
            'command:ArtisanBuild\\BuiltForCloud\\Commands\\InstallOperatorCredentialCommand=bfc:install:operator-credential',
        ];

        if (array_diff($requiredSystem, $classification) === []) {
            $paths[] = 'path:system|SubjectType::Operator/Application/Installation+AuditActorType::CliOperator';
        }

        $provider = $routeDeclarations;
        $deviceController = $classes['ArtisanBuild\\BuiltForCloud\\Http\\Controllers\\DeviceAuthorizations']['code'] ?? '';
        $loopbackController = $classes['ArtisanBuild\\BuiltForCloud\\Http\\Controllers\\LoopbackAuthorizations']['code'] ?? '';
        $bound = $classes['ArtisanBuild\\BuiltForCloud\\BoundBearerCredentialAuthenticator']['code'] ?? '';
        $contain = $classes['ArtisanBuild\\BuiltForCloud\\Actions\\ContainCredentialAuthorizations']['code'] ?? '';

        if (str_contains($provider, "'/bfc/device-authorizations'")
            && str_contains($provider, "'/bfc/device'")
            && str_contains($provider, "'/bfc/device/token'")
            && str_contains($deviceController, 'StartDeviceAuthorization')
            && str_contains($deviceController, 'DecideDeviceAuthorization')
            && str_contains($deviceController, 'PollDeviceAuthorization')
            && str_contains($bound, 'resolveBoundBearer(')
            && str_contains($contain, 'credential_authorizations')) {
            $paths[] = 'path:device|Http\\Controllers\\DeviceAuthorizations+Actions\\StartDeviceAuthorization/DecideDeviceAuthorization/PollDeviceAuthorization+BoundBearerCredentialAuthenticator+ContainCredentialAuthorizations';
        }

        if (str_contains($provider, "'/bfc/loopback/authorize'")
            && str_contains($provider, "'/bfc/loopback/token'")
            && str_contains($loopbackController, 'StartLoopbackAuthorization')
            && str_contains($loopbackController, 'DecideLoopbackAuthorization')
            && str_contains($loopbackController, 'ExchangeLoopbackAuthorization')
            && str_contains($bound, 'resolveBoundBearer(')
            && str_contains($contain, 'credential_authorizations')) {
            $paths[] = 'path:loopback|Http\\Controllers\\LoopbackAuthorizations+Actions\\StartLoopbackAuthorization/DecideLoopbackAuthorization/ExchangeLoopbackAuthorization+BoundBearerCredentialAuthenticator+ContainCredentialAuthorizations';
        }

        return $paths;
    }

    /**
     * @param  array<string, array{code: string, imports: array<string, string>}>  $classes
     * @return list<string>
     */
    private static function authorizationPathViolations(array $classes): array
    {
        $violations = [];

        foreach ($classes as $class => $record) {
            if ($class === self::class) {
                continue;
            }

            if (str_contains($record['code'], 'CredentialAuthorizationFlow::Device')
                && str_contains($record['code'], "DB::table('credentials')->insert")) {
                $violations[] = 'rogue-device-exchange:'.$class;
            }

            if (str_contains($record['code'], 'CredentialAuthorizationFlow::Loopback')
                && str_contains($record['code'], "DB::table('credentials')")
                && str_contains($record['code'], "'secret_hash'")) {
                $violations[] = 'rogue-loopback-selector:'.$class;
            }
        }

        return $violations;
    }

    /**
     * @param  list<string>  $mechanisms
     * @param  list<string>  $lifecycle
     * @param  array<string, string>  $providerImports
     * @param  list<string>  $classification
     * @param  list<string>  $transitionMembers
     * @return list<string>
     */
    private static function transitional(
        array $mechanisms,
        array $lifecycle,
        string $providerCode,
        array $providerImports,
        array $classification,
        array $transitionMembers,
    ): array {
        $rows = [];
        $namespace = ['ArtisanBuild', 'BuiltForCloud'];
        $legacyRegistry = implode('\\', [...$namespace, implode('', ['Token', 'Registry'])]);
        $legacyMinterClass = implode('\\', [...$namespace, implode('', ['Api', 'Token', 'Minter'])]);
        $legacyAdminGate = implode('\\', [...$namespace, 'Http', 'Middleware', implode('', ['Ensure', 'Admin', 'Token'])]);

        if (in_array('resolver-service:'.$legacyRegistry, $mechanisms, true)) {
            $rows[] = 'transitional:TokenRegistry-secret-resolution-service';
        }

        $legacyMinter = implode('', ['Api', 'Token']).'('.implode('_', ['api', 'tokens']).')';
        if (in_array('minter:'.$legacyMinterClass.'=>'.$legacyMinter, $lifecycle, true)) {
            $rows[] = 'transitional:ApiTokenMinter=>'.$legacyMinter;
        }

        $legacyAlias = implode('\\.', ['bfc', 'token', 'admin']);
        if (preg_match('/aliasMiddleware\(\s*[\'\"]'.$legacyAlias.'[\'\"]\s*,\s*([A-Z][A-Za-z0-9_]*)::class\s*\)/', $providerCode, $alias) === 1
            && self::imported($providerImports, $alias[1]) === $legacyAdminGate) {
            $rows[] = 'transitional:EnsureAdminToken@'.implode('.', ['bfc', 'token', 'admin']);
        }

        foreach ([
            'enum:ArtisanBuild\\BuiltForCloud\\AuditActorType::'.implode('', ['Admin', 'Token']).'='.implode('_', ['admin', 'token']) => 'transitional:AuditActorType::'.implode('', ['Admin', 'Token']),
            'enum:ArtisanBuild\\BuiltForCloud\\Audit\\AppActorType::'.implode('', ['Legacy', 'Api', 'Token']).'='.implode('_', ['legacy', 'api', 'token']) => 'transitional:Audit\\AppActorType::'.implode('', ['Legacy', 'Api', 'Token']),
        ] as $member => $row) {
            if (in_array($member, $classification, true)) {
                $rows[] = $row;
            }
        }

        if (count($transitionMembers) === 7) {
            $rows[] = 'transitional:commands['.implode(',', $transitionMembers).']';
        }

        return $rows;
    }

    /**
     * @param  list<string>  $classification
     * @return list<string>
     */
    private static function transitionMembers(array $classification): array
    {
        $classes = [
            'FallbackTokenGenerateCommand',
            'TokenCreateCommand',
            'TokenListCommand',
            'TokenRevokeCommand',
            'TokenRevokeSelfCommand',
            'TokenRotateCommand',
            'TokenUsageCommand',
        ];

        $members = [];

        foreach ($classification as $item) {
            if (! str_starts_with($item, 'command:')) {
                continue;
            }

            foreach ($classes as $class) {
                if (str_contains($item, '\\'.$class.'=')) {
                    $members[] = $item;
                    break;
                }
            }
        }

        return $members;
    }

    /**
     * Derive middleware from literal registrations in the provider and in the
     * package route files (each read against its own imports), and from a
     * class-valued mapping method whose result is attached to a route.
     *
     * @param  array<string, array{code: string, imports: array<string, string>}>  $classes
     * @param  array<string, string>  $providerImports
     * @param  array<string, string>  $routeFiles
     * @return list<string>
     */
    private static function registeredMiddleware(array $classes, string $providerCode, array $providerImports, array $routeFiles = []): array
    {
        $middleware = [];
        $sources = [[$providerCode, $providerImports]];

        foreach ($routeFiles as $routeCode) {
            $sources[] = [$routeCode, self::imports($routeCode)];
        }

        foreach ($classes as $class => $record) {
            if (! str_starts_with($class, 'ArtisanBuild\\BuiltForCloud\\Http\\Middleware\\')
                || ! str_contains($record['code'], 'public function handle(')) {
                continue;
            }

            foreach ($sources as [$code, $imports]) {
                $spellings = [$class, '\\'.$class];

                foreach ($imports as $alias => $importedClass) {
                    if ($importedClass === $class) {
                        $spellings[] = $alias;
                    }
                }

                foreach ($spellings as $spelling) {
                    if (self::directlyRegistersMiddleware($code, $spelling)) {
                        $middleware[] = 'middleware:'.$class;
                        break 2;
                    }
                }
            }
        }

        foreach ($classes as $registrationClass => $registration) {
            preg_match_all(
                '/\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Z][A-Za-z0-9_]*)::([A-Za-z_][A-Za-z0-9_]*)\([^;]*\);[\s\S]{0,1000}?->middleware\(\s*\$\1\s*\)/',
                $registration['code'],
                $bindings,
                PREG_SET_ORDER,
            );

            foreach ($bindings as $binding) {
                $mappingClass = self::resolvedClass($registrationClass, $registration['imports'], $binding[2]);
                $mapping = $classes[$mappingClass] ?? null;

                if ($mapping === null || ! str_contains($mapping['code'], 'function '.$binding[3].'(')) {
                    continue;
                }

                preg_match_all('/=>\s*([^\s:,()]+)::class(?:\.|,)/', $mapping['code'], $mappedGates);

                foreach ($mappedGates[1] as $short) {
                    $gate = self::resolvedClass($mappingClass, $mapping['imports'], $short);

                    if (isset($classes[$gate]) && str_contains($classes[$gate]['code'], 'public function handle(')) {
                        $middleware[] = 'middleware:'.$gate;
                    }
                }
            }
        }

        return self::sortedUnique($middleware);
    }

    private static function directlyRegistersMiddleware(string $providerCode, string $short): bool
    {
        $class = preg_quote($short, '/').'::class';

        if (preg_match('/(?:aliasMiddleware|addPersistentMiddleware)\([^;]*'.$class.'/', $providerCode) === 1
            || preg_match('/(?:->|::)middleware\(\s*(?:\[[^\]]*)?'.$class.'/', $providerCode) === 1) {
            return true;
        }

        preg_match_all('/\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\[(.*?)\];/s', $providerCode, $assignments, PREG_SET_ORDER);
        $arrays = [];

        foreach ($assignments as $assignment) {
            $arrays[$assignment[1]] = $assignment[2];
        }

        foreach ($arrays as $variable => $body) {
            if (preg_match('/\b'.$class.'/', $body) === 1
                && self::middlewareArrayIsRegistered($providerCode, $variable, $arrays)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param  array<string, string>  $arrays
     * @param  list<string>  $seen
     */
    private static function middlewareArrayIsRegistered(string $providerCode, string $variable, array $arrays, array $seen = []): bool
    {
        if (in_array($variable, $seen, true)) {
            return false;
        }

        if (preg_match('/(?:->|::)middleware\([^)]*(?:\.\.\.)?\$'.preg_quote($variable, '/').'\b/', $providerCode) === 1) {
            return true;
        }

        $seen[] = $variable;

        foreach ($arrays as $parent => $body) {
            if (preg_match('/(?:\.\.\.)?\$'.preg_quote($variable, '/').'\b/', $body) === 1
                && self::middlewareArrayIsRegistered($providerCode, $parent, $arrays, $seen)) {
                return true;
            }
        }

        return false;
    }

    /** @param array<string, string> $imports */
    private static function resolvedClass(string $contextClass, array $imports, string $short): string
    {
        if (str_starts_with($short, '\\')) {
            return ltrim($short, '\\');
        }

        if (isset($imports[$short])) {
            return $imports[$short];
        }

        $separator = strrpos($contextClass, '\\');

        return $separator === false ? $short : substr($contextClass, 0, $separator).'\\'.$short;
    }

    private static function presentsSecret(string $code): bool
    {
        return str_contains($code, 'bearerToken()')
            || str_contains($code, "headers->get('Authorization')")
            || str_contains($code, "header('Authorization')")
            || str_contains($code, 'HmacEnvelope::HEADER')
            || str_contains($code, 'AssertionVerifier::HEADER');
    }

    private static function presentsStoreSecret(string $code): bool
    {
        return str_contains($code, 'bearerToken()')
            || str_contains($code, "headers->get('Authorization')")
            || str_contains($code, "header('Authorization')");
    }

    private static function readsCredentialStoreByHash(string $code): bool
    {
        return preg_match(
            '/(?:Credential::(?:query\(\)|where\s*\()|(?:DB::table|->table)\(\s*[\'\"]credentials[\'\"]\s*\))(?:(?!;).)*?[\'\"]secret_hash[\'\"]/s',
            $code,
        ) === 1;
    }

    /**
     * @param  array<string, string>  $imports
     * @return list<string>
     */
    private static function resolutionDependencies(string $gate, string $code, array $imports): array
    {
        preg_match_all('/(?:private|protected|public)\s+(?:readonly\s+)?([A-Z][A-Za-z0-9_]*)\s+\$([A-Za-z_][A-Za-z0-9_]*)/', $code, $constructorTypes, PREG_SET_ORDER);
        preg_match_all('/app\(\s*([A-Z][A-Za-z0-9_]*)::class\s*\)\s*->\s*(?:resolve|resolveModel|verify)\s*\(/', $code, $locatedTypes);
        $dependencies = [];
        $separator = strrpos($gate, '\\');
        $namespace = $separator === false ? '' : substr($gate, 0, $separator);

        foreach ($constructorTypes as $constructorType) {
            if (preg_match('/\$this\s*->\s*'.preg_quote($constructorType[2], '/').'\s*->\s*(?:resolve|resolveModel|verify)\s*\(/', $code) !== 1) {
                continue;
            }

            $short = $constructorType[1];
            $dependency = $imports[$short] ?? ($namespace === '' ? $short : $namespace.'\\'.$short);

            if (self::isResolutionService($dependency)) {
                $dependencies[] = $dependency;
            }
        }

        foreach ($locatedTypes[1] as $short) {
            $dependency = $imports[$short] ?? ($namespace === '' ? $short : $namespace.'\\'.$short);

            if (self::isResolutionService($dependency)) {
                $dependencies[] = $dependency;
            }
        }

        return array_values(array_unique($dependencies));
    }

    private static function isResolutionService(string $class): bool
    {
        return str_ends_with($class, 'Resolver')
            || str_ends_with($class, 'Verifier')
            || str_ends_with($class, 'Registry');
    }

    private static function readsSecondCredentialStore(string $code): bool
    {
        preg_match_all(
            '/(?<![A-Za-z0-9_\x5c])(\x5c?[A-Z][A-Za-z0-9_\x5c]*)::(?:query\(\)|where\s*\(|firstWhere\s*\()/s',
            $code,
            $modelQueries,
        );

        foreach ($modelQueries[1] as $model) {
            $model = ltrim($model, '\\');
            $resolved = self::imports($code)[$model] ?? $model;

            if (! in_array($resolved, [
                'Credential',
                'ArtisanBuild\\BuiltForCloud\\Credential',
                'ArtisanBuild\\BuiltForCloud\\CredentialProtocolBinding',
            ], true)) {
                return true;
            }
        }

        preg_match_all(
            '/(DB::connection\([^;]+?\)->table|DB::table|->table)\(\s*[\'"]([^\'"]+)[\'"]\s*\)/s',
            $code,
            $tableQueries,
            PREG_SET_ORDER,
        );

        foreach ($tableQueries as $query) {
            if ($query[2] !== 'credentials' || str_contains($query[1], 'connection(')) {
                return true;
            }
        }

        preg_match_all(
            '/DB::(?:select|selectOne)\(\s*([\'"])(.*?)\1/s',
            $code,
            $rawQueries,
            PREG_SET_ORDER,
        );

        foreach ($rawQueries as $query) {
            if (preg_match('/\bfrom\s+[`"]?([A-Za-z0-9_.-]+)/i', $query[2], $table) === 1
                && $table[1] !== 'credentials') {
                return true;
            }
        }

        return self::readsSecondCredentialStoreByHash($code);
    }

    private static function readsSecondCredentialStoreByHash(string $code): bool
    {
        preg_match_all(
            '/\b([A-Z][A-Za-z0-9_]*)::query\(\)(?:(?!;).)*?->where\(\s*[\'\"](?:secret_hash|token_hash)[\'\"]/s',
            $code,
            $modelQueries,
        );

        foreach ($modelQueries[1] as $model) {
            if ($model !== 'Credential') {
                return true;
            }
        }

        preg_match_all(
            '/(?:DB::table|->table)\(\s*[\'\"]([^\'\"]+)[\'\"]\s*\)(?:(?!;).)*?->where\(\s*[\'\"](?:secret_hash|token_hash)[\'\"]/s',
            $code,
            $tableQueries,
        );

        foreach ($tableQueries[1] as $table) {
            if ($table !== 'credentials') {
                return true;
            }
        }

        return false;
    }

    /**
     * @param  array<string, array{code: string, imports: array<string, string>}>  $classes
     * @return list<string>
     */
    private static function implementations(array $classes, string $interface): array
    {
        $implementations = [];

        foreach ($classes as $class => $record) {
            if (preg_match('/\bimplements\s+[^\{]*\b'.preg_quote($interface, '/').'\b/', $record['code']) === 1) {
                $implementations[] = $class;
            }
        }

        sort($implementations);

        return $implementations;
    }

    /**
     * @param  array<string, string>  $files
     * @return array<string, array{code: string, imports: array<string, string>}>
     */
    private static function classes(array $files): array
    {
        $classes = [];

        foreach ($files as $code) {
            if (preg_match('/^namespace\s+([^;]+);/m', $code, $namespace) !== 1
                || preg_match('/\b(?:final\s+|abstract\s+)?(?:readonly\s+)?(?:class|enum|interface|trait)\s+([A-Z][A-Za-z0-9_]*)\b/', $code, $class) !== 1) {
                continue;
            }

            $classes[$namespace[1].'\\'.$class[1]] = [
                'code' => $code,
                'imports' => self::imports($code),
            ];
        }

        return $classes;
    }

    /**
     * The package's route files beside the scanned source root (routes/*.php),
     * comments removed, keyed so they never collide with a source file key.
     * They hold the route declarations the provider used to carry.
     *
     * @return array<string, string>
     */
    private static function routeFiles(string $sourceRoot): array
    {
        $files = [];

        foreach (glob(dirname($sourceRoot).'/routes/*.php') ?: [] as $path) {
            $files['routes:'.basename($path)] = self::withoutComments(self::requiredContents($path));
        }

        return $files;
    }

    /**
     * @param  list<string>  $roots
     * @return array<string, string>
     */
    private static function sourceFiles(array $roots): array
    {
        $files = [];

        foreach ($roots as $rootIndex => $root) {
            foreach (self::phpFiles($root) as $relativePath => $file) {
                $contents = file_get_contents($file->getPathname());

                if (! is_string($contents)) {
                    throw new RuntimeException("Could not read [{$file->getPathname()}].");
                }

                $files[$rootIndex.':'.$relativePath] = self::withoutComments($contents);
            }
        }

        return $files;
    }

    /** @return array<string, string> */
    private static function imports(string $contents): array
    {
        preg_match_all('/^use\s+([^;]+);$/m', $contents, $matches);
        $imports = [];

        foreach ($matches[1] as $declaration) {
            foreach (self::expandedImports($declaration) as $class) {
                if (str_starts_with($class, 'function ') || str_starts_with($class, 'const ')) {
                    continue;
                }

                $parts = preg_split('/\s+as\s+/i', trim($class));
                $target = ltrim($parts[0], '\\');
                $alias = $parts[1] ?? self::shortName($target);
                $imports[$alias] = $target;
            }
        }

        return $imports;
    }

    /** @return list<string> */
    private static function expandedImports(string $declaration): array
    {
        $open = strpos($declaration, '{');

        if ($open === false) {
            return array_map('trim', explode(',', $declaration));
        }

        $close = strrpos($declaration, '}');

        if ($close === false) {
            return [];
        }

        $prefix = rtrim(trim(substr($declaration, 0, $open)), '\\').'\\';
        $members = explode(',', substr($declaration, $open + 1, $close - $open - 1));

        return array_map(static fn (string $member): string => $prefix.trim($member), $members);
    }

    /** @param array<string, string> $imports */
    private static function imported(array $imports, string $short): string
    {
        return $imports[$short] ?? throw new RuntimeException("Could not resolve imported class [{$short}].");
    }

    private static function shortName(string $class): string
    {
        $separator = strrpos($class, '\\');

        return $separator === false ? $class : substr($class, $separator + 1);
    }

    private static function requiredContents(string $path): string
    {
        $contents = file_get_contents($path);

        return is_string($contents) ? $contents : throw new RuntimeException("Could not read [{$path}].");
    }

    private static function withoutComments(string $contents): string
    {
        return implode('', array_map(
            static fn (array|string $token): string => is_string($token)
                ? $token
                : (in_array($token[0], [T_COMMENT, T_DOC_COMMENT], true) ? ' ' : $token[1]),
            token_get_all($contents, TOKEN_PARSE),
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

    /** @return iterable<string, SplFileInfo> */
    private static function phpFiles(string $root): iterable
    {
        $files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
        );

        /** @var SplFileInfo $file */
        foreach ($files as $file) {
            if ($file->isFile() && $file->getExtension() === 'php') {
                yield substr($file->getPathname(), strlen($root) + 1) => $file;
            }
        }
    }
}
