<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use ArtisanBuild\BuiltForCloud\SubjectType;
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
 * from installed PHP source. The frozen eight-path and transitional oracles
 * deliberately live in the test, not here, so discovery cannot edit its own
 * expected answer. P5-AC12 can run this same scanner after removal unchanged.
 *
 * This is source classification, not whole-program data-flow analysis. It
 * cannot see dynamic class names, container bindings assembled outside the
 * provider, routes registered through an unknown wrapper, runtime rebinding,
 * direct model writes, host code or non-PHP generated code. The device path is
 * honestly partial: no enrollment verifier exists, so this scanner derives
 * only the declared composition over ExternalConsumer and Installation. Four
 * fixture controls prove the ordinary bypass, second-store resolver, extra
 * enrollment-route and out-of-pair device shapes this instrument claims to
 * report; deliberately hidden dynamic equivalents remain review/P6 concerns.
 */
final class CredentialPathInventory
{
    /**
     * The source declaration for the partial device composition. It does not
     * create an enrollment protocol; it gives the otherwise conceptual row an
     * executable, enumerable pair while R1 owns completion.
     */
    private const array DEVICE_SUBJECT_TYPES = [
        SubjectType::ExternalConsumer,
        SubjectType::Installation,
    ];

    /**
     * @param  list<string>  $additionalRoots
     * @return array{
     *   mechanisms: list<string>,
     *   lifecycle: list<string>,
     *   enrollment: list<string>,
     *   classification: list<string>,
     *   key_selection: list<string>,
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

        $authenticators = self::implementations($classes, 'CredentialAuthenticator');
        $minters = self::implementations($classes, 'DurableCredentialMinter');
        $middleware = [];

        foreach ($providerImports as $class) {
            if (str_starts_with($class, 'ArtisanBuild\\BuiltForCloud\\Http\\Middleware\\')
                && str_contains($providerCode, self::shortName($class).'::class')) {
                $middleware[] = 'middleware:'.$class;
            }
        }

        preg_match_all(
            '/\$auth->extend\((?:(?!\$auth->extend).)*?return\s+new\s+([A-Z][A-Za-z0-9_]*)\s*\(/s',
            $providerCode,
            $guardMatches,
        );

        $mechanisms = [
            'resolver:ArtisanBuild\\BuiltForCloud\\Auth\\CredentialResolver',
            'key-sink:ArtisanBuild\\BuiltForCloud\\Hmac\\HmacSigner',
            'key-sink:ArtisanBuild\\BuiltForCloud\\Hmac\\HmacVerifier',
        ];

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
        $violations = [];

        foreach ($presentedGates as $gate) {
            $record = $classes[$gate] ?? null;

            if ($record === null || ! self::presentsSecret($record['code'])) {
                continue;
            }

            $dependencies = self::resolutionDependencies($gate, $record['code'], $record['imports']);

            foreach ($dependencies as $dependency) {
                $mechanisms[] = 'resolver-service:'.$dependency;
                $dependencyCode = $classes[$dependency]['code'] ?? '';

                if ($dependency !== 'ArtisanBuild\\BuiltForCloud\\TokenRegistry'
                    && self::readsLegacyStore($dependencyCode)) {
                    $violations[] = 'second-store-resolver:'.$gate.'=>'.$dependency;
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
        $enrollment = self::enrollment($files, $providerImports);
        $classification = self::classification($classes, $providerCode, $providerImports);
        $keySelection = self::keySelection($classes);
        $deviceSubjects = self::deviceSubjects($files);
        $transitionMembers = self::transitionMembers($classification);

        foreach (self::DEVICE_SUBJECT_TYPES as $subjectType) {
            $declared = 'device-subject:'.SubjectType::class.'::'.$subjectType->name;

            if (! in_array($declared, $deviceSubjects, true)) {
                $violations[] = 'undiscovered-device-declaration:'.$declared;
            }
        }

        $paths = self::paths(
            $classes,
            $authenticators,
            $enrollment,
            $classification,
            $keySelection,
            $deviceSubjects,
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

        foreach ($deviceSubjects as $subject) {
            if (! in_array($subject, [
                'device-subject:ArtisanBuild\\BuiltForCloud\\SubjectType::ExternalConsumer',
                'device-subject:ArtisanBuild\\BuiltForCloud\\SubjectType::Installation',
            ], true)) {
                $violations[] = 'out-of-pair-device-composition:'.$subject;
            }
        }

        $mechanisms = self::sortedUnique($mechanisms);
        $lifecycle = self::sortedUnique($lifecycle);
        $enrollment = self::sortedUnique($enrollment);
        $classification = self::sortedUnique($classification);
        $keySelection = self::sortedUnique($keySelection);
        $paths = self::sortedUnique($paths);
        $transitional = self::sortedUnique($transitional);
        $transitionMembers = self::sortedUnique($transitionMembers);
        $violations = self::sortedUnique($violations);

        return [
            'mechanisms' => $mechanisms,
            'lifecycle' => $lifecycle,
            'enrollment' => $enrollment,
            'classification' => $classification,
            'key_selection' => $keySelection,
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
            $target = str_contains($code, 'Credential::query()->create')
                ? 'Credential(credentials)'
                : (str_contains($code, 'TokenRegistry') && str_contains($code, '->store(')
                    ? 'ApiToken(api_tokens)'
                    : 'unknown');
            $items[] = 'minter:'.$minter.'=>'.$target;
        }

        return $items;
    }

    /**
     * @param  array<string, string>  $files
     * @param  array<string, string>  $providerImports
     * @return list<string>
     */
    private static function enrollment(array $files, array $providerImports): array
    {
        $items = [];

        foreach ($files as $code) {
            preg_match_all(
                '/\$router->(get|post|put|patch|delete)\(\s*[\'\"]([^\'\"]+)[\'\"]\s*,\s*\[\s*([A-Z][A-Za-z0-9_]*)::class\s*,\s*[\'\"]([^\'\"]+)[\'\"]\s*\]/i',
                $code,
                $routes,
                PREG_SET_ORDER,
            );

            foreach ($routes as $route) {
                $controller = $providerImports[$route[3]] ?? $route[3];

                if ($controller === 'ArtisanBuild\\BuiltForCloud\\Http\\Controllers\\ManageOnboarding') {
                    $items[] = 'route:'.strtoupper($route[1]).' '.$route[2].'=>'.$controller.'::'.$route[4];
                }
            }
        }

        $items[] = 'model:ArtisanBuild\\BuiltForCloud\\OnboardingToken';

        return $items;
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

        return $items;
    }

    /**
     * @param  array<string, array{code: string, imports: array<string, string>}>  $classes
     * @param  list<string>  $authenticators
     * @param  list<string>  $enrollment
     * @param  list<string>  $classification
     * @param  list<string>  $keySelection
     * @param  list<string>  $deviceSubjects
     * @return list<string>
     */
    private static function paths(
        array $classes,
        array $authenticators,
        array $enrollment,
        array $classification,
        array $keySelection,
        array $deviceSubjects,
    ): array {
        $paths = [];

        foreach ($authenticators as $authenticator) {
            $code = $classes[$authenticator]['code'];

            if (preg_match('/CredentialKind::(Basic|Bearer)/', $code, $kind) === 1
                && str_contains($code, 'CredentialResolver')) {
                $paths[] = sprintf(
                    'path:%s|%s|CredentialKind::%s+secret_hash|CredentialResolver::resolve',
                    $kind[1],
                    $authenticator,
                    $kind[1],
                );
            }
        }

        $mcp = $classes['ArtisanBuild\\BuiltForCloud\\Http\\Middleware\\AuthenticateMcp']['code'] ?? '';
        if (str_contains($mcp, 'TokenRegistry') && str_contains($mcp, 'AssertionVerifier')) {
            $paths[] = 'path:MCP|Http\\Middleware\\AuthenticateMcp:store-bearer+v4.public|CredentialKind::Bearer/DelegatedActor|TokenRegistry::resolveModel/AssertionVerifier+ConsoleKeyring';
        }

        if ($keySelection === [
            'key-selection:ArtisanBuild\\BuiltForCloud\\Hmac\\HmacSigner',
            'key-selection:ArtisanBuild\\BuiltForCloud\\Hmac\\HmacVerifier',
        ]) {
            $paths[] = 'path:HMAC|Http\\Middleware\\VerifyHmacSignature+Hmac\\HmacVerifier|CredentialKind::Hmac+secret_ciphertext+secret_key_version|HmacVerifier::verify';
        }

        $mint = $classes['ArtisanBuild\\BuiltForCloud\\Actions\\MintCredential']['code'] ?? '';
        if (str_contains($mint, 'CredentialKind::Asymmetric => $this->mintEnrollment(')
            && ! str_contains($mint, "'public_key'")
            && str_contains($mint, 'status\' => CredentialStatus::Pending')) {
            $paths[] = 'path:asymmetric|Actions\\MintCredential::mintEnrollment|CredentialKind::Asymmetric+public_key:null|no-verifier';
        }

        $expectedEnrollmentRoutes = [
            'route:POST /bfc/claim=>ArtisanBuild\\BuiltForCloud\\Http\\Controllers\\ManageOnboarding::claim',
            'route:POST /bfc/onboarding/exchange=>ArtisanBuild\\BuiltForCloud\\Http\\Controllers\\ManageOnboarding::exchange',
            'route:POST /bfc/onboarding/issue=>ArtisanBuild\\BuiltForCloud\\Http\\Controllers\\ManageOnboarding::issue',
            'route:POST /bfc/onboarding/verify=>ArtisanBuild\\BuiltForCloud\\Http\\Controllers\\ManageOnboarding::verify',
        ];
        $actualRoutes = array_values(array_filter($enrollment, static fn (string $item): bool => str_starts_with($item, 'route:')));
        sort($actualRoutes);

        if (array_diff($expectedEnrollmentRoutes, $actualRoutes) === []) {
            $paths[] = 'path:enrollment|OnboardingToken+POST:/bfc/claim,/bfc/onboarding/issue,/exchange,/verify|DeliveryShape::EnrollmentCode|CredentialResolver::resolve-after-exchange';
        }

        if ($deviceSubjects === [
            'device-subject:ArtisanBuild\\BuiltForCloud\\SubjectType::ExternalConsumer',
            'device-subject:ArtisanBuild\\BuiltForCloud\\SubjectType::Installation',
        ]) {
            $paths[] = 'path:device|enrollment+(external_consumer,installation)|DeliveryShape::EnrollmentCode|as-enrollment-partial';
        }

        $requiredSystem = [
            'enum:ArtisanBuild\\BuiltForCloud\\AuditActorType::CliOperator=cli_operator',
            'enum:ArtisanBuild\\BuiltForCloud\\SubjectType::Application=application',
            'enum:ArtisanBuild\\BuiltForCloud\\SubjectType::Installation=installation',
            'enum:ArtisanBuild\\BuiltForCloud\\SubjectType::Operator=operator',
            'command:ArtisanBuild\\BuiltForCloud\\Commands\\InstallOperatorCredentialCommand=bfc:install:operator-credential',
        ];

        if (array_diff($requiredSystem, $classification) === []) {
            $paths[] = 'path:system|SubjectType::Operator/Application/Installation+AuditActorType::CliOperator|CredentialKind::Bearer/Basic|CredentialResolver::resolve';
        }

        return $paths;
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

        if (in_array('resolver-service:ArtisanBuild\\BuiltForCloud\\TokenRegistry', $mechanisms, true)) {
            $rows[] = 'transitional:TokenRegistry-secret-resolution-service';
        }

        if (in_array('minter:ArtisanBuild\\BuiltForCloud\\ApiTokenMinter=>ApiToken(api_tokens)', $lifecycle, true)) {
            $rows[] = 'transitional:ApiTokenMinter=>ApiToken(api_tokens)';
        }

        if (preg_match('/aliasMiddleware\(\s*[\'\"]bfc\.token\.admin[\'\"]\s*,\s*([A-Z][A-Za-z0-9_]*)::class\s*\)/', $providerCode, $alias) === 1
            && self::imported($providerImports, $alias[1]) === 'ArtisanBuild\\BuiltForCloud\\Http\\Middleware\\EnsureAdminToken') {
            $rows[] = 'transitional:EnsureAdminToken@bfc.token.admin';
        }

        foreach ([
            'enum:ArtisanBuild\\BuiltForCloud\\AuditActorType::AdminToken=admin_token' => 'transitional:AuditActorType::AdminToken',
            'enum:ArtisanBuild\\BuiltForCloud\\Audit\\AppActorType::LegacyApiToken=legacy_api_token' => 'transitional:Audit\\AppActorType::LegacyApiToken',
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
     * @param  array<string, string>  $files
     * @return list<string>
     */
    private static function deviceSubjects(array $files): array
    {
        $subjects = [];

        foreach ($files as $code) {
            if (preg_match('/DEVICE_SUBJECT_TYPES\s*=\s*\[(.*?)\]/s', $code, $declaration) !== 1) {
                continue;
            }

            preg_match_all('/SubjectType::([A-Za-z_][A-Za-z0-9_]*)/', $declaration[1], $cases);

            foreach ($cases[1] as $case) {
                $subjects[] = 'device-subject:ArtisanBuild\\BuiltForCloud\\SubjectType::'.$case;
            }
        }

        $subjects = array_values(array_unique($subjects));
        sort($subjects);

        return $subjects;
    }

    private static function presentsSecret(string $code): bool
    {
        return str_contains($code, 'bearerToken()')
            || str_contains($code, "headers->get('Authorization')")
            || str_contains($code, 'HmacEnvelope::HEADER')
            || str_contains($code, 'AssertionVerifier::HEADER');
    }

    /**
     * @param  array<string, string>  $imports
     * @return list<string>
     */
    private static function resolutionDependencies(string $gate, string $code, array $imports): array
    {
        preg_match_all('/(?:private|protected|public)\s+(?:readonly\s+)?([A-Z][A-Za-z0-9_]*)\s+\$[A-Za-z_][A-Za-z0-9_]*/', $code, $constructorTypes);
        preg_match_all('/app\(\s*([A-Z][A-Za-z0-9_]*)::class\s*\)\s*->\s*(?:resolve|resolveModel|verify)\s*\(/', $code, $locatedTypes);
        $dependencies = [];
        $separator = strrpos($gate, '\\');
        $namespace = $separator === false ? '' : substr($gate, 0, $separator);

        foreach ([...$constructorTypes[1], ...$locatedTypes[1]] as $short) {
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

    private static function readsLegacyStore(string $code): bool
    {
        return str_contains($code, 'ApiToken::') || str_contains($code, "'api_tokens'") || str_contains($code, '"api_tokens"');
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

        foreach ($matches[1] as $class) {
            if (str_contains($class, '{') || str_contains($class, ' function ') || str_contains($class, ' const ')) {
                continue;
            }

            $parts = preg_split('/\s+as\s+/i', trim($class));
            $target = $parts[0];
            $alias = $parts[1] ?? self::shortName($target);
            $imports[$alias] = $target;
        }

        return $imports;
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
