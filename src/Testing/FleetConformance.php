<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use ArtisanBuild\BuiltForCloud\AppPurposeRegistry;
use ArtisanBuild\BuiltForCloud\BuiltForCloud;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;
use Throwable;

final readonly class FleetConformance
{
    /** @var array<string, list<string>> */
    private const array LIMITS = [
        'credential_paths' => [
            'literal PHP declarations, registrations, dependencies, calls, routes, and selectors only',
            'dynamic bindings, generated code, and whole-program data flow are not established',
        ],
        'credential_writers' => CredentialWriterInventory::LIMITS,
        'legacy_removal' => [
            'literal shipped PHP symbols, keys, routes, and named public documents only',
            'dynamic identifiers and whole-program absence are not established',
        ],
        'system_authority' => [
            'explicit provider command lists, loaded queue interfaces, and attributable schedules only',
            'dynamic registration, helper indirection, and transitive calls are not established',
        ],
        'no_signing_path' => [
            'literal PHP signing calls and Paseto signing-key class references only',
            'dynamic calls, generated code, and whole-program absence are not established',
        ],
        'ui_config_reads' => [
            'literal supported config read syntax in PHP only',
            'dynamic keys, wrappers, templates, caches, and data flow are not established',
        ],
        'thin_host' => [
            'conventional application paths and live auth configuration only',
            'arbitrary indirect authentication implementations are not established',
        ],
        'mcp_delegated' => [
            'currently eligible registered tools and serialized declarations only',
            'absent tools, response bodies, and semantic honesty are not established',
        ],
    ];

    public function __construct(private object $testCase) {}

    public function inspect(ConsumerConformance $spec): ConformanceReport
    {
        $families = [];

        foreach (ConsumerConformance::FAMILIES as $family) {
            $families[$family] = str_starts_with($family, 'runtime.')
                ? $this->runtimeFamily($family, $spec)
                : $this->scannerFamily($family, $spec);
        }

        $passed = true;
        foreach ($families as $family) {
            if ($family->violations !== []) {
                $passed = false;
                break;
            }
        }

        return new ConformanceReport(
            $spec->consumer,
            BuiltForCloud::API_VERSION,
            $passed,
            $families,
        );
    }

    public function assert(ConsumerConformance $spec): ConformanceReport
    {
        $report = $this->inspect($spec);

        if (! $report->passed) {
            throw new ConformanceFailed($report);
        }

        return $report;
    }

    private function runtimeFamily(string $family, ConsumerConformance $spec): ConformanceFamilyReport
    {
        $assertion = substr($family, strlen('runtime.'));

        if (! in_array($assertion, $spec->runtimeAssertions, true)) {
            return new ConformanceFamilyReport('not_applicable', 'not_declared', 0, $spec->expected[$family], [], [], []);
        }

        $violations = [];

        try {
            match ($assertion) {
                'meta' => $this->assertMeta($spec),
                'auth_schema' => $this->assertAuthSchema($spec),
                'credential_listing' => $this->callAssertion('assertBuiltForCloudCredentialListingContract'),
                'transport_parity' => $this->callAssertion('assertBuiltForCloudTransportParityContract'),
            };
        } catch (Throwable) {
            $violations[] = 'assertion-failed:'.$family;
        }

        return $this->applicable($spec->expected[$family], [], $violations, 1, []);
    }

    private function assertMeta(ConsumerConformance $spec): void
    {
        $this->callAssertion('assertBuiltForCloudMetaContract');
        $response = $this->testCase->getJson('/bfc/meta')->assertOk();
        $capabilities = $response->json('capabilities');

        if (! is_array($capabilities)
            || array_diff($spec->capabilities, array_filter($capabilities, 'is_string')) !== []) {
            throw new \RuntimeException('A required capability predicate is not observable.');
        }

        $registry = app(AppPurposeRegistry::class);
        foreach ($spec->purposeMappings as $appPurpose => $purpose) {
            if ($registry->purpose($appPurpose) !== $purpose) {
                throw new \RuntimeException('A purpose mapping does not resolve canonically.');
            }
        }
    }

    private function assertAuthSchema(ConsumerConformance $spec): void
    {
        $this->callAssertion('assertBuiltForCloudOwnershipAuthContract');
        $this->callAssertion('assertBuiltForCloudOnboardingAuthContract');
        $this->callAssertion('assertBuiltForCloudModelContract');
        $this->callAssertion('assertBuiltForCloudHumanIdentityContract');
        $this->callAssertion('assertBuiltForCloudHumanLifecycleContract');

        $this->callAssertion('assertBuiltForCloudThinHostSources', [$spec->consumerRoot]);
    }

    /** @param list<mixed> $arguments */
    private function callAssertion(string $method, array $arguments = []): mixed
    {
        if (! method_exists($this->testCase, $method)) {
            throw new \RuntimeException('The consuming test case does not use ContractAssertions.');
        }

        return $this->testCase->{$method}(...$arguments);
    }

    private function scannerFamily(string $family, ConsumerConformance $spec): ConformanceFamilyReport
    {
        if ($family === 'mcp_delegated' && ! in_array('mcp-delegated', $spec->capabilities, true)) {
            return new ConformanceFamilyReport(
                'not_applicable',
                'capability_not_declared',
                0,
                $spec->expected[$family],
                [],
                [],
                self::LIMITS[$family],
            );
        }

        try {
            [$discovered, $violations, $visited] = match ($family) {
                'thin_host' => $this->thinHost($spec),
                'credential_paths' => $this->credentialPaths($spec),
                'credential_writers' => $this->credentialWriters($spec),
                'legacy_removal' => $this->legacyRemoval($spec),
                'system_authority' => $this->systemAuthority($spec),
                'no_signing_path' => $this->noSigningPath($spec),
                'ui_config_reads' => $this->uiConfigReads($spec),
                'mcp_delegated' => $this->mcpDelegated($spec),
            };
        } catch (Throwable) {
            $discovered = [];
            $violations = ['scanner-execution-failed:'.$family];
            $visited = 0;
        }

        return $this->applicable(
            $spec->expected[$family],
            $this->identities($discovered, $spec),
            $this->identities($violations, $spec),
            $visited,
            self::LIMITS[$family],
        );
    }

    /** @return array{list<string>, list<string>, int} */
    private function thinHost(ConsumerConformance $spec): array
    {
        $members = [];
        $visited = 0;

        $visited = $this->phpFileCount($spec->consumerRoot);
        foreach (ThinHostConformance::sourceArtifacts($spec->consumerRoot) as $path => $kind) {
            $members[] = 'consumer/'.$path.'|'.$kind;
        }

        return [$members, $members, $visited];
    }

    /** @return array{list<string>, list<string>, int} */
    private function credentialPaths(ConsumerConformance $spec): array
    {
        $inventory = CredentialPathInventory::discover($spec->packageRoot.'/src', $spec->sourceRoots);
        $purpose = CredentialPathInventory::comparePurposePolicy($spec->packageRoot.'/src', $spec->sourceRoots);

        return [
            [...$inventory['paths'], ...$inventory['transitional']],
            [...$inventory['violations'], ...$purpose['violations']],
            $this->visited($spec),
        ];
    }

    /** @return array{list<string>, list<string>, int} */
    private function credentialWriters(ConsumerConformance $spec): array
    {
        $inventory = CredentialWriterInventory::discover($spec->packageRoot.'/src', $spec->sourceRoots);

        return [
            array_map(static fn (array $writer): string => $writer['member'], $inventory['writers']),
            $inventory['violations'],
            $this->visited($spec),
        ];
    }

    /** @return array{list<string>, list<string>, int} */
    private function legacyRemoval(ConsumerConformance $spec): array
    {
        $offences = [
            ...LegacyRemovalInventory::productionOffences($spec->packageRoot),
            ...LegacyRemovalInventory::publicDocumentOffences($spec->packageRoot),
        ];

        foreach ($spec->sourceRoots as $root) {
            foreach (LegacyRemovalInventory::sourceOffences($root) as $offence) {
                $offences[] = $this->rootIdentity($root, $spec).'/'.$offence;
            }
        }

        return [$offences, $offences, $this->visited($spec)];
    }

    /** @return array{list<string>, list<string>, int} */
    private function systemAuthority(ConsumerConformance $spec): array
    {
        $inventory = SystemAuthorityInventory::discover(
            $spec->providerFiles,
            [$spec->packageRoot.'/src', ...$spec->sourceRoots],
        );

        return [
            [...$inventory['commands'], ...$inventory['queued'], ...$inventory['scheduled']],
            [...$inventory['violations']['commands'], ...$inventory['violations']['queued'], ...$inventory['violations']['scheduled']],
            $this->visited($spec),
        ];
    }

    /** @return array{list<string>, list<string>, int} */
    private function noSigningPath(ConsumerConformance $spec): array
    {
        $offences = [];
        $visited = 0;

        foreach ([$spec->packageRoot.'/src', ...$spec->sourceRoots] as $root) {
            $visited += NoSigningPathScan::countPhpFiles($root);
            foreach (NoSigningPathScan::scan($root) as $path => $rules) {
                foreach ($rules as $rule) {
                    $offences[] = $this->rootIdentity($root, $spec).'/'.$path.'|'.$rule;
                }
            }
        }

        return [$offences, $offences, $visited];
    }

    /** @return array{list<string>, list<string>, int} */
    private function uiConfigReads(ConsumerConformance $spec): array
    {
        $reads = [];
        $violations = [];
        $visited = 0;

        foreach ([$spec->packageRoot.'/src', ...$spec->sourceRoots] as $root) {
            $visited += UiConfigReadScan::countPhpFiles($root);
            array_push($reads, ...UiConfigReadScan::discoverPublishedConfiguration($root));
        }

        try {
            UiConfigReadScan::assertPublishedConfigurationDispositions(
                $spec->packageRoot.'/src',
                $spec->sourceRoots,
            );
        } catch (Throwable) {
            $violations[] = 'published-configuration-dispositions';
        }

        return [$reads, $violations, $visited];
    }

    /** @return array{list<string>, list<string>, int} */
    private function mcpDelegated(ConsumerConformance $spec): array
    {
        $server = $spec->mcpServer ?? throw new \RuntimeException('Missing MCP server.');
        $inventory = McpDelegatedTools::discover($server);

        try {
            McpDelegatedTools::assertConforms($server);
        } catch (Throwable) {
            $inventory['violations'][] = 'mcp-delegated-conformance';
        }

        return [$inventory['tools'], $inventory['violations'], count($inventory['tools'])];
    }

    /**
     * @param  list<string>  $expected
     * @param  list<string>  $discovered
     * @param  list<string>  $violations
     * @param  list<string>  $limits
     */
    private function applicable(array $expected, array $discovered, array $violations, int $visited, array $limits): ConformanceFamilyReport
    {
        $discovered = $this->sortedUnique($discovered);

        foreach (array_diff($expected, $discovered) as $missing) {
            $violations[] = 'missing:'.$missing;
        }

        foreach (array_diff($discovered, $expected) as $unexpected) {
            $violations[] = 'unexpected:'.$unexpected;
        }

        if ($visited === 0) {
            $violations[] = 'zero-visitation';
        }

        return new ConformanceFamilyReport(
            'applicable',
            null,
            max(0, $visited),
            $expected,
            $discovered,
            $this->sortedUnique($violations),
            $this->sortedUnique($limits),
        );
    }

    /** @param list<string> $members
     * @return list<string>
     */
    private function identities(array $members, ConsumerConformance $spec): array
    {
        return array_map(function (string $member) use ($spec): string {
            foreach ([$spec->packageRoot => 'package', $spec->consumerRoot => 'consumer'] as $root => $label) {
                $resolved = realpath($root);
                if (is_string($resolved)) {
                    $member = str_replace([$root, $resolved], $label, $member);
                }
            }

            return $member;
        }, $members);
    }

    private function rootIdentity(string $root, ConsumerConformance $spec): string
    {
        $resolved = (string) realpath($root);
        $package = (string) realpath($spec->packageRoot);
        $consumer = (string) realpath($spec->consumerRoot);

        if ($resolved === $package || str_starts_with($resolved, $package.DIRECTORY_SEPARATOR)) {
            return 'package'.substr($resolved, strlen($package));
        }

        return 'consumer'.substr($resolved, strlen($consumer));
    }

    private function visited(ConsumerConformance $spec): int
    {
        return $this->phpFileCount($spec->packageRoot.'/src')
            + array_sum(array_map($this->phpFileCount(...), $spec->sourceRoots));
    }

    private function phpFileCount(string $root): int
    {
        $count = 0;
        foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root)) as $file) {
            if ($file instanceof SplFileInfo && $file->isFile() && $file->getExtension() === 'php') {
                $count++;
            }
        }

        return $count;
    }

    /** @param list<string> $values
     * @return list<string>
     */
    private function sortedUnique(array $values): array
    {
        $values = array_values(array_unique($values));
        sort($values);

        return $values;
    }
}
