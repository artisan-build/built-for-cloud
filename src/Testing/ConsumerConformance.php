<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use InvalidArgumentException;
use Laravel\Mcp\Server;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

final readonly class ConsumerConformance
{
    /** @var list<string> */
    public const array RUNTIME_ASSERTIONS = ['auth_schema', 'credential_listing', 'meta', 'transport_parity'];

    /** @var list<string> */
    public const array FAMILIES = [
        'runtime.meta',
        'runtime.auth_schema',
        'runtime.credential_listing',
        'runtime.transport_parity',
        'thin_host',
        'credential_paths',
        'credential_writers',
        'legacy_removal',
        'system_authority',
        'no_signing_path',
        'ui_config_reads',
        'mcp_delegated',
    ];

    /** @var array<string, list<string>> */
    public array $expected;

    /**
     * @param  list<string>  $sourceRoots
     * @param  list<string>  $providerFiles
     * @param  list<string>  $runtimeAssertions
     * @param  list<string>  $capabilities
     * @param  array<string, CredentialPurpose>  $purposeMappings
     * @param  class-string<Server>|null  $mcpServer
     * @param  array<string, list<string>>  $expected
     */
    public function __construct(
        public string $consumer,
        public string $consumerRoot,
        public string $packageRoot,
        public array $sourceRoots,
        public array $providerFiles,
        public array $runtimeAssertions,
        public array $capabilities,
        public array $purposeMappings,
        public ?string $mcpServer,
        array $expected,
    ) {
        if ($consumer === '') {
            throw new InvalidArgumentException('The consumer slug must be non-empty.');
        }

        foreach ([$consumerRoot, $packageRoot] as $root) {
            self::assertAbsoluteExistingDirectory($root);
        }

        self::assertSortedUniquePaths($sourceRoots, [$consumerRoot, $packageRoot], false);
        self::assertSortedUniquePaths($providerFiles, [$consumerRoot, $packageRoot], true);
        self::assertSortedUniqueStrings($runtimeAssertions, true);
        self::assertSortedUniqueStrings($capabilities, true);

        if (array_diff($runtimeAssertions, self::RUNTIME_ASSERTIONS) !== []) {
            throw new InvalidArgumentException('The runtime assertion declaration is invalid.');
        }

        if (($capabilities !== [] || $purposeMappings !== []) && ! in_array('meta', $runtimeAssertions, true)) {
            throw new InvalidArgumentException('Capabilities and purpose mappings require the runtime meta assertion.');
        }

        $purposeKeys = array_keys($purposeMappings);
        $sortedPurposeKeys = $purposeKeys;
        sort($sortedPurposeKeys);

        if ($purposeKeys !== $sortedPurposeKeys) {
            throw new InvalidArgumentException('Purpose mappings must be sorted.');
        }

        foreach ($purposeMappings as $appPurpose => $purpose) {
            if (! is_string($appPurpose) || $appPurpose === '' || ! $purpose instanceof CredentialPurpose) {
                throw new InvalidArgumentException('A purpose mapping is invalid.');
            }
        }

        if (in_array('mcp-delegated', $capabilities, true) && $mcpServer === null) {
            throw new InvalidArgumentException('The mcp-delegated capability requires an MCP server.');
        }

        if ($mcpServer !== null && ! is_a($mcpServer, Server::class, true)) {
            throw new InvalidArgumentException('The MCP server declaration is invalid.');
        }

        if (self::sortedKeys($expected) !== self::sortedKeys(array_fill_keys(self::FAMILIES, []))) {
            throw new InvalidArgumentException('The expected conformance families are invalid.');
        }

        foreach ($expected as $members) {
            self::assertSortedUniqueStrings($members, true);
        }

        $this->expected = array_replace(array_fill_keys(self::FAMILIES, []), $expected);
    }

    /**
     * @param  array<string, mixed>  $input
     */
    public static function fromArray(array $input): self
    {
        $keys = [
            'consumer', 'consumer_root', 'package_root', 'source_roots', 'provider_files',
            'runtime_assertions', 'capabilities', 'purpose_mappings', 'mcp_server', 'expected',
        ];

        if (self::sortedKeys($input) !== self::sortedKeys(array_fill_keys($keys, null))) {
            throw new InvalidArgumentException('The consumer conformance fields are invalid.');
        }

        foreach (['consumer', 'consumer_root', 'package_root'] as $key) {
            if (! is_string($input[$key])) {
                throw new InvalidArgumentException('A consumer conformance field has the wrong type.');
            }
        }

        foreach (['source_roots', 'provider_files', 'runtime_assertions', 'capabilities', 'purpose_mappings', 'expected'] as $key) {
            if (! is_array($input[$key])) {
                throw new InvalidArgumentException('A consumer conformance field has the wrong type.');
            }
        }

        foreach (['source_roots', 'provider_files', 'runtime_assertions', 'capabilities'] as $key) {
            if (! array_is_list($input[$key])) {
                throw new InvalidArgumentException('A consumer conformance list field has the wrong shape.');
            }
        }

        foreach ($input['expected'] as $members) {
            if (! is_array($members) || ! array_is_list($members)) {
                throw new InvalidArgumentException('An expected conformance family has the wrong shape.');
            }
        }

        if ($input['mcp_server'] !== null && ! is_string($input['mcp_server'])) {
            throw new InvalidArgumentException('A consumer conformance field has the wrong type.');
        }

        /** @var array<string, CredentialPurpose> $purposeMappings */
        $purposeMappings = $input['purpose_mappings'];
        /** @var array<string, list<string>> $expected */
        $expected = $input['expected'];

        return new self(
            $input['consumer'],
            $input['consumer_root'],
            $input['package_root'],
            $input['source_roots'],
            $input['provider_files'],
            $input['runtime_assertions'],
            $input['capabilities'],
            $purposeMappings,
            $input['mcp_server'],
            $expected,
        );
    }

    private static function assertAbsoluteExistingDirectory(string $path): void
    {
        if (! str_starts_with($path, DIRECTORY_SEPARATOR) || ! is_dir($path) || realpath($path) === false) {
            throw new InvalidArgumentException('Conformance roots must be absolute existing directories.');
        }
    }

    /** @param array<string, mixed> $values
     * @return list<string>
     */
    private static function sortedKeys(array $values): array
    {
        $keys = array_keys($values);
        sort($keys);

        return $keys;
    }

    /**
     * @param  list<string>  $paths
     * @param  list<string>  $declaredRoots
     */
    private static function assertSortedUniquePaths(array $paths, array $declaredRoots, bool $files): void
    {
        self::assertSortedUniqueStrings($paths, false);

        foreach ($paths as $path) {
            $resolved = realpath($path);

            if (! is_string($resolved) || ($files ? ! is_file($resolved) : ! is_dir($resolved))) {
                throw new InvalidArgumentException('A declared conformance path does not exist.');
            }

            $inside = false;

            foreach ($declaredRoots as $root) {
                $root = (string) realpath($root);
                if ($resolved === $root || str_starts_with($resolved, rtrim($root, DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR)) {
                    $inside = true;
                    break;
                }
            }

            if (! $inside) {
                throw new InvalidArgumentException('A declared conformance path escapes its roots.');
            }

            if (! $files && self::phpFileCount($resolved) === 0) {
                throw new InvalidArgumentException('Every source root must contain a scanner-visible file.');
            }
        }
    }

    /** @param list<mixed> $values */
    private static function assertSortedUniqueStrings(array $values, bool $allowEmpty): void
    {
        if (! $allowEmpty && $values === []) {
            throw new InvalidArgumentException('A required conformance list is empty.');
        }

        foreach ($values as $value) {
            if (! is_string($value) || $value === '') {
                throw new InvalidArgumentException('A conformance list member is invalid.');
            }
        }

        $sorted = array_values(array_unique($values));
        sort($sorted);

        if ($values !== $sorted) {
            throw new InvalidArgumentException('Conformance lists must be sorted and duplicate-free.');
        }
    }

    private static function phpFileCount(string $root): int
    {
        $count = 0;

        foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root)) as $file) {
            if ($file instanceof SplFileInfo && $file->isFile() && $file->getExtension() === 'php') {
                $count++;
            }
        }

        return $count;
    }
}
