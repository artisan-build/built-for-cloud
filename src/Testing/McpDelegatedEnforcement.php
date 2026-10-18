<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use ArtisanBuild\BuiltForCloud\Console\ActingPrincipal;
use ArtisanBuild\BuiltForCloud\Console\ActingPrincipalResolver;
use ArtisanBuild\BuiltForCloud\Console\ConsoleRole;
use ArtisanBuild\BuiltForCloud\Console\DelegatedActor;
use ArtisanBuild\BuiltForCloud\Console\RequestAssertion;
use ArtisanBuild\BuiltForCloud\Exceptions\DelegatedPrincipalUnsupported;
use ArtisanBuild\BuiltForCloud\Exceptions\NoActingPrincipal;
use ArtisanBuild\BuiltForCloud\Mcp\Effect;
use ArtisanBuild\BuiltForCloud\Mcp\RequestEffectCeiling;
use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Http\Request as HttpRequest;
use Laravel\Mcp\Request as McpRequest;
use Laravel\Mcp\Response;
use Laravel\Mcp\ResponseFactory;
use Laravel\Mcp\Server;
use Laravel\Mcp\Server\Tool;
use Laravel\Mcp\Server\Transport\FakeTransporter;
use PHPUnit\Framework\Assert;
use Throwable;
use Traversable;

/**
 * Drives every delegated MCP tool under a verified assertion. This is the
 * behavioral leg; {@see McpDelegatedTools} remains the declaration leg.
 */
final class McpDelegatedEnforcement
{
    private const string STATE_BINDING = 'bfc.testing.mcp-delegated-enforcement-state';

    /** @var list<string> */
    private const array SUPPORTED_SCHEMA_KEYWORDS = [
        'additionalProperties', 'anyOf', 'const', 'default', 'description', 'enum', 'format',
        'items', 'maximum', 'maxItems', 'maxLength', 'minimum', 'minItems', 'minLength',
        'multipleOf', 'oneOf', 'pattern', 'properties', 'required', 'title', 'type', 'uniqueItems',
    ];

    /**
     * @param  class-string<Server>  $serverClass
     * @param  list<class-string<Tool>>  $expected
     * @param  (Closure(ActingPrincipal, ActingPrincipal, Closure(class-string<Tool>, ?array<string, mixed>): mixed): void)|null  $negativeAuthorization
     * @param  array<class-string<Tool>, array<string, mixed>>  $arguments
     */
    public static function assertHonors(
        string $serverClass,
        array $expected,
        ConsoleRole $role = ConsoleRole::Member,
        ?Closure $negativeAuthorization = null,
        array $arguments = [],
    ): void {
        self::state()->forget($serverClass);
        Assert::assertNotEmpty($expected, 'Delegated MCP enforcement requires a non-empty expected tool list.');

        foreach ($expected as $tool) {
            Assert::assertTrue(
                is_string($tool) && is_a($tool, Tool::class, true),
                'Every expected delegated MCP tool must be a Tool class.',
            );
        }

        $normalizedExpected = array_values(array_unique($expected));
        sort($normalizedExpected);
        Assert::assertCount(count($expected), $normalizedExpected, 'The expected delegated MCP tool list must not contain duplicates.');

        foreach (array_keys($arguments) as $tool) {
            Assert::assertContains($tool, $normalizedExpected, 'Argument overrides may name only expected delegated MCP tools.');
        }

        $result = self::probe($serverClass, $role, $negativeAuthorization, $arguments);
        $violations = $result['violations'];

        foreach (array_diff($normalizedExpected, $result['tools']) as $missing) {
            $violations[] = 'expected-tool-unreached:'.$missing;
        }

        foreach (array_diff($result['tools'], $normalizedExpected) as $unexpected) {
            $violations[] = 'unexpected-tool:'.$unexpected;
        }

        $violations = self::sorted($violations);

        Assert::assertSame(
            [],
            $violations,
            "The MCP server does not honor delegated callers:\n".implode("\n", $violations),
        );

        self::state()->record($serverClass, $normalizedExpected);
    }

    /**
     * @param  class-string<Server>  $serverClass
     * @param  (Closure(ActingPrincipal, ActingPrincipal, Closure(class-string<Tool>, ?array<string, mixed>): mixed): void)|null  $negativeAuthorization
     * @param  array<class-string<Tool>, array<string, mixed>>  $arguments
     * @return array{
     *     tools: list<class-string<Tool>>,
     *     invoked: list<class-string<Tool>>,
     *     refusals: array<class-string<Tool>, class-string<Throwable>>,
     *     principal_mismatches: array<class-string<Tool>, string>,
     *     errors: array<class-string<Tool>, string>,
     *     unreached: array<class-string<Tool>, string>,
     *     negative_authorization: 'absent'|'passed'|'failed',
     *     violations: list<string>
     * }
     */
    public static function probe(
        string $serverClass,
        ConsoleRole $role = ConsoleRole::Member,
        ?Closure $negativeAuthorization = null,
        array $arguments = [],
    ): array {
        $originalRequest = app()->bound('request') ? app('request') : null;
        $request = HttpRequest::create('/bfc-testing/mcp-delegated', 'POST');
        app()->instance('request', $request);

        $tools = [];
        $invoked = [];
        $refusals = [];
        $principalMismatches = [];
        $errors = [];
        $unreached = [];
        $violations = [];
        $negativeStatus = $negativeAuthorization instanceof Closure ? 'failed' : 'absent';
        $createdActorIds = [];

        try {
            $primary = self::publish($request, $role, false, $createdActorIds);
            $declarations = McpDelegatedTools::discover($serverClass);
            array_push($violations, ...$declarations['violations']);

            $registered = self::registeredTools($serverClass, $request);
            $tools = array_keys($registered);
            sort($tools);

            if ($tools === []) {
                $violations[] = 'no-tools-registered-under-delegated-assertion';
            }

            foreach ($registered as $toolClass => $tool) {
                $hasOverride = array_key_exists($toolClass, $arguments);
                $toolArguments = self::argumentsFor(
                    $tool,
                    $hasOverride ? $arguments[$toolClass] : null,
                    $hasOverride,
                );

                if (! $toolArguments['ok']) {
                    $unreached[$toolClass] = $toolArguments['reason'];
                    $violations[] = 'tool-unreached:'.$toolClass.':'.$toolArguments['reason'];

                    continue;
                }

                self::invoke(
                    $tool,
                    $toolArguments['value'],
                    $request,
                    $primary,
                    $invoked,
                    $refusals,
                    $principalMismatches,
                    $errors,
                    $violations,
                );
            }

            if ($negativeAuthorization instanceof Closure) {
                $negativeStatus = self::runNegativeAuthorizationCase(
                    $serverClass,
                    $role,
                    $primary,
                    $negativeAuthorization,
                    $invoked,
                    $refusals,
                    $principalMismatches,
                    $errors,
                    $unreached,
                    $violations,
                    $createdActorIds,
                );
            }
        } catch (McpDelegatedFixtureCollision $failure) {
            $violations[] = 'probe-setup-failed:fixture-state-collision:'.$failure->reason;
        } catch (Throwable $failure) {
            $violations[] = 'probe-setup-failed:'.$failure::class;
        } finally {
            foreach ($createdActorIds as $actorId) {
                DelegatedActor::query()->whereKey($actorId)->delete();
            }

            if ($originalRequest instanceof HttpRequest) {
                app()->instance('request', $originalRequest);
            } else {
                app()->forgetInstance('request');
            }
        }

        ksort($refusals);
        ksort($principalMismatches);
        ksort($errors);
        ksort($unreached);

        return [
            'tools' => self::sorted($tools),
            'invoked' => self::sorted($invoked),
            'refusals' => $refusals,
            'principal_mismatches' => $principalMismatches,
            'errors' => $errors,
            'unreached' => $unreached,
            'negative_authorization' => $negativeStatus,
            'violations' => self::sorted($violations),
        ];
    }

    /**
     * @param  class-string<Server>  $serverClass
     * @return list<class-string<Tool>>|null
     *
     * @internal
     */
    public static function recordedTools(string $serverClass): ?array
    {
        return self::state()->toolsFor($serverClass);
    }

    private static function state(): McpDelegatedEnforcementState
    {
        if (! app()->bound(self::STATE_BINDING)) {
            app()->instance(self::STATE_BINDING, new McpDelegatedEnforcementState);
        }

        /** @var McpDelegatedEnforcementState */
        return app(self::STATE_BINDING);
    }

    /** @param list<int|string> $createdActorIds */
    private static function publish(
        HttpRequest $request,
        ConsoleRole $role,
        bool $secondary,
        array &$createdActorIds,
    ): ActingPrincipal {
        $assertion = McpDelegatedAssertionFixture::verified($role, $secondary);
        $identityHash = DelegatedActor::identityHash($assertion->issuer, $assertion->subject);

        if (DelegatedActor::query()->where('identity_hash', $identityHash)->exists()) {
            throw new McpDelegatedFixtureCollision('delegated-actor-identity');
        }

        try {
            $actor = DelegatedActor::query()->create([
                'identity_hash' => $identityHash,
                'issuer' => $assertion->issuer,
                'subject' => $assertion->subject,
                'last_handoff_display_name' => $assertion->displayName,
                'last_handoff_on_behalf_of' => $assertion->onBehalfOf,
                'last_handoff_role' => $assertion->role->value,
            ]);
        } catch (UniqueConstraintViolationException) {
            throw new McpDelegatedFixtureCollision('delegated-actor-race');
        }
        $actorId = $actor->getKey();
        if (! is_int($actorId) && ! is_string($actorId)) {
            $actor->delete();

            throw new \RuntimeException('The delegated enforcement fixture actor has no stable identifier.');
        }
        $createdActorIds[] = $actorId;

        if (! $actor->isActive()) {
            throw new \RuntimeException('The delegated enforcement fixture actor is inactive.');
        }

        return RequestAssertion::publish($request, $actor, $assertion);
    }

    /**
     * @param  class-string<Server>  $serverClass
     * @return array<class-string<Tool>, Tool>
     */
    private static function registeredTools(string $serverClass, HttpRequest $request): array
    {
        $server = app()->make($serverClass, ['transport' => new FakeTransporter]);
        Assert::assertInstanceOf(Server::class, $server, $serverClass.' is not a Laravel MCP server.');
        $server->start();

        $registered = RequestEffectCeiling::run(
            $request,
            Effect::Destructive,
            static fn () => $server->createContext()->tools(),
        );
        $tools = [];

        foreach ($registered as $tool) {
            $tools[$tool::class] = $tool;
        }

        ksort($tools);

        return $tools;
    }

    /**
     * @param  array<string, mixed>|null  $override
     * @return array{ok: bool, value: array<string, mixed>, reason: string}
     */
    private static function argumentsFor(Tool $tool, ?array $override = null, bool $hasOverride = false): array
    {
        try {
            $schema = $tool->toArray()['inputSchema'] ?? null;
        } catch (Throwable $failure) {
            return ['ok' => false, 'value' => [], 'reason' => 'schema-exception:'.$failure::class];
        }

        if (! is_array($schema)) {
            return ['ok' => false, 'value' => [], 'reason' => 'invalid-input-schema'];
        }

        if ($hasOverride) {
            $validation = self::validateValue($schema, $override);

            return $validation === null
                ? ['ok' => true, 'value' => $override, 'reason' => '']
                : ['ok' => false, 'value' => [], 'reason' => 'override-invalid:'.$validation];
        }

        $synthesized = self::synthesize($schema);

        if (! $synthesized['ok'] || ! is_array($synthesized['value'])) {
            return ['ok' => false, 'value' => [], 'reason' => $synthesized['reason']];
        }

        $validation = self::validateValue($schema, $synthesized['value']);

        if ($validation !== null) {
            return ['ok' => false, 'value' => [], 'reason' => 'synthesized-invalid:'.$validation];
        }

        return ['ok' => true, 'value' => $synthesized['value'], 'reason' => ''];
    }

    /**
     * @param  array<string, mixed>  $schema
     * @return array{ok: bool, value: mixed, reason: string}
     */
    private static function synthesize(array $schema): array
    {
        if (array_key_exists('default', $schema)) {
            return ['ok' => true, 'value' => $schema['default'], 'reason' => ''];
        }

        if (array_key_exists('const', $schema)) {
            return ['ok' => true, 'value' => $schema['const'], 'reason' => ''];
        }

        if (isset($schema['enum']) && is_array($schema['enum']) && $schema['enum'] !== []) {
            return ['ok' => true, 'value' => $schema['enum'][0], 'reason' => ''];
        }

        foreach (['anyOf', 'oneOf'] as $choice) {
            if (! isset($schema[$choice]) || ! is_array($schema[$choice])) {
                continue;
            }

            foreach ($schema[$choice] as $candidate) {
                if (is_array($candidate)) {
                    $value = self::synthesize($candidate);

                    if ($value['ok']) {
                        return $value;
                    }
                }
            }

            return ['ok' => false, 'value' => null, 'reason' => 'unsynthesizable-'.$choice];
        }

        $type = $schema['type'] ?? (isset($schema['properties']) ? 'object' : null);
        if (is_array($type)) {
            foreach ($type as $candidate) {
                if (is_string($candidate) && $candidate !== 'null') {
                    return self::synthesize([...$schema, 'type' => $candidate]);
                }
            }

            return ['ok' => true, 'value' => null, 'reason' => ''];
        }

        return match ($type) {
            'object' => self::synthesizeObject($schema),
            'array' => self::synthesizeArray($schema),
            'string' => self::synthesizeString($schema),
            'integer' => self::synthesizeInteger($schema),
            'number' => self::synthesizeNumber($schema),
            'boolean' => ['ok' => true, 'value' => false, 'reason' => ''],
            'null' => ['ok' => true, 'value' => null, 'reason' => ''],
            default => ['ok' => false, 'value' => null, 'reason' => 'unsupported-schema-type'],
        };
    }

    /**
     * @param  array<string, mixed>  $schema
     * @return array{ok: bool, value: mixed, reason: string}
     */
    private static function synthesizeObject(array $schema): array
    {
        $properties = $schema['properties'] ?? [];
        $required = $schema['required'] ?? [];

        if ((! is_array($properties) && ! is_object($properties)) || ! is_array($required)) {
            return ['ok' => false, 'value' => null, 'reason' => 'invalid-object-schema'];
        }

        $properties = (array) $properties;
        $value = [];

        foreach ($required as $name) {
            if (! is_string($name) || ! isset($properties[$name]) || ! is_array($properties[$name])) {
                return ['ok' => false, 'value' => null, 'reason' => 'invalid-required-property'];
            }

            $property = self::synthesize($properties[$name]);
            if (! $property['ok']) {
                return ['ok' => false, 'value' => null, 'reason' => 'property-'.$name.':'.$property['reason']];
            }

            $value[$name] = $property['value'];
        }

        return ['ok' => true, 'value' => $value, 'reason' => ''];
    }

    /**
     * @param  array<string, mixed>  $schema
     * @return array{ok: bool, value: mixed, reason: string}
     */
    private static function synthesizeArray(array $schema): array
    {
        $minimum = $schema['minItems'] ?? 0;
        $maximum = $schema['maxItems'] ?? null;

        if (! is_int($minimum) || $minimum < 0 || ($maximum !== null && (! is_int($maximum) || $maximum < 0))) {
            return ['ok' => false, 'value' => null, 'reason' => 'invalid-array-bounds'];
        }

        if ($maximum !== null && $minimum > $maximum) {
            return ['ok' => false, 'value' => null, 'reason' => 'empty-array-range'];
        }

        if (($schema['uniqueItems'] ?? false) === true && $minimum > 1) {
            return ['ok' => false, 'value' => null, 'reason' => 'unsupported-unique-items'];
        }

        if ($minimum === 0) {
            return ['ok' => true, 'value' => [], 'reason' => ''];
        }

        if (! isset($schema['items']) || ! is_array($schema['items'])) {
            return ['ok' => false, 'value' => null, 'reason' => 'missing-array-items'];
        }

        $item = self::synthesize($schema['items']);
        if (! $item['ok']) {
            return ['ok' => false, 'value' => null, 'reason' => 'array-item:'.$item['reason']];
        }

        return ['ok' => true, 'value' => array_fill(0, $minimum, $item['value']), 'reason' => ''];
    }

    /**
     * @param  array<string, mixed>  $schema
     * @return array{ok: bool, value: mixed, reason: string}
     */
    private static function synthesizeString(array $schema): array
    {
        if (isset($schema['pattern'])) {
            return ['ok' => false, 'value' => null, 'reason' => 'unsupported-string-pattern'];
        }

        $minimum = $schema['minLength'] ?? 0;
        $maximum = $schema['maxLength'] ?? null;

        if (! is_int($minimum) || $minimum < 0 || ($maximum !== null && (! is_int($maximum) || $maximum < 0))) {
            return ['ok' => false, 'value' => null, 'reason' => 'invalid-string-bounds'];
        }

        if ($maximum !== null && $minimum > $maximum) {
            return ['ok' => false, 'value' => null, 'reason' => 'empty-string-range'];
        }

        $format = $schema['format'] ?? null;
        $value = match ($format) {
            'date' => '1970-01-01',
            'date-time' => '1970-01-01T00:00:00+00:00',
            'email' => 'probe@example.test',
            'hostname' => 'probe.example.test',
            'ipv4' => '127.0.0.1',
            'ipv6' => '::1',
            'uri', 'url' => 'https://probe.example.test',
            'uuid' => '00000000-0000-4000-8000-000000000000',
            null => '',
            default => null,
        };

        if ($value === null) {
            return ['ok' => false, 'value' => null, 'reason' => 'unsupported-string-format'];
        }

        if ($format === null && strlen($value) < $minimum) {
            $value = str_repeat('x', $minimum);
        }

        if ($maximum !== null && self::stringLength($value) > $maximum) {
            return ['ok' => false, 'value' => null, 'reason' => 'format-exceeds-max-length'];
        }

        return ['ok' => true, 'value' => $value, 'reason' => ''];
    }

    /**
     * @param  array<string, mixed>  $schema
     * @return array{ok: bool, value: mixed, reason: string}
     */
    private static function synthesizeInteger(array $schema): array
    {
        $minimum = is_int($schema['minimum'] ?? null) ? $schema['minimum'] : 0;
        $multiple = is_int($schema['multipleOf'] ?? null) ? $schema['multipleOf'] : 1;

        if ($multiple <= 0) {
            return ['ok' => false, 'value' => null, 'reason' => 'invalid-integer-multiple'];
        }

        $value = (int) (ceil($minimum / $multiple) * $multiple);
        $maximum = $schema['maximum'] ?? null;

        return is_int($maximum) && $value > $maximum
            ? ['ok' => false, 'value' => null, 'reason' => 'empty-integer-range']
            : ['ok' => true, 'value' => $value, 'reason' => ''];
    }

    /**
     * @param  array<string, mixed>  $schema
     * @return array{ok: bool, value: mixed, reason: string}
     */
    private static function synthesizeNumber(array $schema): array
    {
        $minimum = $schema['minimum'] ?? 0;
        $multiple = $schema['multipleOf'] ?? 1;

        if ((! is_int($minimum) && ! is_float($minimum))
            || (! is_int($multiple) && ! is_float($multiple))
            || $multiple <= 0) {
            return ['ok' => false, 'value' => null, 'reason' => 'invalid-number-minimum'];
        }

        $value = (float) (ceil($minimum / $multiple) * $multiple);
        $maximum = $schema['maximum'] ?? null;

        return (is_int($maximum) || is_float($maximum)) && $value > $maximum
            ? ['ok' => false, 'value' => null, 'reason' => 'empty-number-range']
            : ['ok' => true, 'value' => $value, 'reason' => ''];
    }

    /**
     * Return the first deterministic reason the value violates the schema,
     * or null when it satisfies every constraint this Laravel builder emits.
     *
     * @param  array<string, mixed>  $schema
     */
    private static function validateValue(array $schema, mixed $value): ?string
    {
        foreach (array_keys($schema) as $keyword) {
            if (! is_string($keyword) || ! in_array($keyword, self::SUPPORTED_SCHEMA_KEYWORDS, true)) {
                return 'unsupported-schema-keyword:'.(is_string($keyword) ? $keyword : 'non-string');
            }
        }

        if (array_key_exists('const', $schema) && $value !== $schema['const']) {
            return 'const-mismatch';
        }

        if (isset($schema['enum'])) {
            if (! is_array($schema['enum']) || ! in_array($value, $schema['enum'], true)) {
                return 'enum-mismatch';
            }
        }

        foreach (['anyOf', 'oneOf'] as $choice) {
            if (! array_key_exists($choice, $schema)) {
                continue;
            }

            if (! is_array($schema[$choice])) {
                return 'invalid-'.$choice;
            }

            $matches = 0;
            foreach ($schema[$choice] as $candidate) {
                if (is_array($candidate) && self::validateValue($candidate, $value) === null) {
                    $matches++;
                }
            }

            if (($choice === 'anyOf' && $matches === 0) || ($choice === 'oneOf' && $matches !== 1)) {
                return $choice.'-mismatch';
            }
        }

        $type = $schema['type'] ?? (isset($schema['properties']) ? 'object' : null);
        if ($type === null) {
            return null;
        }

        $types = is_array($type) ? $type : [$type];
        if ($types === [] || array_filter($types, 'is_string') !== $types) {
            return 'invalid-schema-type';
        }

        $matchedType = null;
        foreach ($types as $candidate) {
            if (self::matchesType($candidate, $value)) {
                $matchedType = $candidate;
                break;
            }
        }

        if ($matchedType === null) {
            return 'type-mismatch';
        }

        if (is_array($type)) {
            $allowed = ['anyOf', 'const', 'default', 'description', 'enum', 'oneOf', 'title', 'type'];
        } else {
            $allowed = match ($matchedType) {
                'array' => ['anyOf', 'const', 'default', 'description', 'enum', 'items', 'maxItems', 'minItems', 'oneOf', 'title', 'type', 'uniqueItems'],
                'integer', 'number' => ['anyOf', 'const', 'default', 'description', 'enum', 'maximum', 'minimum', 'multipleOf', 'oneOf', 'title', 'type'],
                'object' => ['additionalProperties', 'anyOf', 'const', 'default', 'description', 'enum', 'oneOf', 'properties', 'required', 'title', 'type'],
                'string' => ['anyOf', 'const', 'default', 'description', 'enum', 'format', 'maxLength', 'minLength', 'oneOf', 'pattern', 'title', 'type'],
                default => ['anyOf', 'const', 'default', 'description', 'enum', 'oneOf', 'title', 'type'],
            };
        }

        foreach (array_keys($schema) as $keyword) {
            if (! in_array($keyword, $allowed, true)) {
                return 'unsupported-'.$matchedType.'-keyword:'.$keyword;
            }
        }

        return match ($matchedType) {
            'array' => self::validateArray($schema, $value),
            'integer', 'number' => self::validateNumber($schema, $value),
            'object' => self::validateObject($schema, $value),
            'string' => self::validateString($schema, $value),
            default => null,
        };
    }

    private static function matchesType(string $type, mixed $value): bool
    {
        return match ($type) {
            'array' => is_array($value) && array_is_list($value),
            'boolean' => is_bool($value),
            'integer' => is_int($value),
            'null' => $value === null,
            'number' => (is_int($value) || is_float($value)) && is_finite((float) $value),
            'object' => is_array($value) && ($value === [] || ! array_is_list($value)),
            'string' => is_string($value),
            default => false,
        };
    }

    /** @param array<string, mixed> $schema
     * @param  list<mixed>  $value
     */
    private static function validateArray(array $schema, array $value): ?string
    {
        $minimum = $schema['minItems'] ?? 0;
        $maximum = $schema['maxItems'] ?? null;

        if (! is_int($minimum) || $minimum < 0 || ($maximum !== null && (! is_int($maximum) || $maximum < 0))) {
            return 'invalid-array-bounds';
        }

        if (count($value) < $minimum) {
            return 'array-below-min-items';
        }

        if ($maximum !== null && count($value) > $maximum) {
            return 'array-above-max-items';
        }

        if (isset($schema['uniqueItems']) && ! is_bool($schema['uniqueItems'])) {
            return 'invalid-unique-items';
        }

        if (($schema['uniqueItems'] ?? false) === true
            && count(array_unique(array_map(serialize(...), $value))) !== count($value)) {
            return 'array-items-not-unique';
        }

        if (isset($schema['items'])) {
            if (! is_array($schema['items'])) {
                return 'invalid-array-items';
            }

            foreach ($value as $index => $item) {
                $reason = self::validateValue($schema['items'], $item);
                if ($reason !== null) {
                    return 'item-'.$index.':'.$reason;
                }
            }
        }

        return null;
    }

    /** @param array<string, mixed> $schema */
    private static function validateNumber(array $schema, int|float $value): ?string
    {
        foreach (['minimum', 'maximum', 'multipleOf'] as $keyword) {
            if (isset($schema[$keyword]) && ! is_int($schema[$keyword]) && ! is_float($schema[$keyword])) {
                return 'invalid-'.$keyword;
            }
        }

        if (isset($schema['minimum']) && $value < $schema['minimum']) {
            return 'number-below-minimum';
        }

        if (isset($schema['maximum']) && $value > $schema['maximum']) {
            return 'number-above-maximum';
        }

        if (isset($schema['multipleOf'])) {
            $multiple = (float) $schema['multipleOf'];
            if ($multiple <= 0) {
                return 'invalid-multipleOf';
            }

            $quotient = (float) $value / $multiple;
            if (abs($quotient - round($quotient)) > 1e-9 * max(1.0, abs($quotient))) {
                return 'number-not-multiple';
            }
        }

        return null;
    }

    /** @param array<string, mixed> $schema
     * @param  array<string, mixed>  $value
     */
    private static function validateObject(array $schema, array $value): ?string
    {
        $properties = $schema['properties'] ?? [];
        $required = $schema['required'] ?? [];

        if ((! is_array($properties) && ! is_object($properties)) || ! is_array($required)) {
            return 'invalid-object-schema';
        }

        $properties = (array) $properties;
        foreach ($required as $name) {
            if (! is_string($name) || ! array_key_exists($name, $value)) {
                return 'missing-required-property:'.(is_string($name) ? $name : 'non-string');
            }
        }

        if (isset($schema['additionalProperties']) && ! is_bool($schema['additionalProperties'])) {
            return 'invalid-additional-properties';
        }

        if (($schema['additionalProperties'] ?? true) === false) {
            foreach (array_diff(array_keys($value), array_keys($properties)) as $extra) {
                return 'additional-property:'.$extra;
            }
        }

        foreach ($value as $name => $propertyValue) {
            if (! isset($properties[$name])) {
                continue;
            }

            if (! is_array($properties[$name])) {
                return 'invalid-property-schema:'.$name;
            }

            $reason = self::validateValue($properties[$name], $propertyValue);
            if ($reason !== null) {
                return 'property-'.$name.':'.$reason;
            }
        }

        return null;
    }

    /** @param array<string, mixed> $schema */
    private static function validateString(array $schema, string $value): ?string
    {
        $minimum = $schema['minLength'] ?? 0;
        $maximum = $schema['maxLength'] ?? null;

        if (! is_int($minimum) || $minimum < 0 || ($maximum !== null && (! is_int($maximum) || $maximum < 0))) {
            return 'invalid-string-bounds';
        }

        $length = self::stringLength($value);
        if ($length < $minimum) {
            return 'string-below-min-length';
        }

        if ($maximum !== null && $length > $maximum) {
            return 'string-above-max-length';
        }

        if (isset($schema['pattern'])) {
            if (! is_string($schema['pattern'])) {
                return 'invalid-string-pattern';
            }

            $matches = self::patternMatches($schema['pattern'], $value);
            if ($matches === null) {
                return 'invalid-string-pattern';
            }
            if (! $matches) {
                return 'string-pattern-mismatch';
            }
        }

        if (isset($schema['format'])) {
            if (! is_string($schema['format'])) {
                return 'invalid-string-format';
            }

            $matches = self::formatMatches($schema['format'], $value);
            if ($matches === null) {
                return 'unsupported-string-format';
            }
            if (! $matches) {
                return 'string-format-mismatch';
            }
        }

        return null;
    }

    private static function stringLength(string $value): int
    {
        return function_exists('mb_strlen') ? mb_strlen($value) : strlen($value);
    }

    private static function patternMatches(string $pattern, string $value): ?bool
    {
        $result = @preg_match($pattern, $value);

        if ($result === false) {
            $result = @preg_match('~'.str_replace('~', '\\~', $pattern).'~u', $value);
        }

        return $result === false ? null : $result === 1;
    }

    private static function formatMatches(string $format, string $value): ?bool
    {
        return match ($format) {
            'date' => ($date = \DateTimeImmutable::createFromFormat('!Y-m-d', $value)) !== false
                && $date->format('Y-m-d') === $value,
            'date-time' => \DateTimeImmutable::createFromFormat(DATE_ATOM, $value) !== false,
            'email' => filter_var($value, FILTER_VALIDATE_EMAIL) !== false,
            'hostname' => filter_var($value, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) !== false,
            'ipv4' => filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false,
            'ipv6' => filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false,
            'uri', 'url' => filter_var($value, FILTER_VALIDATE_URL) !== false,
            'uuid' => preg_match('/\A[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/i', $value) === 1,
            default => null,
        };
    }

    /**
     * @param  array<string, mixed>  $arguments
     * @param  list<class-string<Tool>>  $invoked
     * @param  array<class-string<Tool>, class-string<Throwable>>  $refusals
     * @param  array<class-string<Tool>, string>  $principalMismatches
     * @param  array<class-string<Tool>, string>  $errors
     * @param  list<string>  $violations
     */
    private static function invoke(
        Tool $tool,
        array $arguments,
        HttpRequest $request,
        ActingPrincipal $expected,
        array &$invoked,
        array &$refusals,
        array &$principalMismatches,
        array &$errors,
        array &$violations,
    ): mixed {
        $toolClass = $tool::class;
        $actingObservations = [];
        $rawIdentifiers = [];
        $request->attributes->set(
            ActingPrincipalResolver::OBSERVER_ATTRIBUTE,
            static function (ActingPrincipal $principal) use (&$actingObservations): void {
                $actingObservations[] = $principal;
            },
        );
        $resolver = $request->getUserResolver();
        $request->setUserResolver(static function () use ($resolver, &$rawIdentifiers): mixed {
            $principal = $resolver();

            if ($principal instanceof Authenticatable) {
                $identifier = $principal->getAuthIdentifier();
                $rawIdentifiers[] = is_int($identifier) || is_string($identifier) ? (string) $identifier : null;
            }

            return $principal;
        });

        $result = null;
        $responseError = false;
        $container = app();
        $mcpRequestWasBound = $container->bound('mcp.request');
        $priorMcpRequest = null;

        if ($mcpRequestWasBound) {
            $resolvedMcpRequest = $container->make('mcp.request');
            if (! $resolvedMcpRequest instanceof McpRequest) {
                throw new \RuntimeException('The existing mcp.request binding is invalid.');
            }
            $priorMcpRequest = $resolvedMcpRequest;
        }
        $typedRequestWasBound = $container->bound(McpRequest::class);
        $priorTypedRequest = null;

        if ($typedRequestWasBound) {
            $resolvedTypedRequest = $container->make(McpRequest::class);
            if (! $resolvedTypedRequest instanceof McpRequest) {
                throw new \RuntimeException('The existing Laravel MCP request binding is invalid.');
            }
            $priorTypedRequest = $resolvedTypedRequest;
        }
        $mcpRequest = new McpRequest($arguments);
        $container->instance('mcp.request', $mcpRequest);
        $container->instance(McpRequest::class, $mcpRequest);

        try {
            $invoked[] = $toolClass;
            $result = RequestEffectCeiling::run(
                $request,
                Effect::Destructive,
                static fn (): mixed => app()->call([$tool, 'handle']),
            );

            if ($result instanceof Traversable) {
                $result = iterator_to_array($result, false);
            }

            $responseError = self::hasErrorResponse($result);
        } catch (DelegatedPrincipalUnsupported|NoActingPrincipal $refusal) {
            $refusals[$toolClass] = $refusal::class;
            $violations[] = 'identity-refusal:'.$toolClass.':'.$refusal::class;
        } catch (Throwable $failure) {
            $errors[$toolClass] = 'execution-exception:'.$failure::class;
            $violations[] = 'tool-execution-failed:'.$toolClass.':'.$failure::class;
        } finally {
            if ($priorMcpRequest instanceof McpRequest) {
                $container->instance('mcp.request', $priorMcpRequest);
            } else {
                $container->forgetInstance('mcp.request');
            }

            if ($priorTypedRequest instanceof McpRequest) {
                $container->instance(McpRequest::class, $priorTypedRequest);
            } else {
                $container->forgetInstance(McpRequest::class);
            }

            $request->attributes->remove(ActingPrincipalResolver::OBSERVER_ATTRIBUTE);
            $request->setUserResolver($resolver);
        }

        if (isset($refusals[$toolClass]) || str_starts_with($errors[$toolClass] ?? '', 'execution-exception:')) {
            return $result;
        }

        $mismatch = self::principalMismatch($expected, $actingObservations, $rawIdentifiers);

        if ($mismatch !== null) {
            $principalMismatches[$toolClass] = $mismatch;
            $violations[] = 'principal-mismatch:'.$toolClass.':'.$mismatch;
        }

        if ($actingObservations === []) {
            $error = $responseError ? 'error-response-without-principal' : 'principal-not-observed';
            $errors[$toolClass] = $error;
            $violations[] = 'tool-observation-failed:'.$toolClass.':'.$error;
        }

        return $result;
    }

    /**
     * @param  list<ActingPrincipal>  $observations
     * @param  list<string|null>  $rawIdentifiers
     */
    private static function principalMismatch(ActingPrincipal $expected, array $observations, array $rawIdentifiers): ?string
    {
        $identifier = $expected->identifier();

        foreach ($observations as $observed) {
            if ($observed->identifier() !== $identifier
                || ! $observed->delegated
                || $observed->role !== $expected->role) {
                return 'different-principal';
            }
        }

        foreach ($rawIdentifiers as $observedIdentifier) {
            if ($observedIdentifier !== (string) $identifier) {
                return 'different-request-principal';
            }
        }

        return null;
    }

    private static function hasErrorResponse(mixed $result): bool
    {
        if ($result instanceof Response) {
            return $result->isError();
        }

        if ($result instanceof ResponseFactory) {
            return $result->responses()->contains(static fn (Response $response): bool => $response->isError());
        }

        if (is_iterable($result)) {
            foreach ($result as $item) {
                if (self::hasErrorResponse($item)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * @param  class-string<Server>  $serverClass
     * @param  Closure(ActingPrincipal, ActingPrincipal, Closure(class-string<Tool>, ?array<string, mixed>): mixed): void  $negativeAuthorization
     * @param  list<class-string<Tool>>  $invoked
     * @param  array<class-string<Tool>, class-string<Throwable>>  $refusals
     * @param  array<class-string<Tool>, string>  $principalMismatches
     * @param  array<class-string<Tool>, string>  $errors
     * @param  array<class-string<Tool>, string>  $unreached
     * @param  list<string>  $violations
     * @param  list<int|string>  $createdActorIds
     * @return 'passed'|'failed'
     */
    private static function runNegativeAuthorizationCase(
        string $serverClass,
        ConsoleRole $role,
        ActingPrincipal $primary,
        Closure $negativeAuthorization,
        array &$invoked,
        array &$refusals,
        array &$principalMismatches,
        array &$errors,
        array &$unreached,
        array &$violations,
        array &$createdActorIds,
    ): string {
        $request = HttpRequest::create('/bfc-testing/mcp-delegated/negative', 'POST');
        app()->instance('request', $request);
        $secondary = self::publish($request, $role, true, $createdActorIds);

        if (! self::negativeSubjectsAreDistinct($primary, $secondary, $violations)) {
            return 'failed';
        }

        $registered = self::registeredTools($serverClass, $request);
        $negativeInvocations = 0;
        $violationsBefore = count($violations);
        $invoke = static function (string $toolClass, ?array $arguments = null) use (
            &$negativeInvocations,
            $registered,
            $request,
            $secondary,
            &$invoked,
            &$refusals,
            &$principalMismatches,
            &$errors,
            &$unreached,
            &$violations,
        ): mixed {
            $tool = $registered[$toolClass] ?? null;

            if (! $tool instanceof Tool) {
                $unreached[$toolClass] = 'not-registered-for-secondary-subject';
                $violations[] = 'negative-tool-unreached:'.$toolClass.':not-registered-for-secondary-subject';

                return null;
            }

            $hasOverride = $arguments !== null;
            $synthesized = self::argumentsFor($tool, $arguments, $hasOverride);
            if (! $synthesized['ok']) {
                $unreached[$toolClass] = $synthesized['reason'];
                $violations[] = 'negative-tool-unreached:'.$toolClass.':'.$synthesized['reason'];

                return null;
            }
            $arguments = $synthesized['value'];

            $negativeInvocations++;

            return self::invoke(
                $tool,
                $arguments,
                $request,
                $secondary,
                $invoked,
                $refusals,
                $principalMismatches,
                $errors,
                $violations,
            );
        };

        try {
            $negativeAuthorization($primary, $secondary, $invoke);
        } catch (Throwable $failure) {
            $violations[] = 'negative-authorization-failed:'.$failure::class;

            return 'failed';
        }

        if ($negativeInvocations === 0) {
            $violations[] = 'negative-authorization-invoked-no-tool';

            return 'failed';
        }

        if (count($violations) !== $violationsBefore) {
            return 'failed';
        }

        return 'passed';
    }

    /** @param list<string> $violations */
    private static function negativeSubjectsAreDistinct(
        ActingPrincipal $primary,
        ActingPrincipal $secondary,
        array &$violations,
    ): bool {
        if ($primary->identifier() !== $secondary->identifier()) {
            return true;
        }

        $violations[] = 'negative-authorization-subjects-not-distinct';

        return false;
    }

    /**
     * @param  list<string>  $values
     * @return list<string>
     */
    private static function sorted(array $values): array
    {
        $values = array_values(array_unique($values));
        sort($values);

        return $values;
    }
}
