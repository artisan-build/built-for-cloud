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

        try {
            $primary = self::publish($request, $role, false);
            $declarations = McpDelegatedTools::discover($serverClass);
            array_push($violations, ...$declarations['violations']);

            $registered = self::registeredTools($serverClass, $request);
            $tools = array_keys($registered);
            sort($tools);

            if ($tools === []) {
                $violations[] = 'no-tools-registered-under-delegated-assertion';
            }

            foreach ($registered as $toolClass => $tool) {
                $toolArguments = array_key_exists($toolClass, $arguments)
                    ? ['ok' => true, 'value' => $arguments[$toolClass], 'reason' => '']
                    : self::argumentsFor($tool);

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
                );
            }
        } catch (Throwable $failure) {
            $violations[] = 'probe-setup-failed:'.$failure::class;
        } finally {
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

    private static function publish(HttpRequest $request, ConsoleRole $role, bool $secondary): ActingPrincipal
    {
        $assertion = McpDelegatedAssertionFixture::verified($role, $secondary);
        $actor = DelegatedActor::recordHandoff($assertion);

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
     * @return array{ok: bool, value: array<string, mixed>, reason: string}
     */
    private static function argumentsFor(Tool $tool): array
    {
        try {
            $schema = $tool->toArray()['inputSchema'] ?? null;
        } catch (Throwable $failure) {
            return ['ok' => false, 'value' => [], 'reason' => 'schema-exception:'.$failure::class];
        }

        if (! is_array($schema)) {
            return ['ok' => false, 'value' => [], 'reason' => 'invalid-input-schema'];
        }

        $synthesized = self::synthesize($schema);

        if (! $synthesized['ok'] || ! is_array($synthesized['value'])) {
            return ['ok' => false, 'value' => [], 'reason' => $synthesized['reason']];
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
        $minimum = max(0, is_int($schema['minItems'] ?? null) ? $schema['minItems'] : 0);

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

        $minimum = max(0, is_int($schema['minLength'] ?? null) ? $schema['minLength'] : 0);

        if ($format === null && strlen($value) < $minimum) {
            $value = str_repeat('x', $minimum);
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

        if (! is_int($minimum) && ! is_float($minimum)) {
            return ['ok' => false, 'value' => null, 'reason' => 'invalid-number-minimum'];
        }

        $value = (float) $minimum;
        $maximum = $schema['maximum'] ?? null;

        return (is_int($maximum) || is_float($maximum)) && $value > $maximum
            ? ['ok' => false, 'value' => null, 'reason' => 'empty-number-range']
            : ['ok' => true, 'value' => $value, 'reason' => ''];
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

        try {
            $invoked[] = $toolClass;
            $result = RequestEffectCeiling::run(
                $request,
                Effect::Destructive,
                static fn (): mixed => app()->call([$tool, 'handle'], ['request' => new McpRequest($arguments)]),
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
    ): string {
        $request = HttpRequest::create('/bfc-testing/mcp-delegated/negative', 'POST');
        app()->instance('request', $request);
        $secondary = self::publish($request, $role, true);

        if ($primary->identifier() === $secondary->identifier()) {
            $violations[] = 'negative-authorization-subjects-not-distinct';

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

            if ($arguments === null) {
                $synthesized = self::argumentsFor($tool);
                if (! $synthesized['ok']) {
                    $unreached[$toolClass] = $synthesized['reason'];
                    $violations[] = 'negative-tool-unreached:'.$toolClass.':'.$synthesized['reason'];

                    return null;
                }
                $arguments = $synthesized['value'];
            }

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
