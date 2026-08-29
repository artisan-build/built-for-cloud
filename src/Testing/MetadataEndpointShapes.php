<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use ArtisanBuild\BuiltForCloud\BuiltForCloud;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyFiled;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresHeadlineStat;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageOwnership;
use ArtisanBuild\BuiltForCloud\MetadataShape;
use ArtisanBuild\BuiltForCloud\Vitals\CollectVitals;
use ArtisanBuild\BuiltForCloud\Vitals\HeadlineLabel;
use ArtisanBuild\BuiltForCloud\Vitals\HeadlineUnit;
use ArtisanBuild\BuiltForCloud\Vitals\Health;
use ArtisanBuild\BuiltForCloud\Vitals\VitalsPayload;
use Carbon\CarbonImmutable;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Assert;
use PHPUnit\Framework\AssertionFailedError;
use Symfony\Component\HttpFoundation\Response as SymfonyResponse;
use Throwable;

/**
 * The expected 2xx shape of every `metadata`-classified route THIS
 * PACKAGE serves (Console PRD D15, docs/http-contract.md "Endpoint
 * classification"), and the evaluator that checks one.
 *
 * **This is a `final` class of `static` methods, and that is the point
 * rather than a style choice.** The registry and the evaluator lived in
 * {@see ContractAssertions} as private TRAIT methods, and a private
 * trait method is not private to the trait: a class that uses the trait
 * may declare a method of the same name, and the class's definition
 * wins. So a consuming test class could have declared its own
 * `builtForCloudMetadataShapes()` — or a permissive
 * `assertBuiltForCloudMetadataAgainst()` — and had the certification
 * path back, which made the trait's claim that "an app endpoint cannot
 * be certified here at all" false. It is true now: a `final` class
 * cannot be subclassed, its statics cannot be overridden, and the trait
 * only delegates here.
 *
 * The residual, stated because an unlisted one reads as covered: a class
 * may still redefine the trait's PUBLIC entry point,
 * {@see ContractAssertions::assertBuiltForCloudMetadataEndpoint}. That
 * is not a substitution — a class that does it is not calling this
 * assertion at all, which is visible in its own source. What cannot be
 * changed from outside is what this assertion CHECKS.
 *
 * WHAT THE SHAPES ARE. Each names exact keys, exact types and exact
 * members, and anything else fails: an unknown key, a missing one, a
 * wrong root structure, a near-miss enum member, a number outside range,
 * a non-finite float.
 *
 * **Where a domain has a producer constant or a producer function, this
 * READS it rather than restating it** — `health` by evaluating
 * {@see Health::fromDegradation} over its whole argument range, `unit`
 * from {@see HeadlineUnit::cases}, `bfc_version` from
 * {@see BuiltForCloud::VERSION}, the numeric bounds from
 * {@see VitalsPayload}'s constants, `headline.label` from the app's own
 * declared vocabulary, and the two timestamp fields by round-tripping
 * through the exact formatter each producer calls. A domain restated is
 * a domain that ends up wider than the thing it describes; three of them
 * already had.
 *
 * Where the producer's rule is a SHAPE rather than a value, the shape is
 * the domain and is named here: an operator-declared `app_version` is
 * genuinely any semver, a `kid` is genuinely any id the keyring accepts,
 * a revoked id is genuinely any bounded identifier, and a count is
 * genuinely any non-negative integer. Those are stated as what they are,
 * not dressed up as derivations.
 *
 * It says nothing whatever about a consuming app's own endpoints; the
 * general instrument that claimed to is withdrawn.
 */
final class MetadataEndpointShapes
{
    /**
     * The `METHOD /uri` names shapes exist for — every
     * `metadata`-classified row in the contract's classification table,
     * and nothing else.
     *
     * @return list<string>
     */
    public static function endpoints(): array
    {
        return array_keys(self::shapes());
    }

    /**
     * Check one response against the expected shape of one enumerated
     * route. A route name that is not enumerated FAILS.
     *
     * Scope: the 2xx body. Error envelopes are outside the
     * classification column, as the contract states.
     *
     * @param  TestResponse<SymfonyResponse>  $response
     */
    public static function assertResponse(TestResponse $response, string $endpoint): void
    {
        $shapes = self::shapes();

        Assert::assertArrayHasKey(
            $endpoint,
            $shapes,
            "No expected metadata shape is enumerated for [{$endpoint}]. This checks THIS PACKAGE's own "
            .'metadata-classified routes and nothing else; a package route with no entry cannot be checked, '
            .'and an app endpoint cannot be checked here at all.',
        );

        $body = (string) $response->getContent();
        $decoded = trim($body) === '' ? null : json_decode($body, true);

        Assert::assertFalse(
            trim($body) !== '' && $decoded === null,
            $endpoint.': the response body is neither empty nor valid JSON, so its shape cannot be checked.',
        );

        self::against($decoded, $shapes[$endpoint], $endpoint, '$');
    }

    /**
     * @return array<string, array<string, mixed>>
     */
    private static function shapes(): array
    {
        return [
            'GET /bfc/console/vitals' => self::vitals(),
            // `ok` is `true` and can be nothing else: the verb has one
            // success path and {@see ManageOwnership::cancelTransfer}
            // returns that literal. `bool` was a domain wider than the
            // producer.
            'POST /bfc/ownership/cancel-transfer' => [
                'type' => 'object',
                'fields' => ['ok' => ['type' => 'enum', 'values' => [true]]],
            ],
            // BOTH offboard shapes. The direct path answers
            // `offboarded`, the integration path the uniform `accepted`,
            // and each alternative is an exact shape of its own.
            // `fully_contained` is genuinely either boolean — it is the
            // honest incompleteness report.
            'POST /bfc/subjects/offboard' => [
                'type' => 'one_of',
                'shapes' => [
                    [
                        'type' => 'object',
                        'fields' => [
                            'offboarded' => ['type' => 'enum', 'values' => [true]],
                            'fully_contained' => ['type' => 'bool'],
                        ],
                    ],
                    [
                        'type' => 'object',
                        'fields' => [
                            'accepted' => ['type' => 'enum', 'values' => [true]],
                            'fully_contained' => ['type' => 'bool'],
                        ],
                    ],
                ],
            ],
            // The console `kid` charset is bounded and deliberately NOT
            // the lowercase token vocabulary, so it has its own NAMED
            // type, whose pattern is the keyring's own constant.
            // `status` is the literal {@see ConsoleKeyFiled::toArray}
            // emits, and the only one it can.
            'POST /bfc/console/re-key' => [
                'type' => 'object',
                'fields' => [
                    'console_key' => [
                        'type' => 'object',
                        'fields' => [
                            'key_id' => ['type' => 'console_key_id'],
                            'status' => ['type' => 'enum', 'values' => ['active']],
                            // {@see ConsoleKeyFiled::toArray} emits
                            // `toRfc3339String()`.
                            'activated_at' => ['type' => 'rfc3339_timestamp', 'nullable' => true],
                            'active_key_ids' => ['type' => 'list', 'of' => ['type' => 'console_key_id']],
                        ],
                    ],
                ],
            ],
            'DELETE /bfc/credentials/{id}' => ['type' => 'empty'],
            'DELETE /bfc/me/credentials/{id}' => ['type' => 'empty'],
            'DELETE /api/credentials/id/{id}' => ['type' => 'empty'],
            // No cardinality bound. How many rows share a name is not a
            // classification concern and the producer imposes no cap; an
            // earlier revision's 1,000 was a bound written where nothing
            // enforced it. Each ITEM being bounded is the claim.
            'DELETE /api/credentials/{name}' => [
                'type' => 'object',
                'fields' => [
                    'revoked_ids' => ['type' => 'list', 'of' => ['type' => 'token']],
                ],
            ],
        ];
    }

    /**
     * `GET /bfc/console/vitals` (Console PRD D9/D15).
     *
     * Every domain here is read from its producer. An earlier revision
     * restated several and each one drifted wider than the code within a
     * round or two: ages capped at a decade the producer computed
     * without limit, magnitudes it was happy to emit, a `health` member
     * it cannot construct, any semver where it emits one string, any
     * identifier-shaped label where it emits an enum case.
     *
     * @return array<string, mixed>
     */
    private static function vitals(): array
    {
        $age = VitalsPayload::MAX_AGE_SECONDS;
        $magnitude = VitalsPayload::MAX_HEADLINE_MAGNITUDE;

        return [
            'type' => 'object',
            'fields' => [
                'version' => ['type' => 'enum', 'values' => [VitalsPayload::VERSION]],
                'api_version' => ['type' => 'enum', 'values' => [BuiltForCloud::API_VERSION]],
                // This instance's own release, not "a semver".
                'bfc_version' => ['type' => 'enum', 'values' => [BuiltForCloud::VERSION]],
                // Genuinely any semver or null: the value is
                // operator-declared config that {@see CollectVitals}
                // bounds to that shape and no further.
                'app_version' => ['type' => 'semver', 'nullable' => true],
                // The producer's ACTUAL range, computed from the only
                // constructor it uses. `Health::Down` exists for the
                // fleet dashboard and `fromDegradation` cannot return
                // it, so evaluating the function is both exact and
                // drift-proof.
                'health' => ['type' => 'enum', 'values' => [
                    Health::fromDegradation(false)->value,
                    Health::fromDegradation(true)->value,
                ]],
                // {@see VitalsPayload::toArray} emits `toAtomString()`,
                // so the domain is that format, not "an ISO-8601
                // instant" — checked by round-tripping through the
                // producer's own formatter.
                'deployed_at' => ['type' => 'atom_timestamp', 'nullable' => true],
                'deploy_age_seconds' => ['type' => 'int', 'nullable' => true, 'min' => -$age, 'max' => $age],
                'queue' => [
                    'type' => 'object',
                    'fields' => [
                        'pending' => ['type' => 'int', 'nullable' => true, 'min' => 0, 'max' => PHP_INT_MAX],
                        'reserved' => ['type' => 'int', 'nullable' => true, 'min' => 0, 'max' => PHP_INT_MAX],
                        'failed' => ['type' => 'int', 'nullable' => true, 'min' => 0, 'max' => PHP_INT_MAX],
                        'oldest_pending_age_seconds' => ['type' => 'int', 'nullable' => true, 'min' => -$age, 'max' => $age],
                    ],
                ],
                'headline' => [
                    'type' => 'object',
                    'nullable' => true,
                    'fields' => [
                        'value' => ['type' => 'number', 'min' => -$magnitude, 'max' => $magnitude],
                        // A member of THIS APP's declared vocabulary, not
                        // merely something identifier-shaped. Accepting
                        // any token was the exact hole the enum work
                        // existed to close, reopened one layer up.
                        'label' => ['type' => 'headline_label'],
                        'unit' => ['type' => 'enum', 'nullable' => true, 'values' => array_map(
                            static fn (HeadlineUnit $unit): string => $unit->value,
                            HeadlineUnit::cases(),
                        )],
                    ],
                ],
            ],
        ];
    }

    /**
     * @param  array<string, mixed>  $spec
     */
    private static function against(mixed $value, array $spec, string $context, string $path): void
    {
        $type = $spec['type'] ?? null;

        Assert::assertIsString($type, $context.': the shape at '.$path.' names no type.');

        if ($value === null) {
            Assert::assertTrue(
                $type === 'empty' || ($spec['nullable'] ?? false) === true,
                $context.': '.$path.' is null, and the shape does not permit null there.',
            );

            return;
        }

        if ($type === 'empty') {
            Assert::fail($context.': '.$path.' carries a body where the shape requires an empty one.');
        }

        switch ($type) {
            case 'bool':
                Assert::assertIsBool($value, $context.': '.$path.' is not a boolean.');

                return;

            case 'int':
                Assert::assertIsInt($value, $context.': '.$path.' is not an integer.');
                self::range($value, $spec, $context, $path);

                return;

            case 'number':
                Assert::assertTrue(
                    (is_int($value) || is_float($value)) && is_finite((float) $value),
                    $context.': '.$path.' is not a finite number.',
                );
                /** @var int|float $value */
                self::range($value, $spec, $context, $path);

                return;

            case 'enum':
                $values = $spec['values'] ?? null;
                Assert::assertIsArray($values, $context.': the enum shape at '.$path.' lists no members.');
                Assert::assertContains(
                    $value,
                    $values,
                    $context.': '.$path.' is not one of the members this shape permits.',
                );

                return;

            case 'headline_label':
                Assert::assertIsString($value, $context.': '.$path.' is not a string.');
                self::headlineLabel($value, $context, $path);

                return;

            case 'token':
            case 'semver':
            case 'console_key_id':
                Assert::assertIsString($value, $context.': '.$path.' is not a string.');
                Assert::assertTrue(
                    match ($type) {
                        'token' => MetadataShape::isToken($value),
                        'semver' => MetadataShape::isSemver($value),
                        default => MetadataShape::isConsoleKeyId($value),
                    },
                    $context.': '.$path.' is not a bounded '.$type.'. Got: '.var_export($value, true),
                );

                return;

            case 'atom_timestamp':
            case 'rfc3339_timestamp':
                Assert::assertIsString($value, $context.': '.$path.' is not a string.');
                self::timestamp($value, $type, $context, $path);

                return;

            case 'one_of':
                self::oneOf($value, $spec, $context, $path);

                return;

            case 'object':
                self::object($value, $spec, $context, $path);

                return;

            case 'list':
                self::list($value, $spec, $context, $path);

                return;

            default:
                Assert::fail($context.': the shape at '.$path.' names the unknown type ['.$type.'].');
        }
    }

    /**
     * A timestamp must be exactly what the producer's formatter emits,
     * checked by parsing it and formatting it back.
     *
     * "An ISO-8601 instant" was a domain wider than either producer:
     * {@see VitalsPayload::toArray} calls `toAtomString()` and
     * {@see ConsoleKeyFiled::toArray} calls `toRfc3339String()`, so a
     * `Z` suffix or fractional seconds would have passed a check while
     * being something neither can emit.
     *
     * It must also still be a bounded metadata string — a round-trip
     * alone would admit an unbounded one — so both checks apply.
     */
    private static function timestamp(string $value, string $type, string $context, string $path): void
    {
        Assert::assertTrue(
            MetadataShape::isTimestamp($value),
            $context.': '.$path.' is not a bounded timestamp. Got: '.var_export($value, true),
        );

        try {
            $parsed = CarbonImmutable::parse($value);
        } catch (Throwable) {
            Assert::fail($context.': '.$path.' is not a parseable instant. Got: '.var_export($value, true));
        }

        $formatted = $type === 'atom_timestamp' ? $parsed->toAtomString() : $parsed->toRfc3339String();

        Assert::assertSame(
            $formatted,
            $value,
            $context.': '.$path.' is not in the format its producer emits.',
        );
    }

    /**
     * A headline label must be a CASE of the vocabulary this app
     * declares, read from the declaration itself rather than approximated
     * by a charset.
     *
     * The charset check that used to stand here — "any bounded lowercase
     * identifier" — was wider than the producer in exactly the way the
     * enum work existed to prevent: `customer-incident` is
     * identifier-shaped, and would have passed while being no member of
     * anything.
     *
     * A payload carrying a label while the app declares no vocabulary
     * fails outright: {@see CollectVitals} reports no headline at all in
     * that case, so a label there is a producer violation.
     */
    private static function headlineLabel(string $value, string $context, string $path): void
    {
        $declaration = app(CredentialDeclaration::class);
        $vocabulary = $declaration instanceof DeclaresHeadlineStat
            ? $declaration::HEADLINE_VOCABULARY
            : null;

        if (! is_string($vocabulary) || ! enum_exists($vocabulary) || ! is_a($vocabulary, HeadlineLabel::class, true)) {
            Assert::fail(
                $context.': '.$path.' carries a headline label while this app declares no headline vocabulary. '
                .'The producer reports no headline at all in that case, so this payload could not have come from it.',
            );
        }

        $permitted = array_map(
            static fn (HeadlineLabel $case): string|int => $case->value,
            $vocabulary::cases(),
        );

        Assert::assertContains(
            $value,
            $permitted,
            $context.': '.$path.' is not a case of the vocabulary this app declares ('.$vocabulary.'). '
            .'Being identifier-shaped is not membership.',
        );
    }

    /**
     * An endpoint with more than one exact 2xx shape.
     *
     * Fail-closed survives because each alternative is itself an exact
     * shape: the payload must match ONE of them completely, unknown keys
     * and all. This is not "any of these keys may appear"; it is "this
     * is one of these documented shapes".
     *
     * @param  array<string, mixed>  $spec
     */
    private static function oneOf(mixed $value, array $spec, string $context, string $path): void
    {
        /** @var list<array<string, mixed>>|null $shapes */
        $shapes = $spec['shapes'] ?? null;

        Assert::assertIsArray($shapes, $context.': the one_of shape at '.$path.' lists no alternatives.');
        Assert::assertNotEmpty($shapes, $context.': the one_of shape at '.$path.' lists no alternatives.');

        $failures = [];

        foreach ($shapes as $index => $shape) {
            try {
                self::against($value, $shape, $context, $path);
            } catch (AssertionFailedError $failure) {
                $failures[] = '  ['.$index.'] '.$failure->getMessage();

                continue;
            }

            return;
        }

        Assert::fail(
            $context.': '.$path.' matches none of the documented shapes for this endpoint:'.PHP_EOL
            .implode(PHP_EOL, $failures),
        );
    }

    /**
     * @param  array<string, mixed>  $spec
     */
    private static function object(mixed $value, array $spec, string $context, string $path): void
    {
        Assert::assertIsArray($value, $context.': '.$path.' is not an object.');

        $fields = $spec['fields'] ?? null;
        Assert::assertIsArray($fields, $context.': the object shape at '.$path.' names no fields.');

        /** @var array<array-key, mixed> $value */
        $unknown = array_diff(array_map(strval(...), array_keys($value)), array_map(strval(...), array_keys($fields)));

        Assert::assertSame(
            [],
            array_values($unknown),
            $context.': '.$path.' carries keys this shape does not permit: '.implode(', ', $unknown)
            .'. A metadata-classified endpoint is an allowlist; an unrecognised field is a refusal, not a pass.',
        );

        /** @var array<string, mixed> $fields */
        foreach ($fields as $key => $fieldSpec) {
            Assert::assertIsArray($fieldSpec, $context.': the shape at '.$path.'.'.$key.' is not a spec.');

            if (! array_key_exists($key, $value)) {
                Assert::assertTrue(
                    ($fieldSpec['optional'] ?? false) === true,
                    $context.': '.$path.'.'.$key.' is required by this shape and absent from the payload.',
                );

                continue;
            }

            /** @var array<string, mixed> $fieldSpec */
            self::against($value[$key], $fieldSpec, $context, $path.'.'.$key);
        }
    }

    /**
     * @param  array<string, mixed>  $spec
     */
    private static function list(mixed $value, array $spec, string $context, string $path): void
    {
        Assert::assertIsArray($value, $context.': '.$path.' is not a list.');

        /** @var array<array-key, mixed> $value */
        Assert::assertSame(
            array_keys(array_values($value)),
            array_keys($value),
            $context.': '.$path.' is a keyed object where this shape requires a sequential list.',
        );

        /** @var array<string, mixed>|null $of */
        $of = $spec['of'] ?? null;
        Assert::assertIsArray($of, $context.': the list shape at '.$path.' names no item spec.');

        foreach (array_values($value) as $index => $item) {
            self::against($item, $of, $context, $path.'.'.$index);
        }
    }

    /**
     * @param  array<string, mixed>  $spec
     */
    private static function range(int|float $value, array $spec, string $context, string $path): void
    {
        $min = $spec['min'] ?? null;
        $max = $spec['max'] ?? null;

        Assert::assertTrue(is_int($min) || is_float($min), $context.': the numeric shape at '.$path.' states no minimum.');
        Assert::assertTrue(is_int($max) || is_float($max), $context.': the numeric shape at '.$path.' states no maximum.');

        Assert::assertGreaterThanOrEqual($min, $value, $context.': '.$path.' is below the range this shape permits.');
        Assert::assertLessThanOrEqual($max, $value, $context.': '.$path.' is above the range this shape permits.');
    }
}
