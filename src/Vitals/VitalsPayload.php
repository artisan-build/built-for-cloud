<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Vitals;

use ArtisanBuild\BuiltForCloud\MetadataShape;
use ArtisanBuild\BuiltForCloud\Testing\ContractAssertions;

/**
 * The assembled `GET /bfc/console/vitals` body (Console PRD D9 + D15) —
 * a `metadata`-classified response, so bounded scalars and enums only.
 *
 * What keeps free text out of it is the FIELD SET, not a filter: there is
 * no field here whose value an operator or an end user authors. The two
 * strings that could have carried one are bounded before they arrive —
 * `app_version` is refused unless it matches
 * {@see MetadataShape::SEMVER} ({@see CollectVitals::appVersion}), and
 * `headline.label` is a {@see HeadlineLabel} enum CASE, so its value
 * cannot be runtime data at all ({@see CollectVitals::headline}). `product`, which `GET /bfc/meta`
 * reports and which is exactly such an operator-authored string, is
 * deliberately absent.
 *
 * That claim is checked rather than asserted in prose:
 * {@see ContractAssertions::assertBuiltForCloudMetadataEndpoint} is
 * pointed at this payload in the test suite, against an expected shape
 * enumerated in that trait for this exact route. It requires this exact
 * key set, rejects any key it does not name, and pins each field's type,
 * enum membership and numeric range.
 */
final readonly class VitalsPayload
{
    /**
     * This payload's own shape version, independent of `api_version`.
     * It bumps when a field is removed, renamed or retyped here — the
     * same rule `api_version` follows, at the granularity of one
     * endpoint, so a dashboard can branch on the vitals shape without
     * waiting for a contract major.
     */
    public const int VERSION = 1;

    /**
     * The largest magnitude a headline value may carry, and the widest
     * age in seconds this payload will report.
     *
     * These exist as constants because the route's enumerated expected
     * shape in {@see ContractAssertions} reads them instead of restating
     * numbers of its own. An earlier revision wrote both bounds twice —
     * once in the producer, once in the test-side shape — and they
     * promptly disagreed: the shape rejected magnitudes beyond 1e15 that
     * {@see CollectVitals} was happy to emit, and capped ages at ten
     * years that it computed without limit. A bound written twice is a
     * bound that will disagree with itself, so it is written once and
     * read from here.
     *
     * The values themselves: a headline is a number a person reads off a
     * dashboard, and 1e15 is past the point where a double stops
     * counting in integers at all; a century is past any honest deploy
     * age or queue-wait. Both are generous enough that no real value is
     * refused, and both are bounds, which is what D15's "bounded
     * scalars" asks for. A value outside either is reported as `null`
     * with `degraded` health rather than clamped — a clamped number is a
     * wrong number presented as a right one.
     */
    public const float MAX_HEADLINE_MAGNITUDE = 1.0e15;

    public const int MAX_AGE_SECONDS = 3153600000;

    public function __construct(
        public int $apiVersion,
        public string $bfcVersion,
        public ?string $appVersion,
        public Health $health,
        public ?string $deployedAt,
        public ?int $deployAgeSeconds,
        public QueueVitals $queue,
        public ?HeadlineStat $headline,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'version' => self::VERSION,
            'api_version' => $this->apiVersion,
            'bfc_version' => $this->bfcVersion,
            'app_version' => $this->appVersion,
            'health' => $this->health->value,
            'deployed_at' => $this->deployedAt,
            'deploy_age_seconds' => $this->deployAgeSeconds,
            'queue' => $this->queue->toArray(),
            'headline' => $this->headline === null ? null : [
                'value' => $this->headline->value,
                'label' => $this->headline->label->value,
                'unit' => $this->headline->unit?->value,
            ],
        ];
    }
}
