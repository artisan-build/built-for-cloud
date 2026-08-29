<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Vitals;

use ArtisanBuild\BuiltForCloud\Contracts\DeclaresHeadlineStat;

/**
 * The one app-chosen headline number on the vitals payload (Console PRD
 * D9 + D15): a value, a label CODE, and an optional unit.
 *
 * This class is a CARRIER and validates nothing — the constructor is
 * public and will hold any string in `$label` and any float in `$value`.
 * The bounds live in {@see CollectVitals::headline}, the only thing in
 * this package that ever reads one: it refuses a label outside the app's
 * declared vocabulary ({@see DeclaresHeadlineStat::headlineLabels}), a
 * vocabulary whose own members are not bounded identifiers, and a
 * non-finite value — dropping the headline and degrading the payload
 * rather than forwarding any of them. Constructing one here with a
 * sentence in `$label` is therefore possible and harmless; getting that
 * sentence onto the wire is not.
 */
final readonly class HeadlineStat
{
    public function __construct(
        public int|float $value,
        public string $label,
        public ?HeadlineUnit $unit = null,
    ) {}
}
