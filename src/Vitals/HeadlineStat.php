<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Vitals;

/**
 * The one app-chosen headline number on the vitals payload (Console PRD
 * D9 + D15): a value, a label CASE, and an optional unit.
 *
 * `$label` is a {@see HeadlineLabel} — an enum case from the app's own
 * declared vocabulary — rather than a string, so there is no
 * constructor call that can put an arbitrary value in this field. What
 * the type cannot decide, {@see CollectVitals::headline} does: that the
 * case belongs to the vocabulary this app DECLARED (not some other
 * enum), that the vocabulary's own cases are bounded identifiers, and
 * that `$value` is finite. A failure of any of those drops the headline
 * and degrades the payload; none of them reaches the wire.
 */
final readonly class HeadlineStat
{
    public function __construct(
        public int|float $value,
        public HeadlineLabel $label,
        public ?HeadlineUnit $unit = null,
    ) {}
}
