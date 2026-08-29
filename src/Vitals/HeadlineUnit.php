<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Vitals;

/**
 * The closed unit vocabulary a headline stat may carry (Console PRD D15).
 * A stat with no meaningful unit declares `null` rather than inventing a
 * word for it — the whole point of D15 is that no free text reaches the
 * vendor, and "unit" is exactly the field an app would otherwise use to
 * send one.
 */
enum HeadlineUnit: string
{
    case Count = 'count';
    case Seconds = 'seconds';
    case Bytes = 'bytes';
    case Percent = 'percent';
}
