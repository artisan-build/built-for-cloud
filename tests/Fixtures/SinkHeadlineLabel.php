<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Vitals\HeadlineLabel;

/**
 * A sink-shaped app vocabulary (Console PRD D15): a backed enum in the
 * APP's repo, its case set fixed at compile time. This is the whole
 * point of typing the vocabulary as an enum class — this file is what a
 * reviewer reads to know every label the vendor can ever be shown.
 */
enum SinkHeadlineLabel: string implements HeadlineLabel
{
    case ActiveSessions = 'active-sessions';
    case OpenCases = 'open-cases';
}
