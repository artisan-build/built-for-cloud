<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Vitals\HeadlineLabel;

/**
 * A vocabulary that IS compile-time and is still not bounded: its case
 * backs onto free text. The enum type stops runtime data; it does not
 * stop an app writing prose into a case, which is why CollectVitals
 * checks every case value against the bounded-identifier shape.
 */
enum UnboundedHeadlineLabel: string implements HeadlineLabel
{
    case Whatever = 'whatever the operator typed today';
}
