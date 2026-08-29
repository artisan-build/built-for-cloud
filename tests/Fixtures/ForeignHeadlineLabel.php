<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Vitals\HeadlineLabel;

/**
 * A second, bounded vocabulary that the app does NOT declare. Reporting
 * a case from it is the enum-typed equivalent of a label outside the
 * vocabulary: the marker interface alone does not make a case a member
 * of THIS app's declared set.
 */
enum ForeignHeadlineLabel: string implements HeadlineLabel
{
    case SomeoneElsesLabel = 'someone-elses-label';
}
