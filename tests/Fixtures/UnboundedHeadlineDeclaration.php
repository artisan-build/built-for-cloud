<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

/** Declares a compile-time vocabulary whose cases are not bounded identifiers. */
final class UnboundedHeadlineDeclaration extends HeadlineDeclaration
{
    public const ?string HEADLINE_VOCABULARY = UnboundedHeadlineLabel::class;
}
