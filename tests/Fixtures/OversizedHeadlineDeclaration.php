<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

/** Declares a vocabulary one case past DeclaresHeadlineStat::MAX_LABELS. */
final class OversizedHeadlineDeclaration extends HeadlineDeclaration
{
    public const ?string HEADLINE_VOCABULARY = OversizedHeadlineLabel::class;
}
