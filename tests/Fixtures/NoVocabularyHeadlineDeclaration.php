<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

/**
 * Implements the interface and declares NO vocabulary — the inherited
 * null. Reporting a stat anyway is a contradiction in the app's own
 * declaration, and degrades.
 */
final class NoVocabularyHeadlineDeclaration extends HeadlineDeclaration
{
    public const ?string HEADLINE_VOCABULARY = null;
}
