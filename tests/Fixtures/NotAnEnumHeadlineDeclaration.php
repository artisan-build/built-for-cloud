<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

/**
 * Names a class that is not an enum at all. PHP enforces only `?string`
 * on the constant, so this is what an app CAN still write — and the
 * package's runtime checks, not the type, are what refuse it.
 */
final class NotAnEnumHeadlineDeclaration extends HeadlineDeclaration
{
    public const ?string HEADLINE_VOCABULARY = HeadlineDeclaration::class;
}
