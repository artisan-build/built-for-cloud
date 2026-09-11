<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

enum ManagedTransitionDirection: string
{
    case Adopt = 'adopt';
    case Exit = 'exit';

    public function modeBefore(): AuthorityMode
    {
        return $this === self::Adopt ? AuthorityMode::Standalone : AuthorityMode::Managed;
    }

    public function modeAfter(): AuthorityMode
    {
        return $this === self::Adopt ? AuthorityMode::Managed : AuthorityMode::Standalone;
    }
}
