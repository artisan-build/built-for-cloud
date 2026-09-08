<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

enum AuthorityMode: string
{
    case Standalone = 'standalone';
    case Managed = 'managed';
}
