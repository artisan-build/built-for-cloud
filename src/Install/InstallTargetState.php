<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Install;

enum InstallTargetState: string
{
    case Unchanged = 'unchanged';
    case Replaced = 'replaced';
    case Failed = 'failed';
}
