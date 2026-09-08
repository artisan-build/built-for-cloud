<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use Illuminate\Database\Eloquent\Model;

interface RogueIdentityContext
{
    public function user(): Model;
}
