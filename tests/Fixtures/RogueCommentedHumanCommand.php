<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\AuditActor;
use Illuminate\Console\Command;

/** This class deliberately puts the word class before its declaration. */
final class RogueCommentedHumanCommand extends Command
{
    protected $signature = 'fixture:rogue-commented-human';

    public function handle(): int
    {
        AuditActor::boundUser('synthetic-operator');

        return self::SUCCESS;
    }
}
