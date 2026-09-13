<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;

final class UnclassifiedStateChangingCommand extends Command
{
    protected $signature = 'fixture:unclassified-state-change';

    public function handle(): int
    {
        DB::table('fixture_state')->update(['changed' => true]);

        return self::SUCCESS;
    }
}
