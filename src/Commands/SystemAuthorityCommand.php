<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Commands;

use ArtisanBuild\BuiltForCloud\SystemAuthorityContext;
use Illuminate\Console\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

abstract class SystemAuthorityCommand extends Command
{
    final public function run(InputInterface $input, OutputInterface $output): int
    {
        return app(SystemAuthorityContext::class)->run(
            fn (): int => parent::run($input, $output),
        );
    }
}
