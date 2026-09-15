<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Commands;

use ArtisanBuild\BuiltForCloud\Actions\PruneCredentialAuthorizations;
use ArtisanBuild\BuiltForCloud\Commands\Concerns\ParsesCredentialVerbInput;

final class PruneCredentialAuthorizationsCommand extends SystemAuthorityCommand
{
    use ParsesCredentialVerbInput;

    protected $signature = 'bfc:credential-authorizations:prune
        {--local : Run against the local database, zero Cloud dependency}';

    protected $description = 'Delete credential authorization tombstones after their fixed 24-hour retention';

    public function handle(PruneCredentialAuthorizations $prune): int
    {
        if (! $this->requireLocal()) {
            return self::FAILURE;
        }

        $deleted = $prune();
        $this->line("Pruned {$deleted} credential authorization row(s).");

        return self::SUCCESS;
    }
}
