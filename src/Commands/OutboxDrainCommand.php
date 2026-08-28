<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Commands;

use ArtisanBuild\BuiltForCloud\OutboxDrainer;
use Illuminate\Console\Command;

/**
 * Re-drain the transactional outbox: anything the synchronous post-commit
 * dispatcher failed to deliver — a subscriber that threw, a process that
 * died mid-delivery — stays claimable and is delivered here. Safe to run
 * any time; delivery is idempotent.
 */
final class OutboxDrainCommand extends Command
{
    protected $signature = 'bfc:outbox:drain';

    protected $description = 'Deliver pending Built for Cloud lifecycle notifications from the outbox';

    public function handle(OutboxDrainer $drainer): int
    {
        $delivered = $drainer->drain();

        $this->line("Delivered {$delivered} pending outbox row(s).");

        return self::SUCCESS;
    }
}
