<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Commands;

use ArtisanBuild\BuiltForCloud\Actions\ListCredentials;
use ArtisanBuild\BuiltForCloud\Commands\Concerns\ParsesCredentialVerbInput;
use ArtisanBuild\BuiltForCloud\CredentialSummary;
use Illuminate\Console\Command;

/**
 * The list verb's CLI transport (PRD 1.0 + 1.6). `--json` emits exactly
 * the rows the HTTP transport serves — the same action, the same
 * serialization — which is what the transport-parity suite asserts.
 */
final class CredentialListCommand extends Command
{
    use ParsesCredentialVerbInput;

    protected $signature = 'bfc:credential:list
        {--json : Emit the rows as JSON (the HTTP listing shape)}
        {--local : Run against the local database, zero Cloud dependency}';

    protected $description = 'List the unified credential store';

    public function handle(ListCredentials $list): int
    {
        if (! $this->requireLocal()) {
            return self::FAILURE;
        }

        $rows = array_map(
            static fn (CredentialSummary $summary): array => $summary->toArray(),
            $list(),
        );

        if ((bool) $this->option('json')) {
            $this->line((string) json_encode($rows));

            return self::SUCCESS;
        }

        $this->table(
            ['Id', 'Kind', 'Subject', 'Name', 'Status', 'Abilities', 'Last Used At', 'Expires At', 'Unsupported'],
            array_map(static fn (array $row): array => [
                $row['id'],
                $row['kind'],
                $row['subject_type'].':'.$row['subject_ref'],
                $row['name'],
                $row['status'],
                $row['abilities'] === null ? null : implode(',', $row['abilities']),
                $row['last_used_at'],
                $row['expires_at'],
                implode(',', $row['unsupported']),
            ], $rows),
        );

        return self::SUCCESS;
    }
}
