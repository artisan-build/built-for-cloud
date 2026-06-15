<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Commands;

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\CloudCommandRunner;
use ArtisanBuild\BuiltForCloud\Contracts\UsageReporter;
use DateTimeInterface;
use Illuminate\Console\Command;

final class TokenUsageCommand extends Command
{
    protected $signature = 'token:usage {name?} {--execute} {--json} {--environment=}';

    protected $description = 'Show Built for Cloud API token usage';

    public function handle(CloudCommandRunner $runner, UsageReporter $reporter): int
    {
        $name = $this->stringArgument('name');

        if ((bool) $this->option('execute')) {
            $rows = $this->rows($reporter, $name);

            if ((bool) $this->option('json')) {
                $this->line((string) json_encode($rows));

                return self::SUCCESS;
            }

            $this->renderTable($rows);

            return self::SUCCESS;
        }

        $environment = $runner->resolveEnvironment($this->stringOption('environment'));
        $command = 'token:usage'.($name === null ? '' : ' '.$this->quote($name)).' --execute --json';
        $result = $runner->run($environment, $command);

        if ($result['exitCode'] !== self::SUCCESS) {
            $this->line($result['output']);

            return $result['exitCode'];
        }

        $this->renderTable($this->decodeRows($result['output']));

        return self::SUCCESS;
    }

    /**
     * @return list<array{name: string, request_count: int, last_used_at: string|null, stats: array<string, mixed>}>
     */
    private function rows(UsageReporter $reporter, ?string $filter): array
    {
        /** @var array<string, array{name: string, request_count: int, last_used_at: DateTimeInterface|null, stats: array<string, mixed>}> $byName */
        $byName = [];

        ApiToken::query()->orderBy('name')->get()->each(function (ApiToken $token) use (&$byName): void {
            if (! isset($byName[$token->name])) {
                $byName[$token->name] = [
                    'name' => $token->name,
                    'request_count' => 0,
                    'last_used_at' => null,
                    'stats' => [],
                ];
            }

            $byName[$token->name]['request_count'] += $token->request_count;

            if ($token->last_used_at !== null && ($byName[$token->name]['last_used_at'] === null || $token->last_used_at > $byName[$token->name]['last_used_at'])) {
                $byName[$token->name]['last_used_at'] = $token->last_used_at;
            }
        });

        foreach ($reporter->perToken() as $name => $stats) {
            if (! isset($byName[$name])) {
                $byName[$name] = [
                    'name' => $name,
                    'request_count' => 0,
                    'last_used_at' => null,
                    'stats' => [],
                ];
            }

            $byName[$name]['stats'] = $stats;
        }

        ksort($byName);

        $rows = [];

        foreach ($byName as $row) {
            if ($filter !== null && $row['name'] !== $filter) {
                continue;
            }

            $rows[] = [
                'name' => $row['name'],
                'request_count' => $row['request_count'],
                'last_used_at' => $this->date($row['last_used_at']),
                'stats' => $row['stats'],
            ];
        }

        return $rows;
    }

    private function date(?DateTimeInterface $value): ?string
    {
        return $value?->format(DATE_ATOM);
    }

    /**
     * @param  list<array{name: string, request_count: int, last_used_at: string|null, stats: array<string, mixed>}>  $rows
     */
    private function renderTable(array $rows): void
    {
        $this->table(['Name', 'Request Count', 'Last Used At', 'Stats'], array_map(
            fn (array $row): array => [$row['name'], $row['request_count'], $row['last_used_at'], json_encode($row['stats'])],
            $rows,
        ));
    }

    /**
     * @return list<array{name: string, request_count: int, last_used_at: string|null, stats: array<string, mixed>}>
     */
    private function decodeRows(string $json): array
    {
        /** @var mixed $decoded */
        $decoded = json_decode($json, true);

        if (! is_array($decoded) || ! array_is_list($decoded)) {
            return [];
        }

        /** @var list<array{name: string, request_count: int, last_used_at: string|null, stats: array<string, mixed>}> $decoded */
        return $decoded;
    }

    private function stringArgument(string $key): ?string
    {
        $value = $this->argument($key);

        return is_string($value) && $value !== '' ? $value : null;
    }

    private function stringOption(string $key): ?string
    {
        $value = $this->option($key);

        return is_string($value) && $value !== '' ? $value : null;
    }

    private function quote(string $value): string
    {
        return escapeshellarg($value);
    }
}
