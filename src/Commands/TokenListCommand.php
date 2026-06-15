<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Commands;

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\CloudCommandRunner;
use DateTimeInterface;
use Illuminate\Console\Command;
use RuntimeException;

final class TokenListCommand extends Command
{
    protected $signature = 'token:list {--execute} {--json} {--environment=}';

    protected $description = 'List Built for Cloud API tokens';

    public function handle(CloudCommandRunner $runner): int
    {
        if ((bool) $this->option('execute')) {
            $rows = $this->rows();

            if ((bool) $this->option('json')) {
                $this->line((string) json_encode($rows));

                return self::SUCCESS;
            }

            $this->renderTable($rows);

            return self::SUCCESS;
        }

        $environment = $runner->resolveEnvironment($this->stringOption('environment'));
        $result = $runner->run($environment, 'token:list --execute --json');

        if ($result['exitCode'] !== self::SUCCESS) {
            $this->line($result['output']);

            return $result['exitCode'];
        }

        $this->renderTable($this->decodeRows($result['output']));

        return self::SUCCESS;
    }

    /**
     * @return list<array{name: string, status: string, last_used_at: string|null, request_count: int, expires_at: string|null}>
     */
    private function rows(): array
    {
        return ApiToken::query()
            ->orderBy('name')
            ->orderBy('created_at')
            ->get()
            ->map(fn (ApiToken $token): array => [
                'name' => $token->name,
                'status' => $this->status($token),
                'last_used_at' => $this->date($token->last_used_at),
                'request_count' => $token->request_count,
                'expires_at' => $this->date($token->expires_at),
            ])
            ->values()
            ->all();
    }

    private function status(ApiToken $token): string
    {
        if ($token->revoked_at !== null) {
            return 'revoked';
        }

        if ($token->expires_at !== null && $token->expires_at->lessThanOrEqualTo(now())) {
            return 'expired';
        }

        return 'active';
    }

    private function date(?DateTimeInterface $value): ?string
    {
        return $value?->format(DATE_ATOM);
    }

    /**
     * @param  list<array{name: string, status: string, last_used_at: string|null, request_count: int, expires_at: string|null}>  $rows
     */
    private function renderTable(array $rows): void
    {
        $this->table(['Name', 'Status', 'Last Used At', 'Request Count', 'Expires At'], array_map(
            fn (array $row): array => [$row['name'], $row['status'], $row['last_used_at'], $row['request_count'], $row['expires_at']],
            $rows,
        ));
    }

    /**
     * @return list<array{name: string, status: string, last_used_at: string|null, request_count: int, expires_at: string|null}>
     */
    private function decodeRows(string $json): array
    {
        /** @var mixed $decoded */
        $decoded = json_decode($json, true);

        if (! is_array($decoded) || ! array_is_list($decoded)) {
            throw new RuntimeException('Laravel Cloud returned invalid JSON.');
        }

        /** @var list<array{name: string, status: string, last_used_at: string|null, request_count: int, expires_at: string|null}> $decoded */
        return $decoded;
    }

    private function stringOption(string $key): ?string
    {
        $value = $this->option($key);

        return is_string($value) && $value !== '' ? $value : null;
    }
}
