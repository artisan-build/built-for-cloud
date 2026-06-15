<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use Illuminate\Support\Facades\Process;
use RuntimeException;

use function Laravel\Prompts\select;

final class CloudCommandRunner
{
    public function resolveEnvironment(?string $explicit = null): string
    {
        if ($explicit !== null && $explicit !== '') {
            return $explicit;
        }

        $application = $this->applicationId();

        $result = Process::run([
            $this->binary(),
            'environment:list',
            $application,
            '--json',
            '--fields=id,name',
        ]);

        if (! $result->successful()) {
            throw new RuntimeException('Unable to list Laravel Cloud environments: '.$result->errorOutput());
        }

        $environments = $this->decodeJsonArray($result->output());

        if ($environments === []) {
            throw new RuntimeException('No environments found for Laravel Cloud application '.$application.'.');
        }

        if (count($environments) === 1) {
            return (string) $environments[0]['id'];
        }

        /** @var array<string, string> $choices */
        $choices = [];

        foreach ($environments as $environment) {
            $id = (string) $environment['id'];
            $name = (string) ($environment['name'] ?? $id);
            $choices[$id] = $name;
        }

        return (string) select(
            label: 'Select the Laravel Cloud environment',
            options: $choices,
        );
    }

    /**
     * @return array{output: string, exitCode: int}
     */
    public function run(string $environment, string $artisanCommand): array
    {
        $result = Process::run([
            $this->binary(),
            'command:run',
            $environment,
            '--cmd',
            'php artisan '.$artisanCommand,
            '--json',
            '--fields=output,exitCode',
            '--no-interaction',
        ]);

        if (! $result->successful()) {
            throw new RuntimeException('Laravel Cloud command failed: '.$result->errorOutput());
        }

        /** @var array{output?: mixed, exitCode?: mixed} $payload */
        $payload = $this->decodeJsonObject($result->output());

        return [
            'output' => (string) ($payload['output'] ?? ''),
            'exitCode' => (int) ($payload['exitCode'] ?? 0),
        ];
    }

    private function binary(): string
    {
        return (string) config('built-for-cloud.cloud.binary', 'cloud');
    }

    private function applicationId(): string
    {
        $configured = config('built-for-cloud.cloud.application');

        if (is_string($configured) && $configured !== '') {
            return $configured;
        }

        $path = base_path('.cloud/config.json');

        if (is_file($path)) {
            /** @var mixed $decoded */
            $decoded = json_decode((string) file_get_contents($path), true);

            if (is_array($decoded) && isset($decoded['application_id']) && is_string($decoded['application_id']) && $decoded['application_id'] !== '') {
                return $decoded['application_id'];
            }
        }

        throw new RuntimeException('No Laravel Cloud application id configured. Set built-for-cloud.cloud.application or .cloud/config.json application_id.');
    }

    /**
     * @return list<array{id: mixed, name?: mixed}>
     */
    private function decodeJsonArray(string $json): array
    {
        /** @var mixed $decoded */
        $decoded = json_decode($json, true);

        if (! is_array($decoded) || ! array_is_list($decoded)) {
            throw new RuntimeException('Laravel Cloud returned invalid JSON.');
        }

        /** @var list<array{id: mixed, name?: mixed}> $decoded */
        return $decoded;
    }

    /**
     * @return array<string, mixed>
     */
    private function decodeJsonObject(string $json): array
    {
        /** @var mixed $decoded */
        $decoded = json_decode($json, true);

        if (! is_array($decoded) || array_is_list($decoded)) {
            throw new RuntimeException('Laravel Cloud returned invalid JSON.');
        }

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }
}
