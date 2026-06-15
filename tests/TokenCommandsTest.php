<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\Contracts\UsageReporter;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Process;

uses(RefreshDatabase::class);

it('runs token create in driver mode without sending plaintext to cloud', function (): void {
    Process::fake([
        '*' => Process::result('{"output":"Token app stored.\\n","exitCode":0}'),
    ]);

    Artisan::call('token:create', [
        'name' => 'app',
        '--environment' => 'env-1',
    ]);

    $output = Artisan::output();

    preg_match('/Save this token - shown once: (tok_[0-9a-f]{64})/', $output, $matches);
    $plaintext = $matches[1] ?? '';
    $hash = hash('sha256', $plaintext);

    expect($plaintext)->not->toBe('')
        ->and(substr_count($output, $plaintext))->toBe(1);

    Process::assertRan(function ($process) use ($plaintext, $hash): bool {
        $command = $process->command[4] ?? '';

        return is_string($command)
            && str_contains($command, 'token:create')
            && str_contains($command, '--execute')
            && str_contains($command, '--hash='.$hash)
            && ! str_contains($command, $plaintext);
    });
});

it('creates a token row in execute mode', function (): void {
    $hash = hash('sha256', 'create-secret');

    Artisan::call('token:create', [
        'name' => 'app',
        '--execute' => true,
        '--hash' => $hash,
    ]);

    expect(ApiToken::query()->where('name', 'app')->where('token_hash', $hash)->exists())->toBeTrue();
});

it('runs token rotate in driver mode without sending plaintext to cloud', function (): void {
    Process::fake([
        '*' => Process::result('{"output":"Token app rotated with one hour grace.\\n","exitCode":0}'),
    ]);

    Artisan::call('token:rotate', [
        'name' => 'app',
        '--environment' => 'env-1',
    ]);

    $output = Artisan::output();

    preg_match('/Save this token - shown once: (tok_[0-9a-f]{64})/', $output, $matches);
    $plaintext = $matches[1] ?? '';
    $hash = hash('sha256', $plaintext);

    expect($plaintext)->not->toBe('')
        ->and(substr_count($output, $plaintext))->toBe(1);

    Process::assertRan(function ($process) use ($plaintext, $hash): bool {
        $command = $process->command[4] ?? '';

        return is_string($command)
            && str_contains($command, 'token:rotate')
            && str_contains($command, '--execute')
            && str_contains($command, '--hash='.$hash)
            && ! str_contains($command, $plaintext);
    });
});

it('forwards emergency mode when rotating tokens in driver mode', function (): void {
    Process::fake([
        '*' => Process::result('{"output":"Token app rotated with emergency expiry.\\n","exitCode":0}'),
    ]);

    Artisan::call('token:rotate', [
        'name' => 'app',
        '--environment' => 'env-1',
        '--emergency' => true,
    ]);

    Process::assertRan(function ($process): bool {
        $command = $process->command[4] ?? '';

        return is_string($command)
            && str_contains($command, 'token:rotate')
            && str_contains($command, '--execute')
            && str_contains($command, '--emergency');
    });
});

it('rotates tokens in execute mode with emergency expiry', function (): void {
    $old = ApiToken::query()->create([
        'name' => 'app',
        'token_hash' => hash('sha256', 'old-secret'),
    ]);

    Artisan::call('token:rotate', [
        'name' => 'app',
        '--execute' => true,
        '--hash' => hash('sha256', 'new-secret'),
        '--emergency' => true,
    ]);

    $old->refresh();

    expect($old->expires_at?->lessThanOrEqualTo(now()))->toBeTrue()
        ->and(ApiToken::query()->where('token_hash', hash('sha256', 'new-secret'))->whereNull('expires_at')->exists())->toBeTrue();
});

it('rotates tokens in execute mode with a one hour grace period', function (): void {
    $old = ApiToken::query()->create([
        'name' => 'app',
        'token_hash' => hash('sha256', 'old-grace-secret'),
    ]);

    Artisan::call('token:rotate', [
        'name' => 'app',
        '--execute' => true,
        '--hash' => hash('sha256', 'new-grace-secret'),
    ]);

    $old->refresh();

    expect($old->expires_at?->greaterThan(now()->addMinutes(59)))->toBeTrue()
        ->and(ApiToken::query()->where('token_hash', hash('sha256', 'new-grace-secret'))->whereNull('expires_at')->exists())->toBeTrue();
});

it('revokes tokens in execute mode and reports the count', function (): void {
    ApiToken::query()->create([
        'name' => 'app',
        'token_hash' => hash('sha256', 'revoke-secret'),
    ]);

    Artisan::call('token:revoke', [
        'name' => 'app',
        '--execute' => true,
    ]);

    expect(Artisan::output())->toContain('Revoked 1 active row(s) for app');
});

it('lists tokens as json without exposing token hashes', function (): void {
    ApiToken::query()->create([
        'name' => 'app',
        'token_hash' => hash('sha256', 'list-secret'),
    ]);

    Artisan::call('token:list', [
        '--execute' => true,
        '--json' => true,
    ]);

    $output = Artisan::output();
    $decoded = json_decode($output, true);

    expect($decoded[0]['name'])->toBe('app')
        ->and($decoded[0]['status'])->toBe('active')
        ->and($output)->not->toContain('token_hash')
        ->and($output)->not->toContain(hash('sha256', 'list-secret'));
});

it('reports token usage as json with bound reporter stats', function (): void {
    app()->singleton(UsageReporter::class, fn (): UsageReporter => new class implements UsageReporter
    {
        /**
         * @return array<string, array<string, mixed>>
         */
        public function perToken(): array
        {
            return ['app' => ['jobs' => 12]];
        }
    });

    ApiToken::query()->create([
        'name' => 'app',
        'token_hash' => hash('sha256', 'usage-secret'),
        'request_count' => 3,
        'last_used_at' => now(),
    ]);

    Artisan::call('token:usage', [
        '--execute' => true,
        '--json' => true,
    ]);

    $decoded = json_decode(Artisan::output(), true);

    expect($decoded[0]['name'])->toBe('app')
        ->and($decoded[0]['request_count'])->toBe(3)
        ->and($decoded[0]['last_used_at'])->not->toBeNull()
        ->and($decoded[0]['stats']['jobs'])->toBe(12);
});

it('writes and updates fallback tokens in the target env file', function (): void {
    $path = tempnam(sys_get_temp_dir(), 'bfc-env-');

    file_put_contents($path, "APP_NAME=Testing\nFALLBACK_TOKEN=old\n");

    Artisan::call('fallback-token:generate', [
        '--path' => $path,
        '--show' => true,
    ]);

    $contents = (string) file_get_contents($path);

    preg_match('/^FALLBACK_TOKEN=(tok_[0-9a-f]{64})$/m', $contents, $matches);

    expect($matches[1] ?? null)->not->toBeNull()
        ->and($contents)->not->toContain('FALLBACK_TOKEN=old')
        ->and(Artisan::output())->toContain('FALLBACK_TOKEN='.($matches[1] ?? ''));
});
