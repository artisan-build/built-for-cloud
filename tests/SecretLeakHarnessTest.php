<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Testing\DetectsSecretLeaks;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\MarkerCarryingJob;
use Illuminate\Console\Command;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\AssertionFailedError;

uses(RefreshDatabase::class, DetectsSecretLeaks::class);

function leakMarker(): string
{
    return 'leak_'.bin2hex(random_bytes(16));
}

/**
 * Run the watched action expecting the harness to catch a planted leak;
 * hand back the failure it raised (null if it wrongly passed).
 */
function plantAndCatch(Closure $act, string $marker): ?AssertionFailedError
{
    $failure = null;

    try {
        test()->assertNoSecretLeakage($marker, $act);
    } catch (AssertionFailedError $failure) {
    }

    return $failure;
}

it('passes a clean action and returns its result', function (): void {
    $marker = leakMarker();

    $result = $this->assertNoSecretLeakage($marker, function (): string {
        Log::info('nothing secret here');
        Cache::put('benign', 'value', 60);
        session(['benign' => 'value']);

        return 'the-result';
    });

    expect($result)->toBe('the-result');
});

it('detects a marker written to the log', function (): void {
    $marker = leakMarker();

    $failure = plantAndCatch(function () use ($marker): void {
        Log::info('planted '.$marker);
    }, $marker);

    expect($failure)->toBeInstanceOf(AssertionFailedError::class)
        ->and($failure->getMessage())->toContain('[log]')
        ->and($failure->getMessage())->not->toContain($marker);
});

it('detects a marker in log context', function (): void {
    $marker = leakMarker();

    $failure = plantAndCatch(function () use ($marker): void {
        Log::info('a benign message', ['secret' => $marker]);
    }, $marker);

    expect($failure)->toBeInstanceOf(AssertionFailedError::class)
        ->and($failure->getMessage())->toContain('[log]');
});

it('detects a marker inserted into the database', function (): void {
    Schema::create('leak_scratch', function (Blueprint $table): void {
        $table->id();
        $table->string('value');
    });

    $marker = leakMarker();

    $failure = plantAndCatch(function () use ($marker): void {
        DB::table('leak_scratch')->insert(['value' => $marker]);
    }, $marker);

    expect($failure)->toBeInstanceOf(AssertionFailedError::class)
        ->and($failure->getMessage())->toContain('[database]')
        ->and($failure->getMessage())->not->toContain($marker);
});

it('detects a marker written by an update', function (): void {
    Schema::create('leak_scratch', function (Blueprint $table): void {
        $table->id();
        $table->string('value');
    });

    DB::table('leak_scratch')->insert(['value' => 'benign']);

    $marker = leakMarker();

    $failure = plantAndCatch(function () use ($marker): void {
        DB::table('leak_scratch')->where('value', 'benign')->update(['value' => 'now '.$marker]);
    }, $marker);

    expect($failure)->toBeInstanceOf(AssertionFailedError::class)
        ->and($failure->getMessage())->toContain('[database]');
});

it('allows the sha256 of the marker at rest — the intended form', function (): void {
    Schema::create('leak_scratch', function (Blueprint $table): void {
        $table->id();
        $table->string('value');
    });

    $marker = leakMarker();

    $this->assertNoSecretLeakage($marker, function () use ($marker): void {
        DB::table('leak_scratch')->insert(['value' => hash('sha256', $marker)]);
    });

    expect(DB::table('leak_scratch')->count())->toBe(1);
});

it('detects a marker riding in a queued job payload', function (): void {
    $marker = leakMarker();

    $failure = plantAndCatch(function () use ($marker): void {
        MarkerCarryingJob::dispatch($marker);
    }, $marker);

    expect($failure)->toBeInstanceOf(AssertionFailedError::class)
        ->and($failure->getMessage())->toContain('[queue]')
        ->and($failure->getMessage())->not->toContain($marker);
});

it('detects a marker written to the cache', function (): void {
    $marker = leakMarker();

    $failure = plantAndCatch(function () use ($marker): void {
        Cache::put('planted', $marker, 60);
    }, $marker);

    expect($failure)->toBeInstanceOf(AssertionFailedError::class)
        ->and($failure->getMessage())->toContain('[cache]');
});

it('detects a marker put into the session', function (): void {
    $marker = leakMarker();

    $failure = plantAndCatch(function () use ($marker): void {
        session(['planted' => $marker]);
    }, $marker);

    expect($failure)->toBeInstanceOf(AssertionFailedError::class)
        ->and($failure->getMessage())->toContain('[session]')
        ->and($failure->getMessage())->not->toContain($marker);
});

it('detects a marker echoed in a response body', function (): void {
    $marker = leakMarker();

    Route::get('/leaky', fn (): array => ['token' => $marker]);

    $response = $this->getJson('/leaky');

    $failure = null;

    try {
        $this->assertResponseCarriesNoSecret($response, $marker);
    } catch (AssertionFailedError $failure) {
    }

    expect($failure)->toBeInstanceOf(AssertionFailedError::class)
        ->and($failure->getMessage())->toContain('[response]');
});

it('detects a marker riding in a response header', function (): void {
    $marker = leakMarker();

    Route::get('/leaky-header', fn () => response()->json(['ok' => true], 200, ['X-Debug-Token' => $marker]));

    $response = $this->getJson('/leaky-header');

    $failure = null;

    try {
        $this->assertResponseCarriesNoSecret($response, $marker);
    } catch (AssertionFailedError $failure) {
    }

    expect($failure)->toBeInstanceOf(AssertionFailedError::class)
        ->and($failure->getMessage())->toContain('[response]')
        ->and($failure->getMessage())->toContain('x-debug-token');
});

it('passes a response that carries no marker', function (): void {
    $marker = leakMarker();

    Route::get('/clean', fn (): array => ['ok' => true]);

    $this->assertResponseCarriesNoSecret($this->getJson('/clean'), $marker);
});

it('detects a marker printed to console output', function (): void {
    $marker = leakMarker();

    Artisan::command('leak:print', function () use ($marker): void {
        /** @var Command $this */
        $this->line('first '.$marker);
        $this->line('second '.$marker);
    });

    Artisan::call('leak:print');

    $failure = null;

    try {
        $this->assertConsoleOutputCarriesNoSecret(Artisan::output(), $marker);
    } catch (AssertionFailedError $failure) {
    }

    expect($failure)->toBeInstanceOf(AssertionFailedError::class)
        ->and($failure->getMessage())->toContain('[console]');
});

it('passes console output that carries no marker', function (): void {
    $marker = leakMarker();

    $this->assertConsoleOutputCarriesNoSecret('nothing to see here', $marker);
});

it('detects a marker in an exception message', function (): void {
    $marker = leakMarker();

    $failure = null;

    try {
        $this->assertExceptionCarriesNoSecret(new RuntimeException('kaboom '.$marker), $marker);
    } catch (AssertionFailedError $failure) {
    }

    expect($failure)->toBeInstanceOf(AssertionFailedError::class)
        ->and($failure->getMessage())->toContain('[exception]');
});

it('detects a marker buried in an exception previous chain', function (): void {
    $marker = leakMarker();

    $exception = new RuntimeException('outer, clean', 0, new RuntimeException('inner '.$marker));

    $failure = null;

    try {
        $this->assertExceptionCarriesNoSecret($exception, $marker);
    } catch (AssertionFailedError $failure) {
    }

    // PHP's exception rendering includes the previous chain, so the outer
    // exception's own rendered form already carries the inner marker —
    // detection at depth 0 is the correct catch.
    expect($failure)->toBeInstanceOf(AssertionFailedError::class)
        ->and($failure->getMessage())->toContain('[exception]');
});

it('passes an exception that carries no marker', function (): void {
    $marker = leakMarker();

    $this->assertExceptionCarriesNoSecret(new RuntimeException('clean'), $marker);
});

it('resets cleanly between watches in the same test', function (): void {
    $first = leakMarker();

    $failure = plantAndCatch(function () use ($first): void {
        Log::info('planted '.$first);
    }, $first);

    expect($failure)->toBeInstanceOf(AssertionFailedError::class);

    // A fresh watch starts clean: the earlier planted record is gone and a
    // clean action passes.
    $second = leakMarker();

    $this->assertNoSecretLeakage($second, function (): void {
        Log::info('all quiet');
    });
});

it('fails when asserting without a watch', function (): void {
    $failure = null;

    try {
        $this->assertNoLeaks();
    } catch (AssertionFailedError $failure) {
    }

    expect($failure)->toBeInstanceOf(AssertionFailedError::class)
        ->and($failure->getMessage())->toContain('beginLeakWatch');
});
