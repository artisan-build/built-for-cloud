<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use Illuminate\Contracts\Debug\ExceptionHandler as ExceptionHandlerContract;
use Illuminate\Foundation\Exceptions\Handler;
use Illuminate\Http\Exceptions\HttpResponseException;
use Illuminate\Http\JsonResponse;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Route;
use Livewire\LivewireManager;

final class ConsoleOptionalLivewireTest extends TestCase
{
    public function test_the_package_boots_and_keeps_the_plain_response_when_livewire_is_not_registered(): void
    {
        $this->assertFalse($this->app->bound(LivewireManager::class));
        $this->assertArrayNotHasKey(
            'livewire/livewire',
            json_decode((string) file_get_contents(__DIR__.'/../composer.json'), true, 512, JSON_THROW_ON_ERROR)['require'],
        );

        config(['built-for-cloud.console.reentry_url' => 'https://scalpels.test/console/enter']);

        /** @var Handler $handler */
        $handler = $this->app->make(ExceptionHandlerContract::class);
        $handler->renderable(
            static fn (HttpResponseException $exception): JsonResponse => new JsonResponse(['replaced' => true], 599),
        );

        Route::middleware([StartSession::class, 'bfc.console'])
            ->post('/console-plain', fn (): array => ['unexpected' => true]);

        $this->postJson('/console-plain', ['return_to' => '/admin/orders?page=2'])
            ->assertStatus(401)
            ->assertHeader('BFC-Console-Reentry', '1')
            ->assertExactJson([
                'version' => 1,
                'error' => 'console_reentry_required',
                'reason' => 'not_authenticated',
                'reentry_url' => 'https://scalpels.test/console/enter',
                'return_to' => '/admin/orders?page=2',
            ]);
    }
}
