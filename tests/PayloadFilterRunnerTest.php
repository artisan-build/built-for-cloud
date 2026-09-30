<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\PassThroughPayloadFilter;
use ArtisanBuild\BuiltForCloud\PayloadFilterRunner;
use ArtisanBuild\BuiltForCloudContracts\OutboundPayload;
use ArtisanBuild\BuiltForCloudContracts\PayloadDisposition;
use ArtisanBuild\BuiltForCloudContracts\PayloadFilter;
use Illuminate\Contracts\Foundation\Application;

function payloadFilterRunnerPayload(PayloadDisposition $disposition = PayloadDisposition::Droppable): OutboundPayload
{
    return new OutboundPayload('assay', 'run.step', 1, $disposition, ['usage' => 10], []);
}

it('resolves the filter on every call so an app rebinding wins', function (): void {
    $runner = new PayloadFilterRunner(app(Application::class));
    $original = payloadFilterRunnerPayload();
    $modified = new OutboundPayload('assay', 'run.step', 1, PayloadDisposition::Droppable, ['usage' => 5], []);
    $reports = [];

    expect($runner->filter($original, function (...$arguments) use (&$reports): void {
        $reports[] = $arguments;
    }))->toBe($original);

    app()->bind(PayloadFilter::class, fn (): PayloadFilter => new readonly class($modified) implements PayloadFilter
    {
        public function __construct(private OutboundPayload $modified) {}

        public function filter(OutboundPayload $payload): OutboundPayload
        {
            return $this->modified;
        }
    });

    expect($runner->filter($original, function (...$arguments) use (&$reports): void {
        $reports[] = $arguments;
    }))->toBe($modified)
        ->and($reports)->toBeEmpty();
});

it('drops and reports a droppable payload when the filter throws', function (): void {
    $sentinel = new RuntimeException('droppable sentinel');
    $payload = payloadFilterRunnerPayload();
    $reports = [];
    app()->instance(PayloadFilter::class, new readonly class($sentinel) implements PayloadFilter
    {
        public function __construct(private Throwable $exception) {}

        public function filter(OutboundPayload $payload): ?OutboundPayload
        {
            throw $this->exception;
        }
    });

    $result = app(PayloadFilterRunner::class)->filter(
        $payload,
        function (OutboundPayload $reportedPayload, ?Throwable $exception) use (&$reports): void {
            $reports[] = [$reportedPayload, $exception];
        },
    );

    expect($result)->toBeNull()
        ->and($reports)->toHaveCount(1)
        ->and($reports[0][0])->toBe($payload)
        ->and($reports[0][1])->toBe($sentinel);
});

it('rethrows the exact filter exception for a deliverable payload without reporting', function (): void {
    $sentinel = new RuntimeException('deliverable sentinel');
    $payload = payloadFilterRunnerPayload(PayloadDisposition::Deliverable);
    $reports = [];
    app()->instance(PayloadFilter::class, new readonly class($sentinel) implements PayloadFilter
    {
        public function __construct(private Throwable $exception) {}

        public function filter(OutboundPayload $payload): ?OutboundPayload
        {
            throw $this->exception;
        }
    });

    try {
        app(PayloadFilterRunner::class)->filter($payload, function (...$arguments) use (&$reports): void {
            $reports[] = $arguments;
        });
        test()->fail('The deliverable filter exception was not rethrown.');
    } catch (Throwable $exception) {
        expect($exception)->toBe($sentinel);
    }

    expect($reports)->toBeEmpty();
});

it('reports an explicit null result for either disposition', function (PayloadDisposition $disposition): void {
    $payload = payloadFilterRunnerPayload($disposition);
    $reports = [];
    app()->instance(PayloadFilter::class, new class implements PayloadFilter
    {
        public function filter(OutboundPayload $payload): ?OutboundPayload
        {
            return null;
        }
    });

    $result = app(PayloadFilterRunner::class)->filter(
        $payload,
        function (OutboundPayload $reportedPayload, ?Throwable $exception) use (&$reports): void {
            $reports[] = [$reportedPayload, $exception];
        },
    );

    expect($result)->toBeNull()
        ->and($reports)->toBe([[$payload, null]]);
})->with(PayloadDisposition::cases());

it('returns a successful filter result by identity without reporting', function (): void {
    $original = payloadFilterRunnerPayload();
    $modified = new OutboundPayload('assay', 'run.step', 1, PayloadDisposition::Droppable, ['usage' => 4], []);
    $reports = [];
    app()->instance(PayloadFilter::class, new readonly class($modified) implements PayloadFilter
    {
        public function __construct(private OutboundPayload $modified) {}

        public function filter(OutboundPayload $payload): OutboundPayload
        {
            return $this->modified;
        }
    });

    expect(app(PayloadFilterRunner::class)->filter($original, function (...$arguments) use (&$reports): void {
        $reports[] = $arguments;
    }))->toBe($modified)
        ->and($reports)->toBeEmpty()
        ->and(app(PayloadFilter::class))->not->toBeInstanceOf(PassThroughPayloadFilter::class);
});
