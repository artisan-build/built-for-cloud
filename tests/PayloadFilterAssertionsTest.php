<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Testing\PayloadFilterAssertions;
use ArtisanBuild\BuiltForCloudContracts\OutboundPayload;
use ArtisanBuild\BuiltForCloudContracts\PayloadDisposition;
use ArtisanBuild\BuiltForCloudContracts\PayloadFilter;
use Illuminate\Contracts\Foundation\Application;
use PHPUnit\Framework\AssertionFailedError;

function payloadFilterAssertionSamples(): array
{
    return [
        'assay' => new OutboundPayload('assay', 'run.step', 1, PayloadDisposition::Droppable, ['usage' => 10], []),
        'hone' => new OutboundPayload('hone', 'request', 1, PayloadDisposition::Droppable, ['duration' => 50], []),
        'mail' => new OutboundPayload('mail', 'message', 1, PayloadDisposition::Deliverable, ['subject' => 'Hello'], []),
    ];
}

it('allows handled products to change or drop while requiring unhandled products to pass through', function (): void {
    app()->instance(PayloadFilter::class, new class implements PayloadFilter
    {
        public function filter(OutboundPayload $payload): ?OutboundPayload
        {
            return $payload->product === 'assay' ? null : $payload;
        }
    });

    PayloadFilterAssertions::assertPassesThroughUnhandledProducts(
        app(Application::class),
        payloadFilterAssertionSamples(),
        ['assay'],
    );

    expect(true)->toBeTrue();
});

it('names an unhandled product whose payload is altered', function (): void {
    app()->instance(PayloadFilter::class, new class implements PayloadFilter
    {
        public function filter(OutboundPayload $payload): ?OutboundPayload
        {
            return $payload->product === 'hone'
                ? new OutboundPayload('hone', 'request', 1, PayloadDisposition::Droppable, [], [])
                : $payload;
        }
    });

    expect(fn () => PayloadFilterAssertions::assertPassesThroughUnhandledProducts(
        app(Application::class),
        payloadFilterAssertionSamples(),
        ['assay'],
    ))->toThrow(AssertionFailedError::class, 'Unhandled product [hone]');
});

it('names an unhandled product whose payload is dropped', function (): void {
    app()->instance(PayloadFilter::class, new class implements PayloadFilter
    {
        public function filter(OutboundPayload $payload): ?OutboundPayload
        {
            return $payload->product === 'mail' ? null : $payload;
        }
    });

    expect(fn () => PayloadFilterAssertions::assertPassesThroughUnhandledProducts(
        app(Application::class),
        payloadFilterAssertionSamples(),
        ['assay'],
    ))->toThrow(AssertionFailedError::class, 'Unhandled product [mail]');
});

it('names an unhandled product whose filter throws', function (): void {
    app()->instance(PayloadFilter::class, new class implements PayloadFilter
    {
        public function filter(OutboundPayload $payload): ?OutboundPayload
        {
            if ($payload->product === 'hone') {
                throw new RuntimeException('sentinel');
            }

            return $payload;
        }
    });

    expect(fn () => PayloadFilterAssertions::assertPassesThroughUnhandledProducts(
        app(Application::class),
        payloadFilterAssertionSamples(),
        ['assay'],
    ))->toThrow(AssertionFailedError::class, 'Unhandled product [hone]');
});

it('fails clearly when a sample key does not match its payload product', function (): void {
    expect(fn () => PayloadFilterAssertions::assertPassesThroughUnhandledProducts(
        app(Application::class),
        ['wrong-key' => payloadFilterAssertionSamples()['hone']],
        [],
    ))->toThrow(AssertionFailedError::class, 'Payload sample key [wrong-key] does not match its product [hone]');
});
