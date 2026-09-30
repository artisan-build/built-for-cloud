<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use ArtisanBuild\BuiltForCloudContracts\OutboundPayload;
use ArtisanBuild\BuiltForCloudContracts\PayloadFilter;
use Illuminate\Contracts\Foundation\Application;
use PHPUnit\Framework\Assert;
use Throwable;

final class PayloadFilterAssertions
{
    /**
     * @param  array<string, OutboundPayload>  $samples
     * @param  list<string>  $handledProducts
     */
    public static function assertPassesThroughUnhandledProducts(
        Application $app,
        array $samples,
        array $handledProducts,
    ): void {
        foreach ($samples as $product => $payload) {
            Assert::assertSame(
                $product,
                $payload->product,
                sprintf('Payload sample key [%s] does not match its product [%s].', $product, $payload->product),
            );

            if (in_array($product, $handledProducts, true)) {
                continue;
            }

            try {
                $filtered = $app->make(PayloadFilter::class)->filter($payload);
            } catch (Throwable $exception) {
                Assert::fail(sprintf(
                    'Unhandled product [%s] threw %s: %s',
                    $product,
                    $exception::class,
                    $exception->getMessage(),
                ));
            }

            Assert::assertSame(
                $payload,
                $filtered,
                sprintf('Unhandled product [%s] must pass through as the exact input payload.', $product),
            );
        }
    }
}
