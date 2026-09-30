<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloudContracts\OutboundPayload;
use ArtisanBuild\BuiltForCloudContracts\PayloadDisposition;
use ArtisanBuild\BuiltForCloudContracts\PayloadFilter as ContractsPayloadFilter;
use Closure;
use Illuminate\Contracts\Foundation\Application;
use Throwable;

final readonly class PayloadFilterRunner
{
    public function __construct(private Application $app) {}

    /**
     * @param  Closure(OutboundPayload, ?Throwable): void  $reportHookDrop
     */
    public function filter(OutboundPayload $payload, Closure $reportHookDrop): ?OutboundPayload
    {
        try {
            $filtered = $this->app->make(ContractsPayloadFilter::class)->filter($payload);
        } catch (Throwable $exception) {
            if ($payload->disposition === PayloadDisposition::Deliverable) {
                throw $exception;
            }

            $reportHookDrop($payload, $exception);

            return null;
        }

        if ($filtered === null) {
            $reportHookDrop($payload, null);
        }

        return $filtered;
    }
}
