<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloudContracts\OutboundPayload;
use ArtisanBuild\BuiltForCloudContracts\PayloadFilter;

final class PassThroughPayloadFilter implements PayloadFilter
{
    public function filter(OutboundPayload $payload): OutboundPayload
    {
        return $payload;
    }
}
