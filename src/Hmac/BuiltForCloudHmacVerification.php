<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Hmac;

use ArtisanBuild\BfcClient\Contracts\HmacVerificationConfiguration;

final class BuiltForCloudHmacVerification implements HmacVerificationConfiguration
{
    public function audience(): ?string
    {
        $audience = config('built-for-cloud.hmac.audience');

        return is_string($audience) && $audience !== '' ? $audience : null;
    }

    public function timestampToleranceSeconds(): int
    {
        $tolerance = config('built-for-cloud.hmac.timestamp_tolerance_seconds', 300);

        return is_numeric($tolerance) && (int) $tolerance > 0 ? (int) $tolerance : 300;
    }

    public function verificationRateCeiling(): int
    {
        $ceiling = config('built-for-cloud.hmac.verification_rate_ceiling', 1000);

        return is_numeric($ceiling) && (int) $ceiling > 0 ? (int) $ceiling : 1000;
    }
}
