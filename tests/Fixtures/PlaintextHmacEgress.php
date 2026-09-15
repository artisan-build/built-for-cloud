<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use Symfony\Component\Process\Process;

final class PlaintextHmacEgress
{
    public function leak(string $plaintext): string
    {
        logger($plaintext);
        json_encode($plaintext);
        file_put_contents('/tmp/hmac-positive-control', $plaintext);
        new Process(['example', $plaintext]);

        return $plaintext;
    }
}
