<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

final class TokenGenerator
{
    public function generate(): GeneratedToken
    {
        $plaintext = (string) config('built-for-cloud.token_prefix').bin2hex(random_bytes(32));

        return new GeneratedToken(
            plaintext: $plaintext,
            hash: hash('sha256', $plaintext),
        );
    }
}
