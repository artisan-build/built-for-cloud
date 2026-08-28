<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use ArtisanBuild\BuiltForCloud\Credential;

/**
 * A credential row plus the in-memory plaintext a test presents. The
 * plaintext exists ONLY here, in test memory — the store persists the hash.
 */
final readonly class MintedTestCredential
{
    public function __construct(
        public Credential $credential,
        public string $plaintext,
    ) {}

    public function bearerHeader(): string
    {
        return 'Bearer '.$this->plaintext;
    }

    /**
     * The Composer `auth.json` shape: the username is decorative, the
     * password is the secret.
     */
    public function basicHeader(string $username = 'token'): string
    {
        return 'Basic '.base64_encode($username.':'.$this->plaintext);
    }
}
