<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Auth;

use ArtisanBuild\BuiltForCloud\Contracts\CredentialAuthenticator;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use Illuminate\Http\Request;

/**
 * HTTP Basic (the Composer `auth.json` shape) against `basic` rows. The
 * password half is the secret; the username is presentation-only and grants
 * nothing. A malformed header authenticates nothing.
 */
final class BasicAuthenticator implements CredentialAuthenticator
{
    public function __construct(private readonly CredentialResolver $resolver) {}

    public function credential(Request $request): ?Credential
    {
        $header = $request->headers->get('Authorization');

        if ($header === null || stripos($header, 'Basic ') !== 0) {
            return null;
        }

        $decoded = base64_decode(substr($header, 6), true);

        if ($decoded === false || ! str_contains($decoded, ':')) {
            return null;
        }

        [, $password] = explode(':', $decoded, 2);

        return $this->resolver->resolve(CredentialKind::Basic, $password);
    }
}
