<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\SubjectType;

/**
 * Test ergonomics for the unified store: mint a credential row whose
 * plaintext lives only in test memory, and present it on subsequent requests.
 * Use on a test case with Laravel's `MakesHttpRequests` (any package or app
 * feature test).
 */
trait WithCredentials
{
    /**
     * Create a presentable credential row and hand back the in-memory
     * plaintext. The secret hash is always derived here — attributes cannot
     * smuggle one in.
     *
     * @param  array<string, mixed>  $attributes
     */
    protected function mintCredential(array $attributes = []): MintedTestCredential
    {
        $plaintext = 'test_'.bin2hex(random_bytes(32));

        $credential = Credential::query()->create(array_merge([
            'kind' => CredentialKind::Bearer,
            'subject_type' => SubjectType::Application,
            'subject_ref' => 'test-subject',
            'status' => CredentialStatus::Active,
        ], $attributes, [
            'secret_hash' => hash('sha256', $plaintext),
        ]));

        return new MintedTestCredential($credential, $plaintext);
    }

    /**
     * Present this credential on every subsequent request in the test, in
     * the `actingAs` style.
     *
     * @return $this
     */
    protected function actingAsCredential(MintedTestCredential $minted): static
    {
        return $this->withHeader('Authorization', $minted->bearerHeader());
    }
}
