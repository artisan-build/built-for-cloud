<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Contracts;

use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\Subject;
use Illuminate\Http\Request;

/**
 * An app's declaration is EXECUTABLE, not metadata: the framework calls these
 * hooks on every credentialed request. Register a class via the
 * `built-for-cloud.credentials.declaration` config key or by binding this
 * interface in the container.
 */
interface CredentialDeclaration
{
    /**
     * Derive the subject a self-service surface should act for, from the
     * authenticated request — server-side, never from client input. Return
     * null when this request implies no subject. Consumed by the
     * self-service surfaces in later package versions; the guard does not
     * call it.
     */
    public function resolveSubject(Request $request): ?Subject;

    /**
     * Authorize an authenticated credential for this request. Called by the
     * guard with a null ability on every credentialed request, and by the
     * abilities middleware with the required ability string. Returning false
     * produces a 403 even for an otherwise-valid credential.
     *
     * The credential's `subject_ref` is an INPUT to this decision, never the
     * check itself: possession of a subject_ref or a name proves nothing.
     */
    public function authorize(Credential $credential, ?string $ability, Request $request): bool;
}
