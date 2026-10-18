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
     * Derive the canonical subject from the supplied request's own user.
     * Read `$request->user()`, not the ambient guard. When the request has a
     * user, never fall back to headers or input. Return null when the request
     * implies no subject.
     *
     * Self-service operations and local-human containment and projection
     * gates call this hook. It may run on every authenticated page view.
     * Keep it fast and side-effect free. Avoid extra I/O.
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
