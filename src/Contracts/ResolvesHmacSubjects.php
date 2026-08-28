<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Contracts;

use ArtisanBuild\BuiltForCloud\Subject;
use Illuminate\Http\Request;

/**
 * Opt-in extension of {@see CredentialDeclaration} (the package's
 * established extension idiom): derive the SUBJECT an incoming signed
 * message must verify against — SERVER-SIDE, from what the app knows
 * about the request (its route, its tenant resolution), NEVER from the
 * signature header (SEC-V3-07: the verifier selects on the server-derived
 * subject; the untrusted key id only narrows within it).
 *
 * Returning null means "no subject derivable for this request", and the
 * verification middleware fails closed on it.
 */
interface ResolvesHmacSubjects
{
    public function resolveHmacSubject(Request $request): ?Subject;
}
