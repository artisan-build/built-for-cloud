<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Middleware;

use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Contracts\ResolvesHmacSubjects;
use ArtisanBuild\BuiltForCloud\Exceptions\HmacVerificationFailed;
use ArtisanBuild\BuiltForCloud\Hmac\HmacEnvelope;
use ArtisanBuild\BuiltForCloud\Hmac\HmacVerifier;
use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The verify half of the middleware pair (PRD 1.21, SEC-V3-07), aliased
 * `bfc.hmac`: put it in front of any route that consumes signed messages.
 * The subject comes from the app's declaration
 * ({@see ResolvesHmacSubjects}) — server-derived per request, never from
 * the header — and every failure is ONE uniform 401: a declaration that
 * cannot derive a subject, a missing header, and every verifier reason
 * are indistinguishable to the caller, so nothing on this surface is an
 * oracle. On success the verified credential's id (never any material)
 * rides the request attributes as `bfc.hmac_credential_id`.
 */
final class VerifyHmacSignature
{
    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $declaration = app(CredentialDeclaration::class);

        if (! $declaration instanceof ResolvesHmacSubjects) {
            return $this->reject();
        }

        $subject = $declaration->resolveHmacSubject($request);

        if ($subject === null) {
            return $this->reject();
        }

        $header = $request->header(HmacEnvelope::HEADER);

        if (! is_string($header) || $header === '') {
            return $this->reject();
        }

        try {
            $credential = app(HmacVerifier::class)->verify($subject, $header, (string) $request->getContent());
        } catch (HmacVerificationFailed) {
            return $this->reject();
        }

        $request->attributes->set('bfc.hmac_credential_id', $credential->id);

        return $next($request);
    }

    private function reject(): JsonResponse
    {
        return response()->json(['message' => 'The request signature could not be verified.'], 401);
    }
}
