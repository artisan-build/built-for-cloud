<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresUnsupportedSummaryFields;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use Illuminate\Http\Request;

/**
 * A capstan-shaped declaration for the personal-credentials surface (PRD
 * 1.17): the subject is the AUTHENTICATED USER, derived from the request's
 * own session and from nothing the caller sent (SEC-V3-07).
 *
 * `$unsupported` is mutable per test so the same declaration can be made
 * THINNER — the "a thinner declaration renders less" case (PRD 1.6).
 */
final class SelfServiceDeclaration implements CredentialDeclaration, DeclaresUnsupportedSummaryFields
{
    /**
     * @var list<string>
     */
    public static array $unsupported = [];

    /**
     * The whole point of the surface: the subject comes from
     * `$request->user()` — the session — and a `subject_ref` in the body
     * is never consulted, so a crafted one changes nothing.
     */
    public function resolveSubject(Request $request): ?Subject
    {
        $user = $request->user();

        if ($user === null) {
            return null;
        }

        return new Subject(SubjectType::UserPrincipal, 'user:'.$user->getAuthIdentifier());
    }

    public function authorize(Credential $credential, ?string $ability, Request $request): bool
    {
        return true;
    }

    /**
     * @return list<string>
     */
    public function unsupportedSummaryFields(): array
    {
        return self::$unsupported;
    }
}
