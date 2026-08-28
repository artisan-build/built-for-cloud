<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresSelfServiceMintPolicy;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use Illuminate\Http\Request;

/**
 * {@see SelfServiceDeclaration} plus an explicit self-service mint policy
 * (PRD 1.17, rework Fix 2): the app states what its own users may mint
 * for themselves, and that statement — never the requesting user's input
 * — is what the credential gets.
 *
 * Both statics are per test so one fixture covers "grants a narrow
 * ability", "opts a kind in" and "grants nothing at all".
 */
final class SelfServicePolicyDeclaration implements CredentialDeclaration, DeclaresSelfServiceMintPolicy
{
    /**
     * @var list<string>
     */
    public static array $abilities = [];

    /**
     * @var list<CredentialKind>
     */
    public static array $kinds = [CredentialKind::Bearer];

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
    public function selfServiceAbilities(Subject $subject): array
    {
        return self::$abilities;
    }

    /**
     * @return list<CredentialKind>
     */
    public function selfServiceKinds(Subject $subject): array
    {
        return self::$kinds;
    }
}
