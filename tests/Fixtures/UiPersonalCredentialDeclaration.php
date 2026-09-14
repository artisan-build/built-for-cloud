<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Contracts\AuthorizesCredentialVerbs;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresSelfServiceMintPolicy;
use ArtisanBuild\BuiltForCloud\Contracts\ResolvesHmacSubjects;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialVerb;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use Illuminate\Http\Request;

final class UiPersonalCredentialDeclaration implements AuthorizesCredentialVerbs, CredentialDeclaration, DeclaresSelfServiceMintPolicy, ResolvesHmacSubjects
{
    /** @var list<CredentialKind> */
    public static array $kinds = [];

    /** @var list<string> */
    public static array $abilities = [];

    /** @var list<CredentialVerb> */
    public static array $deniedVerbs = [];

    public static bool $resolvesSubject = true;

    public static ?string $subjectRef = null;

    public function resolveSubject(Request $request): ?Subject
    {
        $user = $request->user();

        return $user === null || ! self::$resolvesSubject
            ? null
            : new Subject(SubjectType::UserPrincipal, self::$subjectRef ?? 'ui-user:'.$user->getAuthIdentifier());
    }

    public function resolveHmacSubject(Request $request): ?Subject
    {
        $user = $request->route('user');

        return is_string($user) && $user !== ''
            ? new Subject(SubjectType::UserPrincipal, 'ui-user:'.$user)
            : null;
    }

    public function authorize(Credential $credential, ?string $ability, Request $request): bool
    {
        return true;
    }

    public function authorizeVerb(CredentialVerb $verb, ?Subject $subject, Request $request): bool
    {
        return ! in_array($verb, self::$deniedVerbs, true);
    }

    public function selfServiceAbilities(Subject $subject): array
    {
        return self::$abilities;
    }

    public function selfServiceKinds(Subject $subject): array
    {
        return self::$kinds;
    }
}
