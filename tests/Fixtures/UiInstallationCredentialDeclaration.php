<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Contracts\AuthorizesCredentialVerbs;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Contracts\ResolvesHmacSubjects;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialVerb;
use ArtisanBuild\BuiltForCloud\Subject;
use Illuminate\Http\Request;

final class UiInstallationCredentialDeclaration implements AuthorizesCredentialVerbs, CredentialDeclaration, ResolvesHmacSubjects
{
    public static ?Subject $hmacSubject = null;

    public function resolveSubject(Request $request): ?Subject
    {
        return null;
    }

    public function resolveHmacSubject(Request $request): ?Subject
    {
        return self::$hmacSubject;
    }

    public function authorize(Credential $credential, ?string $ability, Request $request): bool
    {
        return true;
    }

    public function authorizeVerb(CredentialVerb $verb, ?Subject $subject, Request $request): bool
    {
        return true;
    }
}
