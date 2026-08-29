<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\Subject;
use Illuminate\Http\Request;

/**
 * An app declaration that refuses named abilities through the
 * `authorize()` hook — the narrowing an app can apply on top of whatever
 * a credential's own abilities list says.
 */
final class RefusingDeclaration implements CredentialDeclaration
{
    /**
     * @var list<string>
     */
    public static array $refuse = [];

    public function resolveSubject(Request $request): ?Subject
    {
        return null;
    }

    public function authorize(Credential $credential, ?string $ability, Request $request): bool
    {
        return $ability === null || ! in_array($ability, self::$refuse, true);
    }
}
