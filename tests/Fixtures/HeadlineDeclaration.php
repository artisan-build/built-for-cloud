<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresHeadlineStat;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\Vitals\HeadlineLabel;
use ArtisanBuild\BuiltForCloud\Vitals\HeadlineStat;
use Illuminate\Http\Request;
use Throwable;

/**
 * A sink-shaped app declaration that declares a headline stat (Console
 * PRD D9/D15). Both halves are mutable per test so one fixture covers
 * the honest case, a case from an undeclared enum, an unbounded
 * vocabulary, a declaration that throws, and a stat reported with no
 * vocabulary at all.
 *
 * The vocabulary here is a TEST vocabulary. The package deliberately
 * ships none: D15 puts it in the consuming app's repo.
 */
final class HeadlineDeclaration implements CredentialDeclaration, DeclaresHeadlineStat
{
    /**
     * @var class-string<HeadlineLabel>|null
     */
    public static ?string $vocabulary = null;

    public static ?HeadlineStat $stat = null;

    public static ?Throwable $throws = null;

    public static function reset(): void
    {
        self::$vocabulary = null;
        self::$stat = null;
        self::$throws = null;
    }

    public function resolveSubject(Request $request): ?Subject
    {
        return null;
    }

    public function authorize(Credential $credential, ?string $ability, Request $request): bool
    {
        return true;
    }

    /**
     * @return class-string<HeadlineLabel>|null
     */
    public function headlineVocabulary(): ?string
    {
        if (self::$throws !== null) {
            throw self::$throws;
        }

        return self::$vocabulary;
    }

    public function headlineStat(): ?HeadlineStat
    {
        if (self::$throws !== null) {
            throw self::$throws;
        }

        return self::$stat;
    }
}
