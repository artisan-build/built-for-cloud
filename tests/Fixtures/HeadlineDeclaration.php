<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresHeadlineStat;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\Vitals\HeadlineStat;
use Illuminate\Http\Request;
use Throwable;

/**
 * A sink-shaped app declaration that declares a headline stat (Console
 * PRD D9/D15).
 *
 * Note the shape of this fixture, because it IS the property under test:
 * the vocabulary is a class CONSTANT, so a test cannot vary it — the
 * variants below are separate classes. Only the current stat is mutable,
 * because only the current stat is a runtime value.
 *
 * The vocabulary here is a TEST vocabulary. The package deliberately
 * ships none: D15 puts it in the consuming app's repo.
 */
class HeadlineDeclaration implements CredentialDeclaration, DeclaresHeadlineStat
{
    public const ?string HEADLINE_VOCABULARY = SinkHeadlineLabel::class;

    public static ?HeadlineStat $stat = null;

    public static ?Throwable $throws = null;

    public static function reset(): void
    {
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

    public function headlineStat(): ?HeadlineStat
    {
        if (self::$throws !== null) {
            throw self::$throws;
        }

        return self::$stat;
    }
}
