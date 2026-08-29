<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Contracts;

use ArtisanBuild\BuiltForCloud\Vitals\HeadlineLabel;
use ArtisanBuild\BuiltForCloud\Vitals\HeadlineStat;

/**
 * Opt-in extension of {@see CredentialDeclaration}: this app's ONE
 * headline stat on the vitals payload (Console PRD D9), and the
 * compile-time vocabulary its label comes from (D15).
 *
 * A declaration that does not implement this interface reports no
 * headline at all. That is the intended default, and it is not a
 * degraded state: the package ships NO vocabulary of its own, because
 * D15 puts the vocabulary in the app's repo, under code review, at
 * conversion time. Inventing a fleet-wide default here would have made
 * the one label the vendor sees a package concern rather than an app
 * decision — which is the failure the decision exists to prevent.
 *
 * THE VOCABULARY IS A CONSTANT NAMING AN ENUM CLASS, and both halves of
 * that are what make "never runtime data" structural rather than
 * aspirational: {@see self::HEADLINE_VOCABULARY} must be a constant
 * expression, so WHICH vocabulary applies is fixed when the file is
 * parsed, and the class it names implements {@see HeadlineLabel}, which
 * extends `BackedEnum`, so WHAT is in that vocabulary is a case set
 * fixed at compile time too. `Tag::pluck('slug')->all()` cannot satisfy
 * either half. See {@see HeadlineLabel} for what this does and does not
 * settle.
 */
interface DeclaresHeadlineStat
{
    /**
     * The largest vocabulary this package will report from.
     *
     * A cap is not a security boundary — the enum is already
     * compile-time — but a vocabulary of a thousand cases is a data
     * channel wearing a vocabulary's clothes, and it is not something a
     * reviewer can actually review. Sixty-four is comfortably above any
     * honest fleet dashboard label set.
     */
    public const int MAX_LABELS = 64;

    /**
     * The enum class whose cases are this app's complete label
     * vocabulary, or null when this app declares none.
     *
     * **A CONSTANT, not a method, and that is the enforcement.** A class
     * constant's value must be a constant expression, so it is fixed
     * when the file is parsed: it cannot be read off a request, a
     * database row, a config value or a tenant. An earlier revision made
     * this a method returning a class-string — the emitted VALUES were
     * already compile-time enum cases, so no free text could reach the
     * vendor either way, but which vocabulary applied could still be
     * selected at runtime, and the docblock claimed more than that. Now
     * the class and its cases are both compile-time, and the claim and
     * the code say the same thing.
     *
     * Null and a stat are a CONTRADICTION in the app's own declaration,
     * not an ordinary state: the payload reports no headline AND
     * degrades, so the operator sees that the app asked for something
     * its declaration does not permit. Null with no stat is ordinary and
     * degrades nothing.
     *
     * The type is `?string` and deliberately carries no
     * `class-string<HeadlineLabel>` annotation. An annotation here would
     * be a promise the interface cannot keep — an implementer may write
     * any constant expression, `self::class` included — and it would
     * make static analysis treat {@see CollectVitals}'s runtime checks
     * as dead code. The checks are the guarantee; the type is only what
     * PHP enforces.
     */
    public const ?string HEADLINE_VOCABULARY = null;

    /**
     * The current headline, or null when this app has nothing to report
     * right now. Null is an ordinary answer, not a fault: it drops the
     * field without degrading the payload's health.
     */
    public function headlineStat(): ?HeadlineStat;
}
