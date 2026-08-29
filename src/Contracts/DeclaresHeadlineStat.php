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
 * THE VOCABULARY IS AN ENUM CLASS, not a list of strings, and that is
 * what makes "never runtime data" structural rather than aspirational:
 * {@see self::headlineVocabulary} returns the class-string of an enum
 * implementing {@see HeadlineLabel}, and its case set — the vocabulary —
 * is fixed at compile time. `Tag::pluck('slug')->all()` cannot satisfy
 * this signature. See {@see HeadlineLabel} for what that does and does
 * not settle.
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
     * Null and a stat are a CONTRADICTION in the app's own declaration,
     * not an ordinary state: the payload reports no headline AND
     * degrades, so the operator sees that the app asked for something
     * its declaration does not permit. Null with no stat is ordinary and
     * degrades nothing.
     *
     * @return class-string<HeadlineLabel>|null
     */
    public function headlineVocabulary(): ?string;

    /**
     * The current headline, or null when this app has nothing to report
     * right now. Null is an ordinary answer, not a fault: it drops the
     * field without degrading the payload's health.
     */
    public function headlineStat(): ?HeadlineStat;
}
