<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Contracts;

use ArtisanBuild\BuiltForCloud\Vitals\CollectVitals;
use ArtisanBuild\BuiltForCloud\Vitals\HeadlineStat;

/**
 * Opt-in extension of {@see CredentialDeclaration}: this app's ONE
 * headline stat on the vitals payload (Console PRD D9), and the static
 * vocabulary its label must come from (D15).
 *
 * A declaration that does not implement this interface reports no
 * headline at all. That is the intended default, and it is not a
 * degraded state: the package ships NO vocabulary of its own, because
 * D15 puts the vocabulary in the app's repo, under code review, at
 * conversion time. Inventing a fleet-wide default here would have made
 * the one label the vendor sees a package concern rather than an app
 * decision — which is the failure the decision exists to prevent.
 *
 * WHERE THE "STATIC, CODE-REVIEWED" PROPERTY IS HELD: not here. This
 * interface is a PHP method, and a method can compute anything — an
 * implementation returning `Tag::pluck('name')->all()` satisfies the
 * signature. What the package enforces is the consequence rather than
 * the source: {@see CollectVitals} refuses any label that is not a
 * member of the returned vocabulary, and refuses the whole vocabulary
 * unless every member is a bounded lowercase identifier, so runtime data
 * cannot reach the wire as free text through this door. "Declared in the
 * app's repo at conversion time" is held by the app's own code review of
 * this method's body, and nowhere else.
 */
interface DeclaresHeadlineStat
{
    /**
     * Every label this app may EVER report, spelled out as literals.
     *
     * An empty list means "no headline" and is honoured as such: the
     * payload carries no `headline` rather than a fabricated one.
     *
     * @return list<string>
     */
    public function headlineLabels(): array;

    /**
     * The current headline, or null when this app has nothing to report
     * right now. Null is an ordinary answer, not a fault: it drops the
     * field without degrading the payload's health.
     */
    public function headlineStat(): ?HeadlineStat;
}
