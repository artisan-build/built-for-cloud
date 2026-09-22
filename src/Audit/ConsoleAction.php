<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Audit;

/**
 * The actions THIS PACKAGE performs and records on the app-action stream
 * (Console PRD D17).
 *
 * It is NOT an app vocabulary and is deliberately not a starter set. An
 * app's actions live in the app's repo ({@see AppAction}); this enum
 * exists because the package itself is an actor here, and an emission
 * point that could not name its own action would have had to take a
 * string.
 *
 * The one case names an action the package no longer performs: the
 * delegated-entry door that emitted it was retired in v0.17.0. The case
 * remains the vocabulary for rows recorded before that retirement, so
 * the historical stream still resolves, and it keeps the enum available
 * to tests of the recorder API as package-owned sample vocabulary.
 */
enum ConsoleAction: string implements AppAction
{
    /**
     * A delegated session was opened at this deployment's door: the
     * assertion verified, the mint was spent, and the operator was
     * logged in. Historical: the door was retired in v0.17.0, so no new
     * row carries this action; rows recorded before that retirement
     * keep it as their action.
     */
    case ConsoleEntered = 'console-entered';
}
