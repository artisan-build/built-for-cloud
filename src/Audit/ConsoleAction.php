<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Audit;

/**
 * The actions THIS PACKAGE performs and records on the app-action stream
 * (Console PRD D17). One case today, and it is the one D4's promise
 * rests on: a delegated operator was admitted through the door.
 *
 * It is NOT an app vocabulary and is deliberately not a starter set. An
 * app's actions live in the app's repo ({@see AppAction}); this enum
 * exists because the package itself is an actor here — `POST
 * /bfc/console/enter` is package code performing a package action — and
 * an emission point that could not name its own action would have had to
 * take a string.
 */
enum ConsoleAction: string implements AppAction
{
    /**
     * A delegated session was opened at this deployment's door: the
     * assertion verified, the mint was spent, and the operator was
     * logged in. Emitted inside the SAME transaction as the burn and the
     * redemption; all three use the default database connection, so an
     * entry that rolled back records nothing.
     */
    case ConsoleEntered = 'console-entered';
}
