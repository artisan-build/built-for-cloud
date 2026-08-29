<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Audit\AppAction;

/**
 * An INT-backed vocabulary. `BackedEnum` permits it, so the marker
 * interface alone does not make a case an identifier — the recorder has
 * to refuse it, and an event carrying `7` as its action name would be
 * unreadable by anyone but the app that wrote it.
 */
enum CountedAppAction: int implements AppAction
{
    case Something = 7;
}
