<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Audit\AppAction;

/**
 * A vocabulary that IS compile-time and is still not bounded: its case
 * backs onto prose. The enum type stops runtime data; it does not stop an
 * app writing a sentence into a case, which is why the recorder checks
 * every case value against the bounded-identifier shape.
 */
enum UnboundedAppAction: string implements AppAction
{
    case Whatever = 'whatever the operator typed today';
}
