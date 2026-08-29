<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Audit\AppAction;

/**
 * A sink-shaped APP action vocabulary (Console PRD D17, D15): a backed
 * enum in the APP's repo, its case set fixed at compile time. This is the
 * whole point of typing the vocabulary as an enum class — this file is
 * what a reviewer reads to know every action name this app can ever
 * record.
 */
enum SinkAppAction: string implements AppAction
{
    case InvoiceVoided = 'invoice-voided';
    case TeammateInvited = 'teammate-invited';
}
