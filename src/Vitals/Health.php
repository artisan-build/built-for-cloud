<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Vitals;

/**
 * The vitals health vocabulary (Console PRD D9). Three members, and this
 * package emits exactly two of them:
 *
 * - `Ok` — everything this endpoint reports was read, and the caller
 *   stated no contract-version disagreement.
 * - `Degraded` — the payload still serves, carrying every field it COULD
 *   fill and nulls where it could not: an unreadable queue, a declaration
 *   this endpoint refused to echo, or contract skew. D9 is explicit that
 *   "displaying skew is part of the dashboard's job", so an unreachable
 *   dependency degrades the report rather than erroring it.
 * - `Down` — the value the FLEET DASHBOARD needs for an app that did not
 *   answer at all.
 *
 * **This package never returns `Down`**, and the reason is structural
 * rather than a promise: {@see self::fromDegradation} is the only
 * constructor {@see CollectVitals} calls, its argument is a boolean, and
 * its range is therefore exactly `Ok`/`Degraded`. A served 200 is itself
 * the proof of reachability, so there is no state this endpoint could
 * observe that `Down` would describe. The member lives here anyway so the
 * dashboard and this endpoint share ONE vocabulary instead of two that
 * drift — the vendor synthesises it for an app whose request failed.
 */
enum Health: string
{
    case Ok = 'ok';
    case Degraded = 'degraded';
    case Down = 'down';

    public static function fromDegradation(bool $degraded): self
    {
        return $degraded ? self::Degraded : self::Ok;
    }
}
