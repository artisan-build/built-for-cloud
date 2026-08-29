<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Audit;

use ArtisanBuild\BuiltForCloud\AuditReason;

/**
 * The bounded `reason` on an app-action event (Console PRD D17's
 * "bounded reason vocabulary"): a CLOSED package enum, the whole of it
 * listed in `docs/http-contract.md`, and the document is checked against
 * this file mechanically rather than read.
 *
 * IT IS DELIBERATELY COARSE, and that is the design rather than an
 * omission. The ACTION carries the specificity — it is the app's own
 * compile-time vocabulary and can be as fine-grained as the app's review
 * will bear. The reason answers only "under what circumstance", from a
 * set small enough that a reader can hold all of it. A reason vocabulary
 * that grew a case whenever one did not quite fit would end up as free
 * text with extra steps, which is the thing D15 forbids; an app whose
 * circumstance is not exactly one of these picks the nearest and lets
 * the action say the rest.
 *
 * It is NOT {@see AuditReason}, for the same
 * reason {@see AppActorType} is not `AuditActorType`: that vocabulary
 * describes why a CREDENTIAL changed state (rotation, supersession,
 * cutover completion), and none of its members describes an app action.
 * Two streams, two closed sets, neither able to hand a reader the
 * other's members.
 */
enum AppActionReason: string
{
    /**
     * A delegated session was opened at this deployment's door. The
     * package's own reason, and the only one it emits today.
     */
    case ConsoleEntry = 'console_entry';

    /** The acting principal asked for this, in the request it acted in. */
    case Requested = 'requested';

    /**
     * The app performed it on its own schedule, under a standing
     * authorization the actor holds — not in a request that actor made.
     */
    case Scheduled = 'scheduled';

    /** Taken to correct or contain something already wrong. */
    case Remediation = 'remediation';

    /** Taken as part of removing a subject's access. */
    case Offboarding = 'offboarding';
}
