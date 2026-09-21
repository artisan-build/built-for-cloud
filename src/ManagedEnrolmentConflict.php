<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

/**
 * The bounded conflict vocabulary shared by the managed-enrolment
 * routes (P1, ruling A1): every 409 carries one of these as `error`,
 * and the disconnect 409s additionally carry the same value as
 * `reason` so an operator surface can classify a refusal without
 * parsing prose. Enrolment, rotation and disconnect draw from this one
 * enum — the same word means the same thing on every route.
 */
enum ManagedEnrolmentConflict: string
{
    /** Disconnect only: no exactly-one active local Owner who can authenticate or receive recovery. */
    case OwnerNotAccessible = 'owner_not_accessible';

    case TransitionInProgress = 'transition_in_progress';

    /** The request's immutable binding (or a reused caller UUID's facts) disagrees with locked stored state. */
    case BindingConflict = 'binding_conflict';

    /** An expected generation counter disagrees with locked stored state. */
    case StaleGeneration = 'stale_generation';

    /** Rotation/disconnect on an installation that is not managed. */
    case NotManaged = 'not_managed';

    /** Enrolment on an installation that is already managed. */
    case AlreadyManaged = 'already_managed';

    /** Enrolment on a standalone installation that is not pristine. */
    case NotPristine = 'not_pristine';

    /** A staged APP_KEY rewrap holds the writer barrier; retry when it verifies zero old-version rows. */
    case KeyCutoverInProgress = 'key_cutover_in_progress';
}
