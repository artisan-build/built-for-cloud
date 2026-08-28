<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Contracts\AuthorizesCredentialVerbs;

/**
 * The verbs of the per-provider authority matrix (PRD 1.4, D2): every
 * provider declares, explicitly and per verb, who may perform each one. A
 * subject type never grants anything; possession of a name or a
 * `subject_ref` never grants anything; the declaration's verb-aware hook
 * ({@see AuthorizesCredentialVerbs})
 * is the only authority answer.
 *
 * `ReceiveReplacement` is in the vocabulary now so the matrix is complete
 * from day one; the delivery shapes that consult it ship in later releases.
 *
 * `Activate` is the hmac kind's signing cutover (PRD 1.21, SEC-V3-01) and
 * gets ITS OWN matrix verb, deliberately: activation flips live signing
 * state, which is an authority distinct from minting or rotating — a
 * declaration may allow an integration to rotate (mint pending
 * replacements) while reserving the cutover for a narrower set of actors.
 * Like every verb, a declaration that has not opted into the matrix
 * defers to the transport gates, and implementing it can only narrow.
 */
enum CredentialVerb: string
{
    /** Who may mint against this subject. */
    case Issue = 'issue';

    /** Who may see that the credential exists, and which fields. */
    case ListMetadata = 'list_metadata';

    /** Who may replace it. */
    case Rotate = 'rotate';

    /** Who may cut a pending hmac signing key over to active (SEC-V3-01). */
    case Activate = 'activate';

    /** Who may kill it. */
    case Revoke = 'revoke';

    /** Where the new secret is delivered, and to whom. */
    case ReceiveReplacement = 'receive_replacement';
}
