<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Contracts\AuthorizesCredentialVerbs;

/**
 * The five verbs of the per-provider authority matrix (PRD 1.4, D2): every
 * provider declares, explicitly and per verb, who may perform each one. A
 * subject type never grants anything; possession of a name or a
 * `subject_ref` never grants anything; the declaration's verb-aware hook
 * ({@see AuthorizesCredentialVerbs})
 * is the only authority answer.
 *
 * `Rotate` and `ReceiveReplacement` are in the vocabulary now so the matrix
 * is complete from day one; the rotation route and delivery shapes that
 * consult them ship in later releases.
 */
enum CredentialVerb: string
{
    /** Who may mint against this subject. */
    case Issue = 'issue';

    /** Who may see that the credential exists, and which fields. */
    case ListMetadata = 'list_metadata';

    /** Who may replace it. */
    case Rotate = 'rotate';

    /** Who may kill it. */
    case Revoke = 'revoke';

    /** Where the new secret is delivered, and to whom. */
    case ReceiveReplacement = 'receive_replacement';
}
