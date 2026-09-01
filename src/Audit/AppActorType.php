<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Audit;

use ArtisanBuild\BuiltForCloud\AuditActorType;
use ArtisanBuild\BuiltForCloud\Console\DelegatedActor;
use ArtisanBuild\BuiltForCloud\Credential;

/**
 * The four principals D17 names for an APP ACTION: a local user, a unified
 * credential, a legacy api token, and a delegated actor.
 *
 * **WHY THIS IS A NEW ENUM AND NOT A REUSE OF {@see AuditActorType}** —
 * the decision is recorded here because the code is where it has to hold.
 *
 * The two streams answer different questions and their vocabularies must
 * not blur. `AuditActorType` types the four principals D8 names for
 * CREDENTIAL work (an admin token, a bound user, an operator
 * integration, the local CLI operator) plus the party a claim surface
 * can honestly attribute. It has no delegated actor and never will,
 * because the credential stream never records one: nothing in the
 * credential lifecycle is performed by a delegated console session.
 *
 * Reusing it would therefore have meant ADDING `delegated_actor` to it —
 * and the moment that case exists, a reader of a CREDENTIAL audit row is
 * holding a vocabulary containing a type that stream cannot produce, and
 * has to know which stream a row came from before it can know which
 * cases are possible. The failure runs the other way too: an app-action
 * row typed `cli_operator` or `credential_holder` would be describing a
 * principal that never performs an app action. A vocabulary whose
 * members are only meaningful given a fact stored somewhere else is not
 * a vocabulary; it is two vocabularies sharing a column name.
 *
 * So: two enums, disjoint by construction, each complete for its own
 * stream. The cost is a second small enum. The alternative was a
 * cross-stream reading hazard on a security record.
 *   Pinned by `tests/AppActionAuditTest.php` — "keeps the two audit
 *   vocabularies disjoint, so neither stream can hand a reader the
 *   other's actor type".
 */
enum AppActorType: string
{
    /**
     * The host application's own authenticated human, identified by the
     * app's own primary key. Not type-qualified, because the app's user
     * id IS the app's id space — see {@see DelegatedActor} for the one
     * principal that must be.
     */
    case LocalUser = 'local_user';

    /**
     * A credential acting on its own behalf — an operator or integration
     * token ({@see Credential}), identified by its opaque credential id.
     */
    case ApiToken = 'api_token';

    /**
     * A token from the legacy `api_tokens` store
     * ({@see \ArtisanBuild\BuiltForCloud\ApiToken}), identified by its
     * model key in that store's UUID id space.
     */
    case LegacyApiToken = 'legacy_api_token';

    /**
     * A delegated human admitted through the Console door, identified by
     * the TYPE-QUALIFIED `bfc-console:{id}` form and never the bare key
     * ({@see DelegatedActor::getAuthIdentifier()}). This is the only
     * actor type that may carry `on_behalf_of`.
     */
    case DelegatedActor = 'delegated_actor';
}
