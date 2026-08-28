<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

/**
 * When a claim code is consumed (PRD 1.2 / D1a). A provider declares the
 * mode it can honour via {@see Contracts\DeclaresBurnMode}.
 */
enum BurnMode: string
{
    /**
     * The code burns when the credential it minted is first successfully
     * presented — hitch's make-before-break rule, honoured by providers
     * with an observable first authenticated use (`api_tokens`). Redemption
     * alone does not burn; a dropped exchange response stays harmless.
     */
    case FirstUse = 'first_use';

    /**
     * The code burns when it is redeemed, under lock. The mode for
     * providers with no observable first use (a user subject, a credential
     * whose secret half never transits the server). A provider declaring
     * this mode does not implement the hitch claim contract and must not
     * advertise it.
     */
    case AtExchange = 'at_exchange';
}
