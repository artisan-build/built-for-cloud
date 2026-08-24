<?php

declare(strict_types=1);

return [

    /*
    |--------------------------------------------------------------------------
    | Product Name
    |--------------------------------------------------------------------------
    |
    | Human-readable product name exposed through the unauthenticated metadata
    | endpoint so consoles can identify the target environment.
    |
    */

    'product' => env('BUILT_FOR_CLOUD_PRODUCT', env('APP_NAME', 'Laravel')),

    /*
    |--------------------------------------------------------------------------
    | Fallback Token
    |--------------------------------------------------------------------------
    |
    | A single plaintext "fallback" token, read straight from the environment.
    | Any caller presenting it authenticates without a database token row. It
    | exists for bootstrap and low-friction internal use only — delete it from
    | the environment to disable it, and provision per-app database tokens for
    | production workloads.
    |
    | When null, fallback authentication is disabled entirely.
    |
    */

    'fallback_token' => env('FALLBACK_TOKEN'),

    /*
    |--------------------------------------------------------------------------
    | Token Prefix
    |--------------------------------------------------------------------------
    |
    | A short, human-recognisable prefix prepended to generated plaintext
    | tokens. Purely cosmetic — it has no bearing on how a token resolves.
    |
    */

    'token_prefix' => env('BUILT_FOR_CLOUD_TOKEN_PREFIX', 'tok_'),

    /*
    |--------------------------------------------------------------------------
    | Credential API
    |--------------------------------------------------------------------------
    |
    | Disabled by default. When enabled, a token-admin guarded JSON API can
    | issue, list, and revoke plain access tokens without sessions or CSRF.
    |
    */

    'credential_api' => [
        'enabled' => env('BUILT_FOR_CLOUD_CREDENTIAL_API_ENABLED', false),
        'prefix' => env('BUILT_FOR_CLOUD_CREDENTIAL_API_PREFIX', 'api/credentials'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Client Identity Observation
    |--------------------------------------------------------------------------
    |
    | Records the client identity claimed on requests that presented NO working
    | credential, so a provider can see "something calling itself client X is
    | reaching us and its token does not work" (expired, revoked, wrong, absent).
    |
    | ADVISORY ONLY. A claimed identity on an unauthenticated request is
    | trivially spoofable — anyone can send any header — so it never grants
    | anything and never influences authentication.
    |
    | DISABLED BY DEFAULT, deliberately. This is a database write driven by an
    | UNAUTHENTICATED request, and the token-guarded routes carry no throttle
    | middleware. A provider opts in; no consuming app inherits it by upgrading.
    |
    | `max_observations` hard-caps the number of DISTINCT identities stored. At
    | the cap a new identity is dropped and nothing is evicted, so a flood of
    | sprayed identities cannot push the genuine client out of the table.
    |
    */

    'client_identity' => [
        'observe_unauthenticated' => env('BUILT_FOR_CLOUD_OBSERVE_UNAUTHENTICATED', false),
        'max_observations' => env('BUILT_FOR_CLOUD_MAX_OBSERVATIONS', 100),
    ],

    /*
    |--------------------------------------------------------------------------
    | Auth Foundation
    |--------------------------------------------------------------------------
    |
    | Enabled by default for backward compatibility. Disable these when the
    | consuming application owns its own invitations or admin-user concept.
    |
    */

    'auth_foundation' => [
        'invitations' => env('BUILT_FOR_CLOUD_INVITATIONS', true),
        'user_admin_column' => env('BUILT_FOR_CLOUD_USER_ADMIN_COLUMN', true),
    ],

    /*
    |--------------------------------------------------------------------------
    | Cloud CLI
    |--------------------------------------------------------------------------
    |
    | The Laravel Cloud CLI binary used to resolve the target environment and
    | to run administration commands remotely. The environment itself is
    | resolved at runtime via `cloud environment:list`, never hard-coded.
    |
    */

    'cloud' => [
        'binary' => env('BUILT_FOR_CLOUD_BINARY', 'cloud'),
        'application' => env('BUILT_FOR_CLOUD_APPLICATION'),
    ],

];
