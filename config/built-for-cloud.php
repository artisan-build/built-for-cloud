<?php

declare(strict_types=1);

return [

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
    ],

];
