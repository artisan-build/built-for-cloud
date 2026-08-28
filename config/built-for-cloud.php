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
    | Unified Credential Store
    |--------------------------------------------------------------------------
    |
    | The one store and the one guard. Point any guard in your app's
    | `auth.guards` config at the `bfc` driver to authenticate requests
    | against the `credentials` table. The guard NEVER consults the fallback
    | token above — env pseudo-credentials have no path into the new store.
    |
    | `guard` names the app's bfc-driven guard, used by the `bfc.ability`
    | middleware to find the authenticated credential.
    |
    | `declaration` is an executable class implementing CredentialDeclaration
    | (resolveSubject/authorize hooks the framework calls). Null uses the
    | package default, which authorizes everything the credential's own
    | lifecycle and abilities already allow.
    |
    | `session_guard` names the session guard consulted ONLY to reject
    | mismatched simultaneous principals. Null uses `auth.defaults.guard`.
    |
    */

    'credentials' => [
        'guard' => env('BUILT_FOR_CLOUD_CREDENTIAL_GUARD', 'bfc'),
        'declaration' => null,
        'session_guard' => null,
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
    | `max_observations` caps the number of DISTINCT identities stored. At the
    | cap a new identity is dropped and nothing is evicted, so a flood of
    | sprayed identities cannot push the genuine client out of the table.
    |
    | The cap is enforced PER REQUEST, not atomically: concurrent requests can
    | each pass the check and briefly overshoot it. Storage stays bounded --
    | the overshoot is limited by in-flight concurrency -- but the number is an
    | approximate ceiling, not an exact one.
    |
    */

    'client_identity' => [
        'observe_unauthenticated' => env('BUILT_FOR_CLOUD_OBSERVE_UNAUTHENTICATED', false),
        'max_observations' => env('BUILT_FOR_CLOUD_MAX_OBSERVATIONS', 100),
    ],

    /*
    |--------------------------------------------------------------------------
    | The Three Lifetimes (PRD 1.3)
    |--------------------------------------------------------------------------
    |
    | Three separately bounded lifetimes govern everything this package
    | mints, and only ONE of them ever has a default:
    |
    | 1. CLAIM CODE — ttl_seconds is REQUIRED on issue and package-bounded
    |    to 60 seconds .. 7 days. The short life belongs on the code.
    | 2. DURABLE CREDENTIAL — expiry is CALLER-CHOSEN and there is NO
    |    default, ever. Revocation-on-event (offboarding, rotation,
    |    self-revoke), not expiry, is the intended end of a durable's life.
    |    When an issuer DOES choose an `expires_at`, the holder is warned
    |    before it lapses (`bfc:credentials:warn-expiring`, below) —
    |    conditional on that choice, never a nudge toward making it.
    | 3. ROTATION GRACE — the superseded credential survives rotation by
    |    1 hour, or 0 with --emergency.
    |
    | `expiry_warning_hours` is how far ahead of a CHOSEN durable expiry the
    | `expiring` event fires. It warns; it never extends or expires anything.
    |
    */

    'lifetimes' => [
        'expiry_warning_hours' => env('BUILT_FOR_CLOUD_EXPIRY_WARNING_HOURS', 72),
    ],

    /*
    |--------------------------------------------------------------------------
    | Audit Stream & Outbox
    |--------------------------------------------------------------------------
    |
    | Every credential lifecycle transition appends an event to the
    | instance-side, append-only `credential_audit_events` table (ids only,
    | never secret values) plus a `credential_outbox` row in the SAME
    | transaction. Notifications consume the outbox after commit.
    |
    | `claim_ttl_seconds` is how long an outbox claim is honoured before a
    | consumer that died mid-delivery is presumed dead and the row becomes
    | claimable again. Keep it comfortably above your slowest mail send
    | times the recipients per event: a claim that expires mid-send lets a
    | second consumer re-deliver to a recipient whose marker has not landed
    | yet. Sends are tracked per recipient, so an expired claim never
    | re-sends to recipients already marked.
    |
    */

    'audit' => [
        'outbox' => [
            'claim_ttl_seconds' => env('BUILT_FOR_CLOUD_OUTBOX_CLAIM_TTL', 600),
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Lifecycle Notification Policy
    |--------------------------------------------------------------------------
    |
    | ONE policy: lifecycle event => declared recipients (`issuer`,
    | `holder`). The defaults are SEC-6's two notices — the issuer is told
    | when a code is exchanged, the intended recipient is told on first
    | use — plus the conditional expiry warning. Override the policy per
    | app to extend it.
    |
    | `issuer` is this instance's issuer notice inbox; null means issuer
    | rows notify no one. "holder" resolves via the code's addressed
    | recipient, else the app declaration's DeclaresHolderResolution — and
    | an unbound subject (a CI key, an app token) resolves to NOBODY rather
    | than falling back to spamming the operator.
    |
    */

    'notifications' => [
        'issuer' => env('BUILT_FOR_CLOUD_ISSUER_NOTIFICATION_EMAIL'),
        'policy' => [
            'exchanged' => ['issuer'],
            'first_used' => ['holder'],
            'expiring' => ['holder'],
        ],
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
