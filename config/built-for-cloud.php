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
    | DEPRECATED (PRD 1.20): the install path now mints a real, revocable,
    | operator-subject credential instead (bfc:install:operator-credential);
    | an env pseudo-credential can never be revoked, audited, or attributed.
    | This key stays read because live 0.4.x apps still carry fallbacks —
    | delete FALLBACK_TOKEN from the environment to disable it. Nothing in
    | the framework's own paths writes or depends on it any more (the
    | unified-store guard never consults it), and a later major removes it.
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
    | HMAC Signing (the hmac credential kind, PRD 1.21)
    |--------------------------------------------------------------------------
    |
    | The verification bounds of the canonical envelope (SEC-V3-07).
    |
    | `timestamp_tolerance_seconds` — how far a signed timestamp may sit
    | from this server's clock, in either direction (inclusive).
    |
    | `verification_rate_ceiling` — GENUINELY NEW accepted verifications
    | per KEY per replay window. This is the nonce store's CARDINALITY
    | bound: only signature-valid requests count against it, replayed
    | nonces are rejected BEFORE the counter and spend nothing (a
    | captured envelope replayed forever cannot rate-limit the honest
    | holder), and the check runs before any nonce is stored, so one
    | credential can never fill the shared cache with unique nonces.
    | Size it above your busiest key's honest volume per window.
    |
    | The replay window (nonce + rate entries alike) is derived as
    | 2 x tolerance + 60s of margin: it strictly outlives the inclusive
    | timestamp-acceptance window, so a nonce accepted once cannot be
    | accepted again anywhere in its valid window — boundary included —
    | and any replay outliving its entry is already stale by the
    | timestamp rule. The store is bounded on BOTH axes: TTL and the
    | per-key cardinality ceiling. Note the nonce cache is only as shared
    | as the default cache store — instance-local stores (array, file)
    | bound replays per instance, not per fleet.
    |
    | `audience` — the audience string this app signs FOR and verifies AS
    | (a re-targeted message signed for another audience is rejected).
    | Null falls back to `app.url`.
    |
    | The hmac ENCRYPTION keyring deliberately has no config here: it
    | rides APP_KEY + APP_PREVIOUS_KEYS (SEC-V3-08) — see bfc:hmac:rewrap
    | and release-notes/hmac-kind.md for the staged rotation runbook.
    |
    */

    'hmac' => [
        'timestamp_tolerance_seconds' => env('BUILT_FOR_CLOUD_HMAC_TIMESTAMP_TOLERANCE', 300),
        'verification_rate_ceiling' => env('BUILT_FOR_CLOUD_HMAC_VERIFICATION_CEILING', 1000),
        'audience' => env('BUILT_FOR_CLOUD_HMAC_AUDIENCE'),
    ],

    /*
    |--------------------------------------------------------------------------
    | The Console (delegated operator entry, Console PRD D12/D18)
    |--------------------------------------------------------------------------
    |
    | The verification bounds for a delegated console assertion — a PASETO
    | v4.public token, signed by the vendor with the PRIVATE half of a
    | per-deployment keypair, carrying the operator who is entering this
    | app. This app holds only the PUBLIC halves (the `bfc_console_keys`
    | ring): stealing this whole database yields no ability to mint one.
    |
    | `issuer` — the single issuer this fleet trusts (D18: exactly one
    | issuer in v1, which is also what bounds per-issuer authority). An
    | assertion naming any other issuer is refused. There is deliberately
    | no list here: a second trusted issuer is a decision, not a config
    | change.
    |
    | `audience` — THIS deployment's identity, verified against the
    | token's `aud`, and REQUIRED: unlike `hmac.audience` above it does
    | not fall back to `app.url` or to any literal. This is the value
    | that makes a stolen assertion worthless at any other deployment,
    | and that containment has to hold on its own, independently of key
    | custody. `app.url` is not reliably per-deployment — `http://localhost`,
    | a cloned .env, or a shared load-balancer hostname would file
    | several deployments under one audience — so an unset audience
    | refuses to verify at all rather than quietly share one.
    |
    | `assertion_max_ttl_seconds` — the upper bound this app enforces on
    | an assertion's own `iat`-to-`exp` span (D12 mints at 60-120s). A
    | token claiming a longer life is refused WHILE STILL UNEXPIRED: the
    | app enforces the bound itself rather than trusting the issuer to
    | have been honest about it. The 60-second LOWER bound is a mint-side
    | concern and is deliberately not enforced here.
    |
    | `clock_skew_seconds` — how far the issuer's clock may run AHEAD of
    | this one before a freshly minted assertion is refused as not yet
    | valid. It is spent on that side only: `exp` is hard, because skew
    | that extended expiry would quietly stretch every assertion past the
    | TTL bound the previous key just enforced.
    |
    | The session clocks (D7's sliding idle and absolute cap) are NOT
    | here: they belong to the delegated guard, not to the assertion.
    |
    */

    'console' => [
        'issuer' => env('BUILT_FOR_CLOUD_CONSOLE_ISSUER'),
        'audience' => env('BUILT_FOR_CLOUD_CONSOLE_AUDIENCE'),
        'assertion_max_ttl_seconds' => env('BUILT_FOR_CLOUD_CONSOLE_ASSERTION_MAX_TTL', 120),
        'clock_skew_seconds' => env('BUILT_FOR_CLOUD_CONSOLE_CLOCK_SKEW', 5),
    ],

    /*
    |--------------------------------------------------------------------------
    | Console Vitals (the ops-vitals read, Console PRD D9/D15)
    |--------------------------------------------------------------------------
    |
    | Two app-declared facts `GET /bfc/console/vitals` reports. Both are
    | optional, and both are BOUNDED before they reach the wire, because
    | that endpoint is `metadata`-classified: bounded scalars and enums
    | only, no free-text strings anywhere (D15).
    |
    | `app_version` — this application's own release. It is echoed only
    | when it is semver-shaped; anything else is dropped and the payload
    | reports `degraded`, rather than forwarding an unbounded
    | operator-authored string to the vendor. (This is the same hazard
    | `product` above carries, and the reason `GET /bfc/meta` is
    | classified `content` while this endpoint is not.)
    |
    | `deployed_at` — when this deployment last shipped, in any format
    | the framework's date parser accepts; reported as ISO-8601, with a
    | derived `deploy_age_seconds`. Unparseable is `degraded` too, for
    | the same reason: a value was declared and could not be used, which
    | must not look identical to declaring nothing.
    |
    | Null for both is an ordinary, un-degraded state: an app that
    | declares neither simply reports nulls.
    |
    | `deployment_id` — a STABLE identifier for this deployment, used to
    | namespace the cached queue snapshot below. It falls back to
    | `cloud.application`, and when neither is set the snapshot cache is
    | DISABLED rather than shared: two apps with no identifier, the same
    | environment and a shared CACHE_PREFIX would otherwise compute the
    | same key and serve each other's queue backlog as honest local data
    | — a silent cross-deployment leak into a vendor dashboard, which is
    | worse than slow vitals. It is never inferred from the product name
    | or the environment; those are not identities.
    |
    | `queue_cache_seconds` — how long one queue-backlog snapshot serves
    | every poll. This route is POLLED: a dashboard reading once a second
    | would otherwise put a queue query (or a redis/sqs round trip) on
    | every request, sixty times a minute per credential. The snapshot
    | carries its own health, so a cache hit reports the same `degraded`
    | the failing read did rather than laundering it into `ok`. Set it to
    | 0 to read on every request. It bounds how OFTEN the read happens,
    | not how long one read may take — see CollectVitals::queueSnapshot
    | for why the package imposes no wall-clock deadline. The oldest-job
    | AGE is derived per request from a cached timestamp, so it keeps
    | moving inside a window even though the counts do not.
    |
    | The headline stat is NOT here. Its label vocabulary is code, not
    | config — the app's contract declaration implements
    | ArtisanBuild\BuiltForCloud\Contracts\DeclaresHeadlineStat, whose
    | vocabulary hook returns a BACKED ENUM CLASS. That is deliberate and
    | it is the enforcement: an enum's case set is fixed at compile time
    | in the app's repo, so the one label the vendor ever sees is
    | reviewed in a diff (D15) rather than assembled at runtime.
    |
    */

    'vitals' => [
        'app_version' => env('BUILT_FOR_CLOUD_APP_VERSION'),
        'deployed_at' => env('BUILT_FOR_CLOUD_DEPLOYED_AT'),
        'deployment_id' => env('BUILT_FOR_CLOUD_DEPLOYMENT_ID'),
        'queue_cache_seconds' => env('BUILT_FOR_CLOUD_VITALS_QUEUE_CACHE', 15),
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
    | Surface Selection (PRD 1.14, fleet F2)
    |--------------------------------------------------------------------------
    |
    | Which framework surfaces this app mounts. Five independently
    | selectable families, ALL ON by default (exactly today's behavior);
    | an app turns off what it does not use — this is what lets an app
    | stop mounting `/bfc/*` entirely instead of leaving a live
    | POST /bfc/ownership/claim minting admin rows into tables it never
    | reads.
    |
    | `routes`          — every HTTP route the package mounts (all of
    |                     /bfc/* and the legacy credential API). The
    |                     middleware ALIASES (bfc.ability, bfc.hmac, …)
    |                     stay registered either way, so an app with
    |                     routes off can still gate its own routes.
    | `migrations`      — loadMigrationsFrom for the package's schema
    |                     migrations. Off means the app owns the schema
    |                     (vendor:publish or its own copies). CAVEAT:
    |                     turning this off AFTER the package migrations
    |                     have already run strands their rollback — the
    |                     migrator can no longer find the files behind
    |                     the recorded entries, so migrate:rollback fails
    |                     at them. The flag is for FRESH installs and
    |                     never-served surfaces; an app that already
    |                     migrated keeps it on (or copies the files into
    |                     its own migrations before flipping it).
    | `commands`        — the bfc:* / token:* artisan commands.
    | `listeners`       — the package's event listeners (the ownership
    |                     webhook queue).
    | `data_migrations` — DATA-writing migration steps (today: the
    |                     initial ownership-claim mint). Distinct from
    |                     `migrations` because an app may want the schema
    |                     without the framework seeding state into it.
    |
    | No single route is individually configurable — the claim surfaces
    | in particular are never env-gated one by one (PRD 1.12); a family
    | is mounted whole or not at all.
    |
    */

    'surfaces' => [
        'routes' => env('BUILT_FOR_CLOUD_SURFACE_ROUTES', true),
        'migrations' => env('BUILT_FOR_CLOUD_SURFACE_MIGRATIONS', true),
        'commands' => env('BUILT_FOR_CLOUD_SURFACE_COMMANDS', true),
        'listeners' => env('BUILT_FOR_CLOUD_SURFACE_LISTENERS', true),
        'data_migrations' => env('BUILT_FOR_CLOUD_SURFACE_DATA_MIGRATIONS', true),
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
