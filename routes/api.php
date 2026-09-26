<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| Built for Cloud API routes
|--------------------------------------------------------------------------
|
| The machine-facing half of the package's HTTP contract: bearer-, claim- and
| operator-credential routes at fixed /bfc/ paths, loaded in every app. Every
| route here is documented in docs/http-contract.md.
|
| Routes inside the `bfc_operator` group are operator routes: the service
| provider appends the gate StandaloneRouteOwnership::operatorGateForAction()
| names for each one's action, then holds it to that gate at boot and on every
| match. Declared middleware (the throttles) stays outermost, so refused
| attempts are bounded too.
|
*/

use ArtisanBuild\BuiltForCloud\Http\Controllers\AsymmetricEnrollments;
use ArtisanBuild\BuiltForCloud\Http\Controllers\BoundHmacCutovers;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ClientObservations;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ConsoleVitals;
use ArtisanBuild\BuiltForCloud\Http\Controllers\DeviceAuthorizations;
use ArtisanBuild\BuiltForCloud\Http\Controllers\LoopbackAuthorizations;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageConsoleKeys;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageCredentials;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManagedEnrolments;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageOnboarding;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageOwnership;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageSubjects;
use ArtisanBuild\BuiltForCloud\Http\Controllers\MetaController;
use ArtisanBuild\BuiltForCloud\Http\Middleware\UniformConsoleKeyRefusal;
use Illuminate\Support\Facades\Route;

Route::get('/bfc/meta', MetaController::class)
    ->middleware('throttle:bfc-public');

Route::post('/bfc/ownership/claim', [ManageOwnership::class, 'claim'])
    ->middleware('throttle:bfc-claim');

// The hitch claim-contract route (PRD 1.12 / OSS-8): the wire
// face of hitch/docs/claim-contract.md over the same claim
// primitive as the onboarding exchange. Unconditional at a
// FIXED path like every /bfc/* surface — never behind a
// configurable prefix, never behind its own env flag.
Route::post('/bfc/claim', [ManageOnboarding::class, 'claim'])
    ->middleware('throttle:bfc-claim');

Route::post('/bfc/onboarding/exchange', [ManageOnboarding::class, 'exchange'])
    ->middleware('throttle:bfc-claim');

Route::post('/bfc/asymmetric-enrollments/{application}', AsymmetricEnrollments::class)
    ->middleware('throttle:bfc-claim');

Route::post('/bfc/onboarding/verify', [ManageOnboarding::class, 'verify'])
    ->middleware('throttle:bfc-public');

// The token halves of device and loopback authorization: the CLI
// polls or exchanges here with no browser session. The browser halves
// live in routes/web.php; both halves belong to the authorization family.
Route::group(['bfc_family' => 'authorization'], function (): void {
    Route::post('/bfc/device/token', [DeviceAuthorizations::class, 'token'])
        ->middleware('throttle:bfc-authorization-token')
        ->name('bfc.device.token');
    Route::post('/bfc/loopback/token', [LoopbackAuthorizations::class, 'token'])
        ->middleware('throttle:bfc-authorization-token')
        ->name('bfc.loopback.token');
});

Route::group(['bfc_operator' => true], function (): void {
    // The P1 managed-enrolment verbs: owner-credential-authenticated
    // (the CURRENT ownership-linked credential — not any admin
    // bearer), throttled before authentication like every operator
    // write, no-store, secret never returned. See
    // docs/http-contract.md "Authority-driven managed enrolment".
    Route::post('/bfc/managed/enrolment', [ManagedEnrolments::class, 'enrol'])
        ->middleware('throttle:bfc-operator-write');

    Route::post('/bfc/managed/enrolment/client-secret', [ManagedEnrolments::class, 'rotateClientSecret'])
        ->middleware('throttle:bfc-operator-write');

    Route::post('/bfc/managed/enrolment/disconnect', [ManagedEnrolments::class, 'disconnect'])
        ->middleware('throttle:bfc-operator-write');

    Route::post('/bfc/ownership/release', [ManageOwnership::class, 'release']);

    Route::post('/bfc/ownership/cancel-transfer', [ManageOwnership::class, 'cancelTransfer']);

    Route::post('/bfc/onboarding/issue', [ManageOnboarding::class, 'issue']);

    Route::get('/bfc/client-observations', ClientObservations::class);

    // The unified store's verb routes (PRD 1.0): the HTTP half of
    // the two-transport rule, at a FIXED /bfc/ path like every
    // other package surface (PRD 1.12's precedent) — part of the
    // versioned public contract (docs/http-contract.md). Their gate
    // accepts a legacy admin token OR the installer-minted operator
    // credential (PRD 1.20 — the credential must work on the
    // surface it exists to manage), and each route names its
    // verb-family ability (GATE-3.7 least privilege): the
    // admin-equivalent `credential:admin` satisfies every one, a
    // narrower operator credential only its own family. Write and
    // expensive verbs additionally carry the per-operator-
    // credential + per-IP rate limiter (throttle FIRST, so even
    // failing auth attempts are bounded).
    Route::get('/bfc/credentials', [ManageCredentials::class, 'index']);

    Route::post('/bfc/credentials', [ManageCredentials::class, 'store'])
        ->middleware('throttle:bfc-operator-write');

    Route::delete('/bfc/credentials/{id}', [ManageCredentials::class, 'destroy'])
        ->middleware('throttle:bfc-operator-write');

    Route::post('/bfc/credentials/{id}/rotate', [ManageCredentials::class, 'rotate'])
        ->middleware('throttle:bfc-operator-write');

    // The hmac signing cutover (PRD 1.21, SEC-V3-01): a separate
    // operator-authorized verb — the claim exchange delivers and
    // never activates, so the flip needs its own route. Its
    // operator ability is the rotate FAMILY (activation completes
    // rotation's dance); the declaration matrix's own `activate`
    // verb stays the finer split.
    Route::post('/bfc/credentials/{id}/activate', [ManageCredentials::class, 'activate'])
        ->middleware('throttle:bfc-operator-write');

    Route::post('/bfc/hmac-cutovers/activate', [BoundHmacCutovers::class, 'activate'])
        ->middleware('throttle:bfc-operator-write');

    Route::post('/bfc/hmac-cutovers/status', [BoundHmacCutovers::class, 'status'])
        ->middleware('throttle:bfc-operator-write');

    // The console re-key verb (Console PRD D12): the retrofit path
    // that files a countersigning key onto an ALREADY-CLAIMED
    // deployment without re-onboarding it. Fixed path under the
    // `/bfc/console/*` namespace the contract reserved for exactly
    // this, like every other package surface.
    //
    // Its stack, outermost first, and each layer is load-bearing:
    //
    //  1. `throttle:bfc-operator-write` — bounded before anything
    //     else runs, so refused attempts cost budget too;
    //  2. `UniformConsoleKeyRefusal` — collapses the gate's 401/403
    //     split into ONE external answer (rework A5). It sits INSIDE
    //     the throttle so a 429 still says 429, and OUTSIDE the gate
    //     so it can catch what the gate aborts with;
    //  3. the gate itself, on `console:key:write` — its OWN ability,
    //     NOT the `credential:rotate` family (rework B2). A re-key
    //     is a rotation in shape, but folding it into that family
    //     would have handed Console-admin takeover to every
    //     rotate-scoped credential already in the field, silently,
    //     on upgrade. `credential:admin` still satisfies it, because
    //     the break-glass is a marking someone chose.
    Route::post('/bfc/console/re-key', [ManageConsoleKeys::class, 'reKey'])
        ->middleware([
            'throttle:bfc-operator-write',
            UniformConsoleKeyRefusal::class,
        ]);

    // The retirement verb (Console PRD D12): the other half of
    // make-before-break, and until this release the half with no
    // operator path at all — the keyring primitive it drives took a
    // PHP caller and nothing else, so a rotation driven over the
    // wire could only ever be started, never finished.
    //
    // The `kid` rides the PATH because the verb acts on a row that
    // already exists — the shape `/bfc/credentials/{id}/rotate`
    // uses — where the re-key's flat body carries a key that does
    // not exist yet.
    //
    // The SAME stack as the re-key, layer for layer, and the same
    // ability. Retirement ends a signing authority where filing
    // begins one, which sounds like the more consequential half and
    // is not: a credential holding `console:key:write` can already
    // file and activate a key of its own, and assertions minted
    // under it authenticate as delegated admins on this deployment's
    // MCP surface, which is more than denying that. A separate
    // ability would have meant no credential already in the field
    // could finish a rotation without being reissued first.
    Route::post('/bfc/console/keys/{key_id}/retire', [ManageConsoleKeys::class, 'retire'])
        ->middleware([
            'throttle:bfc-operator-write',
            UniformConsoleKeyRefusal::class,
        ]);

    // The Console's ops-vitals read (Console PRD D9/D15/D16): a
    // `metadata`-classified surface at a fixed `/bfc/console/*`
    // path.
    //
    // ONE gate, not the operator gate every verb route above uses
    // and not a composition either. {@see EnsureDashboardCredential}
    // is the whole of D16 — authentication, the app declaration's
    // authorization hook, an operator subject, and an ability set
    // EXACTLY equal to `{metadata:read}`.
    //
    // `bfc.credential.admin` could never have gated this: it grants
    // `credential:admin` whatever ability a route names, and D16
    // forbids the ownership/admin credential on any dashboard read
    // path. `bfc.ability:metadata:read` was in front of this gate
    // for one revision and has been removed: it enforces a strict
    // SUBSET of what the gate below enforces, so it never changed an
    // answer, while its own denial audit drained the delivery outbox
    // — putting the amplification lever this route was hardened
    // against back in front of the hardening. A redundant gate is a
    // second code path with its own side effects on the
    // attacker-reachable branch.
    //
    // Rate-limited like every other credentialed surface, per
    // credential AND per IP, and the throttle sits OUTSIDE the gate
    // so refused attempts are bounded too.
    Route::get('/bfc/console/vitals', ConsoleVitals::class)
        ->middleware('throttle:bfc-vitals');

    // The offboard verb (PRD 1.15, SEC-V3-04): full account
    // containment behind its OWN verb-family ability — the widest
    // verb, so a stolen mint- or revoke-scoped credential cannot
    // reach it.
    Route::post('/bfc/subjects/offboard', [ManageSubjects::class, 'offboard'])
        ->middleware('throttle:bfc-operator-write');
});
