<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Http\Controllers\ConsoleChromeScript;
use Illuminate\Support\Facades\Process;

/**
 * AC7 / AC8 — the XHR re-entry interceptor, EXECUTED.
 *
 * **WHY THIS TEST SHELLS OUT.** The interceptor is JavaScript, and a PHP
 * assertion about a JavaScript file can only ever be a claim about its
 * TEXT: "the source contains `window.top`" would pass just as happily if
 * the surrounding branch never ran. So the shipped file — the same bytes
 * `GET /bfc/console/chrome.js` serves, read from
 * {@see ConsoleChromeScript::SOURCE} — is run in node against a minimal
 * window stand-in, and these tests assert what it DID.
 *
 * **WHAT IS EXECUTED HERE, AND WHAT IS ONLY MODELLED.** These tests
 * drive the SCRIPT'S OWN LOGIC: which responses it acts on, what
 * destination it builds, which cause it announces, and in what order.
 * They do NOT verify a single thing the script asks the BROWSER to do —
 * `response.url` shapes, `window.origin` in a sandboxed frame,
 * `Location.assign` raising on a refused navigation, `Response`
 * body-lock semantics, listener completion before unload. Every one of
 * those is a value the harness SUPPLIES, read from a standard and never
 * watched happening, and each is labelled "SPECIFIED, NOT OBSERVED"
 * where the script states it.
 *
 * **THAT DISTINCTION IS NOT ACADEMIC AND THIS FILE HAS ALREADY PAID FOR
 * IT.** An earlier revision had the interceptor read `location.origin`
 * as the document's effective origin, and the harness modelled the same
 * wrong property — so the suite reported that the code matched what its
 * author believed, which is not the same as reporting that it was right.
 * When a brief and its harness share an assumption, the harness cannot
 * falsify the brief.
 *
 * The full list, with the concrete check that would settle each, is at
 * `~/Herd/brain/projects/built-for-cloud/pr5-browser-observable-claims.md`;
 * the sink conversion is where a real browser exists to run them.
 *
 * **SKIPPED IS ITS OWN STATE AND NOT A PASS, AND THAT IS ENFORCED
 * RATHER THAN ASSERTED.** An earlier revision of this docblock said "CI
 * has node" — which was true only because GitHub's runner image happens
 * to ship one. Nothing pinned it, so if that image had changed, the only
 * tests that EXECUTE the interceptor would have silently skipped and the
 * lane would have stayed green, on the component now carrying the
 * same-origin check a phishing primitive depends on. So:
 * `.github/workflows/tests.yml` installs node in BOTH lanes with a
 * pinned `setup-node`, and {@see bfcNodeRequired()} makes this file
 * REFUSE to skip wherever `CI` is set. A developer machine without node
 * still skips; a lane without node now fails.
 *   Pinned by `tests/ConsoleReentryInterceptorTest.php` — "requires node
 *   in every CI lane rather than inheriting it from the runner image".
 */
function bfcNodeAvailable(): bool
{
    return Process::run(['node', '--version'])->successful();
}

/**
 * Whether this run is one where node is REQUIRED rather than optional.
 *
 * **PRESENCE, not truthiness.** An earlier revision treated `CI=0`,
 * `CI=false` and `CI=` as "not CI" while the docblock promised the run
 * was mandatory wherever `CI` is set — the same claim-wider-than-the-code
 * shape this file has already corrected once. A variable that is present
 * at all means a runner set it, and the safe reading of an ambiguous
 * value is the strict one: a lane that runs these tests when it did not
 * have to costs a second, and a lane that skips them when it should not
 * costs the only coverage the interceptor has.
 *
 * `GITHUB_ACTIONS` is checked as well so the intent survives someone
 * unsetting the generic one.
 *   Pinned by `tests/ConsoleReentryInterceptorTest.php` — "treats a CI
 *   variable that is present at all as making node mandatory".
 */
function bfcNodeRequired(): bool
{
    foreach (['CI', 'GITHUB_ACTIONS'] as $variable) {
        if (getenv($variable) !== false) {
            return true;
        }
    }

    return false;
}

/**
 * Run one harness scenario and hand back what the script did.
 *
 * @return array<string, mixed>
 */
function bfcInterceptorScenario(string $scenario): array
{
    $harness = __DIR__.'/Fixtures/console-reentry-harness.mjs';

    $result = Process::run(['node', $harness, $scenario]);

    expect($result->successful())->toBeTrue($result->errorOutput());

    /** @var array<string, mixed> $observed */
    $observed = json_decode($result->output(), true, 512, JSON_THROW_ON_ERROR);

    return $observed;
}

beforeEach(function (): void {
    // Loud where it matters. A CI lane with no node is a broken lane,
    // not an environment to accommodate, and the whole value of this
    // file is that it EXECUTES the script.
    if (bfcNodeRequired()) {
        expect(bfcNodeAvailable())->toBeTrue(
            'node is required in CI and is installed by .github/workflows/tests.yml; '
            .'without it the interceptor is never executed by anything.',
        );
    }

    // The harness reads the shipped file directly; this asserts the
    // route serves that same file, so "the tested script" and "the
    // served script" cannot be two different things.
    expect(file_exists(ConsoleChromeScript::SOURCE))->toBeTrue();
})->skip(
    fn (): bool => ! bfcNodeRequired() && ! bfcNodeAvailable(),
    'node is not on the PATH and this is not a CI run, so the interceptor cannot be executed here.',
);

// ─── The same-origin gate: any CORS-readable response could forge this ──────

it('ignores a cross-origin response carrying the re-entry header', function (): void {
    // THE FORGERY THIS CHECK EXISTS FOR. The wrapper sees every response
    // the page makes, third-party ones included. A CORS-readable
    // endpoint that exposes `BFC-Console-Reentry` via
    // `Access-Control-Expose-Headers` can answer 401 with a
    // `reentry_url` of its choosing — and without an origin check this
    // script would navigate an ADMINISTRATOR's top-level window there,
    // on the exact path operators are trained to follow.
    //
    // Both transports, because the header is readable on both.
    foreach (['fetch-cross-origin', 'xhr-cross-origin'] as $scenario) {
        $observed = bfcInterceptorScenario($scenario);

        expect($observed['topAssigned'])->toBeNull($scenario)
            ->and($observed['frameAssigned'])->toBeNull($scenario)
            // Not even reported: this is somebody else's 401, and
            // announcing it would tell the operator their session had
            // died when a third party said so.
            ->and($observed['events'])->toBe([], $scenario)
            ->and($observed['chromeElement']['attributes'])->toBe([], $scenario);
    }
});

it('ignores a response whose own url it cannot read', function (): void {
    // An opaque response reports an empty `url`, so it cannot be
    // established as this application's. It is ignored — not acted on,
    // and not reported either, because announcing would let any
    // third-party response tell the operator their session had died.
    //
    // (The OTHER unverifiable case — a document that cannot name its own
    // origin — is not silent, because nothing an attacker controls is
    // involved in noticing it. It is driven below, with its cause.)
    $observed = bfcInterceptorScenario('fetch-unreadable-url');

    expect($observed['topAssigned'])->toBeNull()
        ->and($observed['frameAssigned'])->toBeNull()
        ->and($observed['events'])->toBe([]);
});

it('refuses to navigate on a body that is not this contract envelope', function (): void {
    // Same origin and the right header, so this IS a re-entry and is
    // reported as one — but the body is not the documented
    // `{version: 1, error: "console_reentry_required"}` pair, so no
    // destination is read out of it. A future version bump must not be
    // able to send an operator somewhere under the old rules.
    foreach (['fetch-wrong-envelope-version', 'fetch-wrong-envelope-error'] as $scenario) {
        $observed = bfcInterceptorScenario($scenario);

        expect($observed['topAssigned'])->toBeNull($scenario)
            ->and($observed['events'][0]['type'])->toBe('bfc:console-reentry-unavailable', $scenario);
    }
});

it('navigates the top-level window through the issuer, preserving the return path', function (): void {
    $observed = bfcInterceptorScenario('fetch-redirect');

    // The destination is the configured issuer with the return path
    // carried across, encoded — not the raw path spliced into a URL.
    expect($observed['topAssigned'])
        ->toBe('https://scalpels.test/console/re-enter?return_to=%2Forders%3Fpage%3D2')
        // Nothing was reported as unavailable: this re-entry happened.
        // The one event is the departure notice, driven on its own
        // below.
        ->and(array_column($observed['events'], 'type'))->toBe(['bfc:console-reentry']);
});

it('navigates the top window rather than the frame the capped request came from', function (): void {
    // The framed case is the only one that can tell the two apart: in a
    // top-level document `window.top` IS `window`. Re-entry inside an
    // iframe would either be refused by the issuer's framing policy or
    // would leave the outer document sitting on a dead session.
    $observed = bfcInterceptorScenario('fetch-redirect-framed');

    expect($observed['topAssigned'])
        ->toBe('https://scalpels.test/console/re-enter?tenant=acme&return_to=%2Forders')
        // The frame's own location was never touched.
        ->and($observed['frameAssigned'])->toBeNull();
});

it('degrades honestly when the deployment has configured no re-entry url', function (): void {
    // The server omits `reentry_url` entirely when it has none, and this
    // is the client half of that honesty: nowhere is invented, and the
    // 401 is not swallowed either — it is reported in the page and on an
    // event the host application can listen for.
    $observed = bfcInterceptorScenario('fetch-no-reentry-url');

    expect($observed['topAssigned'])->toBeNull()
        ->and($observed['frameAssigned'])->toBeNull()
        ->and($observed['events'])->toBe([[
            'type' => 'bfc:console-reentry-unavailable',
            'detail' => ['reason' => 'session_invalidated', 'return_to' => '/orders', 'cause' => 'no_destination'],
        ]])
        ->and($observed['chromeElement']['attributes'])
        ->toBe(['data-bfc-console-reentry' => 'unavailable'])
        ->and($observed['chromeElement']['textContent'])->toContain('could not be renewed automatically');
});

it('refuses a re-entry url whose scheme is not http or https', function (): void {
    // The server already refuses to emit one, so this is the client's
    // own floor: a `javascript:` destination is treated exactly as an
    // absent one rather than navigated to.
    $observed = bfcInterceptorScenario('fetch-hostile-reentry-url');

    expect($observed['topAssigned'])->toBeNull()
        ->and($observed['frameAssigned'])->toBeNull()
        ->and($observed['events'][0]['type'])->toBe('bfc:console-reentry-unavailable');
});

it('degrades honestly when the top window cannot be reached at all', function (): void {
    // A cross-origin embed throws on the property access. The script
    // does NOT fall back to navigating its own frame, which would be
    // the wrong navigation performed silently.
    $observed = bfcInterceptorScenario('fetch-top-unreachable');

    expect($observed['topAssigned'])->toBeNull()
        ->and($observed['frameAssigned'])->toBeNull()
        ->and($observed['events'][0]['type'])->toBe('bfc:console-reentry-unavailable');
});

it('hands the capped response back to its caller rather than swallowing it', function (): void {
    // Both transports. A capped Livewire request must still end in
    // whatever the component would have done with a 401, because the
    // navigation may not happen at all.
    $viaFetch = bfcInterceptorScenario('fetch-redirect');
    $viaXhr = bfcInterceptorScenario('xhr-redirect');

    expect($viaFetch['callerSawStatus'])->toBe(401)
        ->and($viaFetch['callerGotSameResponse'])->toBeTrue()
        // The body was still readable by the caller: the interceptor
        // read a clone.
        ->and($viaFetch['callerSawBody'])->toContain('console_reentry_required')
        // AND THE LOCK IS REAL. The double refuses a second read the way
        // a browser's `Response` does, so this assertion means something:
        // against a stand-in with no body semantics, an interceptor that
        // read the ORIGINAL body would have passed the line above while
        // leaving the caller nothing to read.
        ->and($viaFetch['callerSawBodyTwice'])->toBeFalse()
        ->and($viaXhr['callerLoadFired'])->toBeTrue()
        ->and($viaXhr['callerSawStatus'])->toBe(401);
});

it('performs the same re-entry for a capped XMLHttpRequest', function (): void {
    $observed = bfcInterceptorScenario('xhr-redirect');

    expect($observed['topAssigned'])
        ->toBe('https://scalpels.test/console/re-enter?return_to=%2Forders');
});

it('announces the navigation before performing it, so an app can persist unsaved state', function (): void {
    // D7's honest cost: re-entry is a full-page navigation and unsaved
    // client-side state goes with it. The event is dispatched
    // synchronously immediately before `location.assign()`, so a
    // listener that writes a draft to localStorage has actually run.
    // It is NOT cancelable — the session is already dead server-side,
    // and letting an app suppress the navigation would only strand the
    // operator on a page whose every request fails.
    $observed = bfcInterceptorScenario('fetch-redirect');

    expect($observed['events'])->toBe([[
        'type' => 'bfc:console-reentry',
        'detail' => ['reason' => 'assertion_age_cap', 'return_to' => '/orders?page=2', 'cause' => null],
    ]])
        // THE ORDERING, ASSERTED RATHER THAN ASSUMED. The harness records
        // the events and the navigation in ONE ordered channel, so this
        // is a claim about sequence and not two independent facts that
        // happen to both be true. A promise about ordering that no test
        // orders is exactly the pattern this build keeps paying for.
        ->and($observed['timeline'])->toBe(['event:bfc:console-reentry', 'navigate:top'])
        ->and($observed['topAssigned'])->not->toBeNull();
});

it('announces every path on which it cannot complete a re-entry, naming the cause', function (): void {
    // ONE RULE, THREE PATHS. The interceptor must never give up quietly,
    // and each way it can fail says which one it was.
    //
    // 1. THE BROWSER REFUSED THE NAVIGATION. `Location.assign` is
    //    exposed across origins and throws — a sandboxed frame without
    //    top-navigation permission raises SecurityError.
    //
    //    **SPECIFIED, NOT OBSERVED, AND LOAD-BEARING.** What is driven
    //    below is that the script CATCHES and announces when `assign()`
    //    throws. That a browser throws at all is the premise, and it is
    //    unverified: if a refusal is silent in practice, this guard
    //    catches nothing and the operator sits on a dead page believing
    //    re-entry is under way — the defect it was added to close. An earlier
    //    revision left that call outside every guard, so the script had
    //    already claimed the response and emitted its departure event
    //    and then threw, leaving the operator on a dead page believing
    //    a re-entry was under way. The harness makes `assign()` itself
    //    throw, which is the operation that actually fails — making the
    //    `window.top` GETTER throw, as the older scenario does,
    //    exercises a different one.
    $refused = bfcInterceptorScenario('fetch-navigation-refused');

    expect($refused['timeline'])->toBe([
        'event:bfc:console-reentry',
        'navigate:top',
        'event:bfc:console-reentry-unavailable',
    ])
        ->and($refused['events'][1]['detail']['cause'])->toBe('navigation_refused')
        ->and($refused['chromeElement']['textContent'])->toContain('could not be renewed automatically');

    // 2. THIS DOCUMENT CANNOT NAME ITS OWN ORIGIN — a sandboxed iframe or
    //    `about:blank`, where `location.origin` is the string "null". The
    //    same-origin check can then never pass, so the interceptor is
    //    inert; that is a NEW limitation the same-origin fix introduced
    //    and it is disclosed at install time rather than absorbed.
    //    Two shapes of the same thing: `window.origin` reported as the
    //    string "null" (a frame sandboxed without `allow-same-origin`),
    //    and a runtime that does not expose `window.origin` at all.
    //
    //    THE FIRST OF THOSE IS MODELLED WITH `location.origin` STILL
    //    REPORTING A GOOD ORIGIN, which is what a browser does — so this
    //    now drives the property the script actually reads rather than
    //    the one an earlier revision assumed. SPECIFIED, NOT OBSERVED:
    //    that a browser reports the pair that way.
    foreach (['opaque-origin-document', 'fetch-origin-unreadable'] as $scenario) {
        $inert = bfcInterceptorScenario($scenario);

        expect($inert['topAssigned'])->toBeNull($scenario)
            ->and($inert['frameAssigned'])->toBeNull($scenario)
            ->and($inert['events'][0]['detail']['cause'])->toBe('origin_unverifiable', $scenario);
    }

    $opaque = bfcInterceptorScenario('opaque-origin-document');

    expect($opaque['timeline'])->toBe(['event:bfc:console-reentry-unavailable'])
        ->and($opaque['chromeElement']['attributes'])->toBe(['data-bfc-console-reentry' => 'unavailable'])
        // AND THE ATTRIBUTION SURVIVES. This session is alive and the
        // operator's identity is still true, so the bar is marked but
        // its text is not replaced — trading a correct D4 statement for
        // a warning about a capability this document lacks would be the
        // wrong swap.
        ->and($opaque['chromeElement']['textContent'])->toBe('');

    // 3. NOWHERE TO GO. Already driven above; asserted here as the third
    //    member of the set so the rule is enumerated rather than implied.
    $nowhere = bfcInterceptorScenario('fetch-no-reentry-url');

    expect($nowhere['events'][0]['detail']['cause'])->toBe('no_destination');
});

it('treats a CI variable that is present at all as making node mandatory', function (): void {
    // The predicate has to match the sentence above it. `CI=0` is still
    // a runner saying it is a runner, and the safe reading of an
    // ambiguous value is the strict one — a lane that skips these tests
    // loses the only coverage the interceptor has.
    $original = ['CI' => getenv('CI'), 'GITHUB_ACTIONS' => getenv('GITHUB_ACTIONS')];

    try {
        putenv('GITHUB_ACTIONS');

        foreach (['1', 'true', '0', 'false', ''] as $value) {
            putenv('CI='.$value);

            expect(bfcNodeRequired())->toBeTrue("CI={$value} must still make node mandatory");
        }

        putenv('CI');

        expect(bfcNodeRequired())->toBeFalse('neither variable is present, so node is optional');

        // Either variable on its own is enough.
        putenv('GITHUB_ACTIONS=false');

        expect(bfcNodeRequired())->toBeTrue();
    } finally {
        foreach ($original as $variable => $value) {
            $value === false ? putenv($variable) : putenv($variable.'='.$value);
        }
    }
});

it('requires node in every CI lane rather than inheriting it from the runner image', function (): void {
    // The tests in this file are the only thing that executes the
    // interceptor. If node were merely inherited from a runner image,
    // a change to that image would make them all skip and the lane
    // would stay green on the highest-risk component in this PR.
    $workflow = (string) file_get_contents(dirname(__DIR__).'/.github/workflows/tests.yml');

    // Every job in the workflow, split on the two-space job keys —
    // scoped to the `jobs:` block, because `on:` has two-space keys of
    // its own and counting those would make this pass for the wrong
    // reason.
    $jobsBlock = strstr($workflow, "\njobs:\n");

    expect($jobsBlock)->toBeString();

    preg_match_all('/^  ([a-z][a-z0-9_-]*):$/m', (string) $jobsBlock, $jobs, PREG_OFFSET_CAPTURE);

    expect($jobs[1])->toHaveCount(2);

    foreach ($jobs[1] as $index => [$name, $offset]) {
        $end = $jobs[1][$index + 1][1] ?? strlen((string) $jobsBlock);
        $body = substr((string) $jobsBlock, $offset, $end - $offset);

        // `toContain()` is variadic in Pest, so the failure message goes
        // through a boolean expectation rather than a second needle.
        expect(str_contains($body, 'actions/setup-node@'))->toBeTrue(
            "The CI job \"{$name}\" does not install node, so ConsoleReentryInterceptorTest would skip there.",
        );
    }
});

it('ignores an ordinary 401 that is not a console re-entry', function (): void {
    // The header is the branch point, not the status: an application's
    // own 401 must be left entirely alone.
    $observed = bfcInterceptorScenario('fetch-ordinary-401');

    expect($observed['topAssigned'])->toBeNull()
        ->and($observed['frameAssigned'])->toBeNull()
        ->and($observed['events'])->toBe([])
        ->and($observed['chromeElement']['attributes'])->toBe([]);
});
