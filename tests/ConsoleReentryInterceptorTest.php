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
 * WHAT THAT STILL IS NOT. It is `test-verified` and not `live-verified`:
 * a stand-in for `window` is not a browser, and nothing here exercises a
 * real `fetch`, a real Livewire request, a real cross-origin frame, or a
 * Content Security Policy. Those are named in the report rather than
 * implied to be covered.
 *
 * A machine with no `node` on its PATH SKIPS these — skipped, which is
 * its own state and not a pass. CI has node; this is for a developer
 * machine that does not.
 */
function bfcNodeAvailable(): bool
{
    return Process::run(['node', '--version'])->successful();
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
    // The harness reads the shipped file directly; this asserts the
    // route serves that same file, so "the tested script" and "the
    // served script" cannot be two different things.
    expect(file_exists(ConsoleChromeScript::SOURCE))->toBeTrue();
})->skip(fn (): bool => ! bfcNodeAvailable(), 'node is not on the PATH, so the interceptor cannot be executed here.');

it('navigates the top-level window through the issuer, preserving the return path', function (): void {
    $observed = bfcInterceptorScenario('fetch-redirect');

    // The destination is the configured issuer with the return path
    // carried across, encoded — not the raw path spliced into a URL.
    expect($observed['topAssigned'])
        ->toBe('https://scalpels.test/console/re-enter?return_to=%2Forders%3Fpage%3D2')
        // Nothing was reported as unavailable: this re-entry happened.
        ->and($observed['events'])->toBe([]);
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
            'detail' => ['reason' => 'session_invalidated', 'return_to' => '/orders'],
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
        ->and($viaXhr['callerLoadFired'])->toBeTrue()
        ->and($viaXhr['callerSawStatus'])->toBe(401);
});

it('performs the same re-entry for a capped XMLHttpRequest', function (): void {
    $observed = bfcInterceptorScenario('xhr-redirect');

    expect($observed['topAssigned'])
        ->toBe('https://scalpels.test/console/re-enter?return_to=%2Forders');
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
