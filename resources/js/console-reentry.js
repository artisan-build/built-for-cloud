/**
 * THE XHR RE-ENTRY INTERCEPTOR (Console PRD D7, as amended).
 *
 * ============================================================
 * WHAT IN THIS FILE HAS BEEN EXECUTED, AND WHAT HAS NOT
 * ============================================================
 *
 * **EXECUTED.** `tests/ConsoleReentryInterceptorTest.php` runs THESE
 * BYTES in node against a window stand-in, so every branch, comparison
 * and ordering decision below is driven: which responses are acted on,
 * what destination is built, which cause is announced, and in what
 * order.
 *
 * **NOT EXECUTED — and every such statement below is marked "SPECIFIED,
 * NOT OBSERVED".** Everything this script depends on the BROWSER to do
 * is read from a standard and has never been watched happening:
 * `response.url` and `responseURL` shapes, `window.origin` in a
 * sandboxed frame, `Location.assign` throwing on a refused top
 * navigation, `window.top` access throwing cross-origin, `Response`
 * body-lock semantics, whether event listeners have finished before a
 * navigation begins, and whether wrapping `window.fetch` intercepts
 * Livewire's transport at all. **The harness supplies all of those; it
 * does not verify any of them.** A stand-in that models a browser
 * wrongly produces a suite that agrees with the mistake — which has
 * already happened once in this file, to `pageOrigin()`.
 *
 * `~/Herd/brain/projects/built-for-cloud/pr5-browser-observable-claims.md`
 * lists each one with the concrete check that would settle it, and the
 * sink conversion is where a real browser exists to run them.
 *
 * A capped or invalidated delegated session gets the same structured 401
 * on every transport: status 401, the header `BFC-Console-Reentry: 1`,
 * and a body of `{version, error, reason, reentry_url?, return_to}`. A
 * full page load can act on that itself; a Livewire/XHR request cannot,
 * because the operator is looking at a page that is still on screen and
 * whose session is already gone. This script is the half that turns such
 * a response into a TOP-LEVEL navigation out through the issuer and
 * back.
 *
 * **IT ACTS ONLY ON A SAME-ORIGIN RESPONSE, AND THAT CHECK IS THE FIRST
 * THING IT DOES.** This wrapper sees EVERY `fetch` and `XMLHttpRequest`
 * response the page makes, third-party ones included. An earlier
 * revision branched on the status and the header alone and then took the
 * destination out of the body — which handed any CORS-readable
 * third-party endpoint a way to return `401` with
 * `BFC-Console-Reentry: 1` (exposed via `Access-Control-Expose-Headers`)
 * and a `reentry_url` of its choosing, and this script would have
 * navigated an ADMINISTRATOR's top-level window there. That is a
 * phishing primitive pointed at the one person whose session is worth
 * the most, on the exact path operators are trained to follow, and it
 * could race a genuine capped response and win. So:
 *
 *  - the response's own URL (`response.url` for fetch, `responseURL` for
 *    XHR) must share this document's origin, compared as scheme +
 *    authority;
 *  - only then are the status and the header read at all;
 *  - and navigation additionally requires the exact envelope — `version`
 *    of 1 and the documented `error` string — so a body that is merely
 *    401-shaped names nowhere.
 *
 * A response whose URL cannot be read is NOT a pass: it is ignored,
 * because this script cannot establish that it is even looking at its
 * own application's answer.
 *   Pinned by `tests/ConsoleReentryInterceptorTest.php` — "ignores a
 *   cross-origin response carrying the re-entry header" and "ignores a
 *   response whose own url it cannot read".
 *
 * THE RESIDUE OF THAT CHECK, named rather than left to be found. An
 * OPAQUE response (`mode: 'no-cors'`) has an empty `url` and is ignored,
 * which is the safe direction and costs nothing, because an opaque
 * response has no readable header either. A response that was REDIRECTED
 * reports its FINAL url, so an app whose own path redirects to another
 * origin would be judged on where it landed — again the safe direction.
 * And a same-origin PROXY the application itself operates is
 * indistinguishable from the application: if an app forwards a third
 * party's bytes under its own origin, this check cannot see through it.
 * That is the boundary of what an origin comparison can say.
 *   **SPECIFIED, NOT OBSERVED:** the first two — an empty `url` on an
 *   opaque response, and the final url after a redirect — are read from
 *   the Fetch standard, and the harness supplies both values rather than
 *   producing them. The third is a statement about origins and holds
 *   whatever a browser does.
 *
 * **AND IT NEVER FAILS SILENTLY. That is one rule, not three
 * exceptions.** Every path on which this script cannot complete a
 * re-entry ends in {@see announce()} — the chrome element marked, and
 * `bfc:console-reentry-unavailable` dispatched with a `detail.cause`
 * naming which of three things went wrong:
 *
 *  - {@see CAUSE_ORIGIN_UNVERIFIABLE} — this document has no readable
 *    effective origin: a frame sandboxed with `allow-scripts` and
 *    WITHOUT `allow-same-origin`, or a runtime not exposing
 *    `window.origin`. No response can then be verified as the
 *    application's. Said once at install time, and the interceptor then
 *    does not install. This is a limitation the same-origin check itself
 *    introduced, and it is disclosed rather than absorbed.
 *    (`about:blank` is NOT in this set as a rule — a blank document
 *    normally INHERITS its creator's origin. An earlier revision listed
 *    it flatly and that was too broad.)
 *      **SPECIFIED, NOT OBSERVED.**
 *  - {@see CAUSE_NO_DESTINATION} — re-entry is required and the payload
 *    names nowhere this script will go.
 *  - {@see CAUSE_NAVIGATION_REFUSED} — a destination was found and the
 *    BROWSER refused the navigation, throwing out of `Location.assign`.
 *      **SPECIFIED, NOT OBSERVED, AND THIS ONE IS LOAD-BEARING.** The
 *      whole path rests on the premise that a refused top navigation
 *      RAISES. If a browser refuses silently instead, the `try` catches
 *      nothing, no cause is announced, and the operator sits on a dead
 *      page believing re-entry is under way — the exact defect the guard
 *      was added to close. Nobody has watched a browser do either thing.
 *      Read it as a guard whose premise is unverified, not a guarantee.
 *
 *   Pinned by `tests/ConsoleReentryInterceptorTest.php` — "announces
 *   every path on which it cannot complete a re-entry, naming the
 *   cause".
 *
 * THE ONE REFUSAL THAT REMAINS INVISIBLE, and it is invisible in the
 * browser rather than here: a navigation the browser declines WITHOUT
 * throwing. In that case the operator is left where the script found
 * them, which is where they would have been had the script never loaded.
 *   **SPECIFIED, NOT OBSERVED:** that some refusals raise and others are
 *   reported only to the developer console is read from the standard and
 *   from browser documentation. WHICH of the two happens for a given
 *   sandbox or policy is exactly what nobody here has watched, and it
 *   decides whether the case above is a caught error or a silent one.
 *
 * IT BRANCHES ON THE HEADER, NOT THE STATUS. A `401` without the header
 * is an ordinary application refusal and is left entirely alone.
 *
 * **TOP-LEVEL, AND NOTHING ELSE.** The navigation is performed on
 * `window.top.location`, never on the frame the capped request came
 * from: re-entry means the operator leaves this app, authenticates at
 * the issuer, and comes back, and doing that inside an iframe would
 * either be framed by a site the issuer refuses to be framed by or
 * would leave the outer document sitting on a dead session. When
 * `window.top` is unreachable — a cross-origin embed — this script does
 * NOT fall back to navigating its own frame; it takes the honest path
 * below instead.
 *   **SPECIFIED, NOT OBSERVED:** that reaching `window.top`'s location
 *   across origins throws, and that assigning to it navigates the top
 *   document, are read from the standard. The harness models both.
 *   Pinned by `tests/ConsoleReentryInterceptorTest.php` — "navigates the
 *   top-level window through the issuer, preserving the return path" and
 *   "navigates the top window rather than the frame the capped request
 *   came from".
 *
 * **RE-ENTRY IS A FULL-PAGE NAVIGATION, AND UNSAVED CLIENT-SIDE STATE
 * IS LOST WITH IT.** That is D7's stated cost — one full-page reload at
 * the cap — and this script announces it rather than performing it
 * silently: `bfc:console-reentry` is dispatched on `document`
 * IMMEDIATELY BEFORE the navigation, synchronously, so a listener can
 * persist a draft (a `localStorage` write completes; a network save does
 * not).
 *   **PART EXECUTED, PART SPECIFIED.** That this script dispatches
 *   before it calls `assign()` IS executed — the harness records both in
 *   one ordered channel. That a browser runs every listener to
 *   completion before the navigation takes effect, and that a
 *   synchronous `localStorage` write survives it, are read from the
 *   standard and have not been watched.
 *
 * It is deliberately NOT cancelable. The session is already dead
 * server-side, so suppressing the navigation grants nothing and only
 * strands the operator on a page whose every request fails — a
 * cancelable event would let an application turn D7's honest reload into
 * a silent dead end.
 *   Pinned by `tests/ConsoleReentryInterceptorTest.php` — "announces the
 *   navigation before performing it, so an app can persist unsaved
 *   state".
 *
 * **AN ABSENT `reentry_url` IS NOT AN ERROR TO SWALLOW AND NOT A
 * DESTINATION TO INVENT.** The server omits that field entirely when the
 * deployment has configured no issuer URL, because an app that cannot
 * reach its issuer must degrade honestly. So does this script: it
 * navigates nowhere, marks the chrome element as unable to re-enter, and
 * dispatches `bfc:console-reentry-unavailable` on the document so the
 * host application can say something of its own. A `reentry_url` whose
 * scheme is not http(s), and a body whose envelope is not the documented
 * one, are treated exactly the same way.
 *   Pinned by `tests/ConsoleReentryInterceptorTest.php` — "degrades
 *   honestly when the deployment has configured no re-entry url" and
 *   "refuses a re-entry url whose scheme is not http or https".
 *
 * **IT NEVER SWALLOWS THE RESPONSE.** The wrapped `fetch` resolves with
 * the original response object — the body is read from a `clone()` — and
 * the XHR wrapper only ADDS a listener, so the caller's own handlers
 * still run and still see the 401. A capped Livewire request that ends
 * in a re-entry must also end in whatever the component would have done
 * with a 401, because the navigation may not happen at all.
 *   **PART EXECUTED, PART SPECIFIED.** That this script clones before
 *   reading, and adds rather than replaces the XHR listener, IS
 *   executed. That a real `Response` locks its body on first read and
 *   that `clone()` yields an independently readable one are read from
 *   the Fetch standard; the harness models them faithfully and is not a
 *   browser. And **nothing here establishes that wrapping `window.fetch`
 *   intercepts Livewire's transport at all** — that is script load order
 *   in a real page, and no test loads two scripts.
 *   Pinned by `tests/ConsoleReentryInterceptorTest.php` — "hands the
 *   capped response back to its caller rather than swallowing it".
 *
 * THE RESIDUE, named: this file is a client-side convenience and it is
 * not what enforces anything. Revocation is enforced server-side, in the
 * guard, on every route — a browser with this script disabled, blocked
 * by a Content Security Policy, or simply not loaded still cannot act
 * with a dead session; it just sits on a page whose requests all fail.
 * That is the ordering the amended D7 chose deliberately: revocation
 * truth never depends on the browser.
 */
(function (global) {
    'use strict';

    if (!global || global.__bfcConsoleReentryInstalled) {
        return;
    }

    global.__bfcConsoleReentryInstalled = true;

    var HEADER = 'BFC-Console-Reentry';
    var ERROR = 'console_reentry_required';
    var ENVELOPE_VERSION = 1;
    var LEAVING_EVENT = 'bfc:console-reentry';
    var UNAVAILABLE_EVENT = 'bfc:console-reentry-unavailable';
    var CHROME_ELEMENT_ID = 'bfc-console-chrome';

    /**
     * WHY re-entry could not be performed, carried on the unavailable
     * event's `detail.cause`. Three values and they are a closed set,
     * for the same reason every other vocabulary in this package is:
     * a listener branches on them.
     */
    // This document cannot establish its own origin, so it can never
    // verify that a response is its application's. The interceptor does
    // not install at all — and says so rather than going quietly inert.
    var CAUSE_ORIGIN_UNVERIFIABLE = 'origin_unverifiable';
    // Re-entry is required and the payload names nowhere to go: no
    // `reentry_url`, a scheme this script refuses, an envelope it does
    // not recognise, or a top window it cannot reach.
    var CAUSE_NO_DESTINATION = 'no_destination';
    // A destination was found and the browser REFUSED the navigation —
    // a sandboxed frame without top-navigation permission, or any other
    // `SecurityError` out of `Location.assign`.
    var CAUSE_NAVIGATION_REFUSED = 'navigation_refused';

    // Deliberately says only what is known: the session is over and
    // this script could not send the operator anywhere. It does not
    // guess WHY — that is what `detail.cause` is for.
    var NOTICE = 'This delegated session has ended and could not be renewed automatically. '
        + 'Return to the console that sent you here and enter again.';

    // One re-entry per page. A capped session usually fails several
    // in-flight requests at once, and each of them carries the same 401.
    var handled = false;

    function claimHandling() {
        if (handled) {
            return false;
        }

        handled = true;

        return true;
    }

    function stringOr(payload, field) {
        return payload && typeof payload[field] === 'string' && payload[field] !== '' ? payload[field] : null;
    }

    /**
     * A URL's origin — scheme plus authority, lower-cased — or null when
     * the value is not an absolute http(s) URL.
     *
     * Deliberately a string comparison rather than a `URL` parse: both
     * sides of the comparison are values the BROWSER serialized
     * (`window.origin` and `response.url`), so both already have their
     * default ports dropped and their host normalised, and anything that
     * does not match this shape is refused rather than repaired.
     *
     * **SPECIFIED, NOT OBSERVED:** that a browser serializes those two
     * values in that shape is read from the standard. No browser has
     * been watched producing them here — the harness supplies them.
     */
    function originOf(url) {
        if (typeof url !== 'string' || url === '') {
            return null;
        }

        var match = /^(https?:)\/\/([^/?#]+)/i.exec(url);

        return match === null ? null : (match[1] + '//' + match[2]).toLowerCase();
    }

    /**
     * This document's EFFECTIVE origin, or null when it cannot be read —
     * in which case nothing is same-origin and this script does not
     * install at all, which is the fail-closed direction.
     *
     * **IT READS `window.origin`, NOT `location.origin`, AND THE
     * DIFFERENCE IS THE WHOLE POINT.** `location.origin` is derived from
     * the document's URL; `window.origin` is the document's effective
     * origin, which is what actually decides what this script may do. A
     * frame sandboxed with `allow-scripts` and WITHOUT
     * `allow-same-origin` has an OPAQUE effective origin — `window.origin`
     * is the string `"null"` — while `location.origin` still reports the
     * URL's origin. An earlier revision read `location.origin`, so the
     * install gate below could never fire in the exact case it was
     * written for.
     *
     * There is deliberately NO fallback to `location.origin` or
     * `location.href`: a fallback would restore that bug on the browsers
     * it was reached on. A runtime that does not expose `window.origin`
     * therefore gets no interceptor and is told so — the interceptor is
     * a convenience, and being wrong about an origin is not a trade this
     * script will make to keep it.
     *
     * **SPECIFIED, NOT OBSERVED:** that `window.origin` is `"null"` in a
     * sandboxed frame, and equal to `location.origin` in an ordinary
     * document, is read from the HTML standard. Neither has been watched
     * in a browser. `docs/http-contract.md` carries the observation that
     * would settle it.
     */
    function pageOrigin() {
        try {
            return originOf(global.origin);
        } catch (unreachable) {
            return null;
        }
    }

    /**
     * Whether a response came from THIS application's own origin.
     *
     * It is asked FIRST, before the status is compared or the header is
     * read at all, because until it answers true nothing about the
     * response is this contract's business.
     */
    function isSameOrigin(responseUrl) {
        var ours = pageOrigin();
        var theirs = originOf(responseUrl);

        return ours !== null && theirs !== null && ours === theirs;
    }

    /**
     * Where to send the operator, or null when the payload names nowhere
     * this script is willing to go.
     *
     * The ENVELOPE is required before anything is read out of the body:
     * a same-origin 401 carrying the sentinel header but not the
     * documented `{version, error}` pair is not this contract's answer,
     * and a future version bump must not be able to send an operator to
     * a destination read under the old rules.
     */
    function destinationFor(payload) {
        if (!payload || payload.version !== ENVELOPE_VERSION || payload.error !== ERROR) {
            return null;
        }

        var url = stringOr(payload, 'reentry_url');

        if (url === null || !/^https?:\/\//i.test(url)) {
            return null;
        }

        var returnTo = stringOr(payload, 'return_to');

        if (returnTo === null) {
            return url;
        }

        return url + (url.indexOf('?') === -1 ? '?' : '&') + 'return_to=' + encodeURIComponent(returnTo);
    }

    /**
     * @param {string} type
     * @param {object|null} payload
     * @param {string|null} cause
     */
    function dispatch(type, payload, cause) {
        var doc = global.document;

        if (!doc || typeof doc.dispatchEvent !== 'function' || typeof global.CustomEvent !== 'function') {
            return;
        }

        doc.dispatchEvent(new global.CustomEvent(type, {
            detail: {
                reason: stringOr(payload, 'reason'),
                return_to: stringOr(payload, 'return_to'),
                cause: cause === undefined ? null : cause
            }
        }));
    }

    /**
     * Say, in the page and in an event, that re-entry could not be
     * performed. **This is the ONE thing that happens on every path
     * where the interceptor cannot finish the job** — there is no path
     * that gives up quietly.
     *
     * The chrome's TEXT is replaced only when the delegated session is
     * actually over. On {@see CAUSE_ORIGIN_UNVERIFIABLE} the session is
     * alive and the operator's attribution is still true, so the bar
     * keeps saying who they are and only gains the attribute — wiping
     * D4's attribution to report a capability this document lacks would
     * trade a correct statement for a warning.
     */
    function announce(payload, cause) {
        var doc = global.document;

        if (doc && typeof doc.getElementById === 'function') {
            var element = doc.getElementById(CHROME_ELEMENT_ID);

            if (element) {
                element.setAttribute('data-bfc-console-reentry', 'unavailable');

                if (cause !== CAUSE_ORIGIN_UNVERIFIABLE) {
                    element.textContent = NOTICE;
                }
            }
        }

        dispatch(UNAVAILABLE_EVENT, payload, cause);
    }

    /**
     * The top-level window's location, or null when this document cannot
     * reach it (a cross-origin embed throws on the property access).
     */
    function topLocation() {
        try {
            var top = global.top;

            return top && top.location && typeof top.location.assign === 'function' ? top.location : null;
        } catch (unreachable) {
            return null;
        }
    }

    function reenter(payload) {
        var destination = destinationFor(payload);
        var location = destination === null ? null : topLocation();

        if (!claimHandling()) {
            return;
        }

        if (location === null) {
            announce(payload, CAUSE_NO_DESTINATION);

            return;
        }

        // Announced synchronously, immediately before the navigation, so
        // a listener that persists a draft has actually run by the time
        // the page starts leaving. Not cancelable — see the docblock.
        dispatch(LEAVING_EVENT, payload, null);

        try {
            location.assign(destination);
        } catch (refused) {
            // `Location.assign` is exposed across origins and THROWS —
            // a sandboxed frame without top-navigation permission
            // raises `SecurityError`, and the HTML navigation algorithm
            // is specified to navigate with exceptions enabled. An
            // earlier revision left this call outside every guard, so a
            // refusal happened AFTER the response had been claimed and
            // the departure event emitted: the operator sat on a dead
            // page believing a re-entry was under way. It is the last
            // silent failure in this file and it is closed here.
            announce(payload, CAUSE_NAVIGATION_REFUSED);
        }
    }

    // A DOCUMENT THAT CANNOT NAME ITS OWN ORIGIN CANNOT VERIFY ANY
    // RESPONSE. A sandboxed iframe and `about:blank` both report an
    // opaque origin — the literal string `"null"` — so the same-origin
    // gate can never pass and every response would be ignored. That is
    // the right answer and it is a NEW limitation this check introduced;
    // going quietly inert about it is not. The interceptor says so, once,
    // at install time — where nothing an attacker controls has reached
    // it yet — and then does not install at all, so there is no path
    // left on which it could act on a response it cannot attribute.
    if (pageOrigin() === null) {
        announce(null, CAUSE_ORIGIN_UNVERIFIABLE);

        return;
    }

    var nativeFetch = global.fetch;

    if (typeof nativeFetch === 'function') {
        global.fetch = function () {
            return nativeFetch.apply(this, arguments).then(function (response) {
                inspectResponse(response);

                // The caller gets the response it would have got. The
                // body above is read from a clone, so it is still
                // unread here.
                return response;
            });
        };
    }

    function inspectResponse(response) {
        if (!response || !isSameOrigin(response.url)) {
            return;
        }

        if (!response.headers || typeof response.headers.get !== 'function') {
            return;
        }

        if (response.status !== 401 || response.headers.get(HEADER) !== '1') {
            return;
        }

        if (typeof response.clone !== 'function') {
            reenter(null);

            return;
        }

        response.clone().json().then(reenter, function () {
            // An unreadable body still means re-entry — our own origin
            // and the header said so — it just names no destination.
            reenter(null);
        });
    }

    var NativeXhr = global.XMLHttpRequest;

    if (typeof NativeXhr === 'function' && NativeXhr.prototype && typeof NativeXhr.prototype.send === 'function') {
        var nativeSend = NativeXhr.prototype.send;

        NativeXhr.prototype.send = function () {
            var request = this;

            if (typeof request.addEventListener === 'function') {
                // ADDED, never replaced: the caller's own handlers run
                // exactly as they would have.
                request.addEventListener('load', function () {
                    inspectRequest(request);
                });
            }

            return nativeSend.apply(this, arguments);
        };
    }

    function inspectRequest(request) {
        if (!isSameOrigin(request.responseURL)) {
            return;
        }

        if (typeof request.getResponseHeader !== 'function') {
            return;
        }

        if (request.status !== 401 || request.getResponseHeader(HEADER) !== '1') {
            return;
        }

        var payload = null;

        try {
            payload = JSON.parse(request.responseText);
        } catch (unreadable) {
            payload = null;
        }

        reenter(payload);
    }
})(typeof window !== 'undefined' ? window : null);
