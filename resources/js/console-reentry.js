/**
 * THE XHR RE-ENTRY INTERCEPTOR (Console PRD D7, as amended).
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
 * A response whose URL cannot be read is NOT a pass and NOT a failure to
 * report: it is ignored entirely, silently, because this script cannot
 * establish that it is even looking at its own application's answer.
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
 * not). It is deliberately NOT cancelable. The session is already dead
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
    // Deliberately says only what is known: the session is over and
    // this script could not send the operator anywhere. It does not
    // guess WHY — an unconfigured issuer, a scheme this script refuses,
    // an envelope it does not recognise, and a top window it cannot
    // reach are four different causes with one honest answer.
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
     * (`location.origin` and `response.url`), so both already have their
     * default ports dropped and their host normalised, and anything that
     * does not match this shape is refused rather than repaired.
     */
    function originOf(url) {
        if (typeof url !== 'string' || url === '') {
            return null;
        }

        var match = /^(https?:)\/\/([^/?#]+)/i.exec(url);

        return match === null ? null : (match[1] + '//' + match[2]).toLowerCase();
    }

    /**
     * This document's own origin, or null when it cannot be read — in
     * which case nothing is same-origin and this script does nothing at
     * all, which is the fail-closed direction.
     */
    function pageOrigin() {
        try {
            var location = global.location;

            if (!location) {
                return null;
            }

            return originOf(location.origin) || originOf(location.href);
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
     */
    function dispatch(type, payload) {
        var doc = global.document;

        if (!doc || typeof doc.dispatchEvent !== 'function' || typeof global.CustomEvent !== 'function') {
            return;
        }

        doc.dispatchEvent(new global.CustomEvent(type, {
            detail: {
                reason: stringOr(payload, 'reason'),
                return_to: stringOr(payload, 'return_to')
            }
        }));
    }

    /**
     * Say, in the page and in an event, that a re-entry is required and
     * could not be performed. This is the honest-degradation path: no
     * navigation, nothing invented, and nothing silently dropped.
     */
    function announce(payload) {
        var doc = global.document;

        if (doc && typeof doc.getElementById === 'function') {
            var element = doc.getElementById(CHROME_ELEMENT_ID);

            if (element) {
                element.setAttribute('data-bfc-console-reentry', 'unavailable');
                element.textContent = NOTICE;
            }
        }

        dispatch(UNAVAILABLE_EVENT, payload);
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
            announce(payload);

            return;
        }

        // Announced synchronously, immediately before the navigation, so
        // a listener that persists a draft has actually run by the time
        // the page starts leaving. Not cancelable — see the docblock.
        dispatch(LEAVING_EVENT, payload);

        location.assign(destination);
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
