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
 * IT BRANCHES ON THE HEADER, NOT THE BODY. The header is the contract's
 * branch point precisely so a client never has to parse a body to know
 * what happened; the body is read only for WHERE to go, and a body that
 * cannot be parsed degrades to the no-destination path rather than to a
 * guess.
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
 * **AN ABSENT `reentry_url` IS NOT AN ERROR TO SWALLOW AND NOT A
 * DESTINATION TO INVENT.** The server omits that field entirely when the
 * deployment has configured no issuer URL, because an app that cannot
 * reach its issuer must degrade honestly. So does this script: it
 * navigates nowhere, marks the chrome element as unable to re-enter, and
 * dispatches `bfc:console-reentry-unavailable` on the document so the
 * host application can say something of its own. A `reentry_url` whose
 * scheme is not http(s) is treated exactly the same way.
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
    var EVENT = 'bfc:console-reentry-unavailable';
    var CHROME_ELEMENT_ID = 'bfc-console-chrome';
    // Deliberately says only what is known: the session is over and
    // this script could not send the operator anywhere. It does not
    // guess WHY — an unconfigured issuer, a scheme this script refuses,
    // and a top window it cannot reach are three different causes with
    // one honest answer.
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
     * Where to send the operator, or null when the payload names nowhere
     * this script is willing to go.
     */
    function destinationFor(payload) {
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
     * Say, in the page and in an event, that a re-entry is required and
     * could not be performed. This is the honest-degradation path: no
     * navigation, nothing invented, and nothing silently dropped.
     */
    function announce(payload) {
        var doc = global.document;

        if (!doc) {
            return;
        }

        if (typeof doc.getElementById === 'function') {
            var element = doc.getElementById(CHROME_ELEMENT_ID);

            if (element) {
                element.setAttribute('data-bfc-console-reentry', 'unavailable');
                element.textContent = NOTICE;
            }
        }

        if (typeof doc.dispatchEvent === 'function' && typeof global.CustomEvent === 'function') {
            doc.dispatchEvent(new global.CustomEvent(EVENT, {
                detail: {
                    reason: stringOr(payload, 'reason'),
                    return_to: stringOr(payload, 'return_to')
                }
            }));
        }
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

        location.assign(destination);
    }

    function isReentry(status, header) {
        return status === 401 && header === '1';
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
        if (!response || !response.headers || typeof response.headers.get !== 'function') {
            return;
        }

        if (!isReentry(response.status, response.headers.get(HEADER))) {
            return;
        }

        if (typeof response.clone !== 'function') {
            reenter(null);

            return;
        }

        response.clone().json().then(reenter, function () {
            // An unreadable body still means re-entry — the header said
            // so — it just names no destination.
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
        if (typeof request.getResponseHeader !== 'function') {
            return;
        }

        if (!isReentry(request.status, request.getResponseHeader(HEADER))) {
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
