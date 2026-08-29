// A minimal browser stand-in for the console re-entry interceptor.
//
// It exists because the interceptor is JavaScript, and a PHP assertion
// about a JavaScript file can only ever be a claim about its TEXT. This
// runs the shipped file — the same bytes the route serves — inside a
// node `vm` context carrying just enough of a window to drive it, and
// prints what the script actually did as JSON.
//
// WHAT IT PROVES, EXACTLY: the script's own logic — which responses it
// acts on, what destination it builds, which cause it announces, in what
// order. WHAT IT CANNOT PROVE: any of the browser behaviour it feeds the
// script. Every value below is a MODEL of something read from a
// standard, never something a browser produced. A model that is wrong
// yields a suite that agrees with the mistake, and that has already
// happened here once: an earlier version modelled `location.origin` as
// the document's effective origin, so the interceptor's install gate and
// this harness were wrong together and the tests confirmed it.
//
// Everything here is a test double. Nothing in it is shipped.

import { readFileSync } from 'node:fs';
import { createContext, runInContext } from 'node:vm';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(resolve(here, '../../resources/js/console-reentry.js'), 'utf8');

const scenario = process.argv[2];

const CHROME_ELEMENT_ID = 'bfc-console-chrome';

// The origin the console page is served from. Every same-origin scenario
// answers from here; the cross-origin ones deliberately do not.
const PAGE_ORIGIN = 'https://app.test';
const SAME_ORIGIN_URL = PAGE_ORIGIN + '/livewire/update';
const CROSS_ORIGIN_URL = 'https://analytics.vendor.test/collect';

const observed = {
    scenario,
    topAssigned: null,
    frameAssigned: null,
    events: [],
    // ONE ORDERED CHANNEL carrying the DOM events AND the navigation,
    // interleaved in the order they actually happened. `events` alone
    // could never show that `bfc:console-reentry` precedes the
    // navigation, and that ordering is the whole promise behind "unsaved
    // work is lost, but you can persist first".
    timeline: [],
    chromeElement: null,
    callerSawStatus: null,
    callerSawBody: null,
    callerGotSameResponse: null,
    callerSawBodyTwice: null,
    callerLoadFired: false,
};

/**
 * A `Response` stand-in with REAL body-lock semantics: the body may be
 * read once, a second read throws the way a browser's does, and
 * `clone()` refuses once the body is used. Without that, the harness
 * would pass just as happily if the interceptor read the ORIGINAL body
 * instead of a clone — which is precisely the thing that would break
 * the caller.
 */
function makeResponse(status, headers, body, url) {
    const build = () => {
        let bodyUsed = false;

        const consume = () => {
            if (bodyUsed) {
                throw new TypeError('Failed to execute \'text\' on \'Response\': body stream already read');
            }

            bodyUsed = true;

            return body;
        };

        return {
            url,
            status,
            headers: { get: (name) => (name in headers ? headers[name] : null) },
            get bodyUsed() { return bodyUsed; },
            clone() {
                if (bodyUsed) {
                    throw new TypeError('Failed to execute \'clone\' on \'Response\': body stream already read');
                }

                return build();
            },
            json: async () => JSON.parse(consume()),
            text: async () => consume(),
        };
    };

    return build();
}

function makeWindow(options) {
    const chromeElement = options.withChromeElement
        ? { attributes: {}, textContent: '', setAttribute(key, value) { this.attributes[key] = value; } }
        : null;

    const frameLocation = {
        origin: PAGE_ORIGIN,
        href: PAGE_ORIGIN + '/orders',
        assign: (url) => {
            observed.frameAssigned = url;
            observed.timeline.push('navigate:frame');
        },
    };
    const topLocation = {
        origin: PAGE_ORIGIN,
        href: PAGE_ORIGIN + '/orders',
        assign: (url) => {
            observed.timeline.push('navigate:top');

            if (options.navigationRefused) {
                // What a real browser does when a sandboxed frame has no
                // top-navigation permission: `Location.assign` is exposed
                // across origins and THROWS. The property access the
                // script guards is a different operation and would not
                // have caught this.
                throw new Error('SecurityError: The operation is insecure.');
            }

            observed.topAssigned = url;
        },
    };

    const document = {
        getElementById: (id) => (id === CHROME_ELEMENT_ID ? chromeElement : null),
        dispatchEvent: (event) => {
            observed.events.push({ type: event.type, detail: event.detail });
            observed.timeline.push('event:' + event.type);

            return true;
        },
    };

    function CustomEvent(type, init) {
        this.type = type;
        this.detail = init && init.detail;
    }

    // `origin` is the document's EFFECTIVE origin and is what the script
    // reads; `location.origin` is derived from the URL and is
    // deliberately kept SEPARATE here, because the two differ in exactly
    // the case the install gate exists for.
    //
    // SPECIFIED, NOT OBSERVED: that a browser reports them as modelled.
    const window = { document, CustomEvent, location: frameLocation, origin: PAGE_ORIGIN };

    if (options.topUnreachable) {
        Object.defineProperty(window, 'top', {
            get() { throw new Error('cross-origin frame'); },
        });
    } else if (options.framed) {
        window.top = { location: topLocation };
    } else {
        // A top-level document: window.top IS window, and its location
        // is the one location there is.
        window.top = window;
        window.location = topLocation;
    }

    if (options.originUnreadable) {
        // A runtime that does not expose `window.origin` at all — the
        // fail-closed case. `location` still reports a perfectly good
        // origin, and the script deliberately does not fall back to it.
        delete window.origin;
        window.top = window;
    }

    if (options.opaqueOrigin) {
        // THE CASE THE INSTALL GATE EXISTS FOR, modelled correctly this
        // time: a frame sandboxed with `allow-scripts` and without
        // `allow-same-origin` has an OPAQUE effective origin — so
        // `window.origin` is the literal string "null" — WHILE
        // `location.origin` still reports the page URL's origin. A
        // harness that set only `location.origin` would let a script
        // reading `location.origin` pass, which is how the earlier bug
        // survived its own test.
        window.origin = 'null';
        window.location = { origin: PAGE_ORIGIN, href: SAME_ORIGIN_URL, assign: topLocation.assign };
        window.top = window;
    }

    const responseUrl = 'responseUrl' in options ? options.responseUrl : SAME_ORIGIN_URL;

    window.fetch = async () => makeResponse(options.status, options.headers, options.body, responseUrl);

    class FakeXhr {
        constructor() {
            this.listeners = {};
            this.status = 0;
            this.responseText = '';
            this.responseURL = '';
            this.responseHeaders = {};
        }

        addEventListener(type, listener) {
            (this.listeners[type] = this.listeners[type] || []).push(listener);
        }

        open() {}

        send() {
            queueMicrotask(() => {
                this.status = options.status;
                this.responseText = options.body;
                this.responseURL = responseUrl;
                this.responseHeaders = options.headers;

                for (const listener of this.listeners.load || []) {
                    listener.call(this, { type: 'load' });
                }
            });
        }

        getResponseHeader(name) {
            return name in this.responseHeaders ? this.responseHeaders[name] : null;
        }
    }

    window.XMLHttpRequest = FakeXhr;

    return { window, chromeElement };
}

const REENTRY_HEADERS = { 'BFC-Console-Reentry': '1' };

/**
 * The body the server actually emits, with whatever this scenario needs
 * to break in it.
 */
function reentryBody(overrides = {}) {
    return JSON.stringify({
        version: 1,
        error: 'console_reentry_required',
        reason: 'assertion_age_cap',
        reentry_url: 'https://scalpels.test/console/re-enter',
        return_to: '/orders',
        ...overrides,
    });
}

const scenarios = {
    'fetch-redirect': {
        status: 401,
        headers: REENTRY_HEADERS,
        body: reentryBody({ return_to: '/orders?page=2' }),
        withChromeElement: true,
    },
    'fetch-redirect-framed': {
        framed: true,
        status: 401,
        headers: REENTRY_HEADERS,
        body: reentryBody({ reentry_url: 'https://scalpels.test/console/re-enter?tenant=acme' }),
        withChromeElement: true,
    },
    'fetch-top-unreachable': {
        topUnreachable: true,
        status: 401,
        headers: REENTRY_HEADERS,
        body: reentryBody(),
        withChromeElement: true,
    },
    'fetch-no-reentry-url': {
        status: 401,
        headers: REENTRY_HEADERS,
        body: JSON.stringify({
            version: 1,
            error: 'console_reentry_required',
            reason: 'session_invalidated',
            return_to: '/orders',
        }),
        withChromeElement: true,
    },
    'fetch-hostile-reentry-url': {
        status: 401,
        headers: REENTRY_HEADERS,
        body: reentryBody({ reason: 'not_authenticated', reentry_url: 'javascript:alert(1)' }),
        withChromeElement: true,
    },
    'fetch-ordinary-401': {
        status: 401,
        headers: {},
        body: JSON.stringify({ message: 'Unauthenticated.' }),
        withChromeElement: true,
    },
    // The forgery: a CORS-readable third party answering 401 with the
    // sentinel header exposed and a destination of its choosing.
    'fetch-cross-origin': {
        responseUrl: CROSS_ORIGIN_URL,
        status: 401,
        headers: REENTRY_HEADERS,
        body: reentryBody({ reentry_url: 'https://phish.attacker.test/login', return_to: '/admin' }),
        withChromeElement: true,
    },
    'xhr-cross-origin': {
        responseUrl: CROSS_ORIGIN_URL,
        status: 401,
        headers: REENTRY_HEADERS,
        body: reentryBody({ reentry_url: 'https://phish.attacker.test/login', return_to: '/admin' }),
        withChromeElement: true,
        transport: 'xhr',
    },
    // An opaque response has an empty url: not verifiable, so ignored.
    'fetch-unreadable-url': {
        responseUrl: '',
        status: 401,
        headers: REENTRY_HEADERS,
        body: reentryBody(),
        withChromeElement: true,
    },
    // A document that cannot report its own origin: nothing can be
    // same-origin, so nothing happens.
    'fetch-origin-unreadable': {
        originUnreadable: true,
        status: 401,
        headers: REENTRY_HEADERS,
        body: reentryBody(),
        withChromeElement: true,
    },
    // Same origin and the right header, but not this contract's body.
    'fetch-wrong-envelope-version': {
        status: 401,
        headers: REENTRY_HEADERS,
        body: reentryBody({ version: 2 }),
        withChromeElement: true,
    },
    'fetch-wrong-envelope-error': {
        status: 401,
        headers: REENTRY_HEADERS,
        body: reentryBody({ error: 'something_else' }),
        withChromeElement: true,
    },
    // The browser REFUSES the navigation: `Location.assign` throws.
    'fetch-navigation-refused': {
        navigationRefused: true,
        status: 401,
        headers: REENTRY_HEADERS,
        body: reentryBody(),
        withChromeElement: true,
    },
    // A document with an opaque origin. Nothing is fetched at all: the
    // script reports its own inertness at install time.
    'opaque-origin-document': {
        opaqueOrigin: true,
        status: 401,
        headers: REENTRY_HEADERS,
        body: reentryBody(),
        withChromeElement: true,
        transport: 'none',
    },
    'xhr-redirect': {
        status: 401,
        headers: REENTRY_HEADERS,
        body: reentryBody(),
        withChromeElement: true,
        transport: 'xhr',
    },
};

const options = scenarios[scenario];

if (!options) {
    process.stderr.write(`Unknown scenario: ${scenario}\n`);
    process.exit(2);
}

const { window, chromeElement } = makeWindow(options);

runInContext(source, createContext({ window }));

async function settle() {
    // Let the interceptor's own promise chain and microtasks finish.
    for (let round = 0; round < 10; round++) {
        await new Promise((done) => setTimeout(done, 0));
    }
}

if (options.transport === 'xhr') {
    const request = new window.XMLHttpRequest();

    request.addEventListener('load', function () {
        observed.callerLoadFired = true;
        observed.callerSawStatus = this.status;
        observed.callerSawBody = this.responseText;
    });

    request.open('POST', '/livewire/update');
    request.send();
} else if (options.transport !== 'none') {
    const response = await window.fetch('/livewire/update');

    observed.callerSawStatus = response.status;
    observed.callerGotSameResponse = typeof response.json === 'function';

    // The caller reads the body it was handed. This only works if the
    // interceptor read a CLONE — a real Response locks its body on first
    // read, and so does this double.
    observed.callerSawBody = await response.text();

    // And the lock is real: a second read throws, exactly as a browser's
    // does. Without this the "never swallows" test would pass against a
    // stand-in with no body semantics at all.
    try {
        await response.text();
        observed.callerSawBodyTwice = true;
    } catch (locked) {
        observed.callerSawBodyTwice = false;
    }
}

await settle();

observed.chromeElement = chromeElement
    ? { attributes: chromeElement.attributes, textContent: chromeElement.textContent }
    : null;

process.stdout.write(JSON.stringify(observed));
