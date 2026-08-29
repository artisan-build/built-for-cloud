// A minimal browser stand-in for the console re-entry interceptor.
//
// It exists because the interceptor is JavaScript, and a PHP assertion
// about a JavaScript file can only ever be a claim about its TEXT. This
// runs the shipped file — the same bytes the route serves — inside a
// node `vm` context carrying just enough of a window to drive it, and
// prints what the script actually did as JSON.
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

const observed = {
    scenario,
    topAssigned: null,
    frameAssigned: null,
    events: [],
    chromeElement: null,
    callerSawStatus: null,
    callerSawBody: null,
    callerGotSameResponse: null,
    callerLoadFired: false,
};

function makeResponse(status, headers, body) {
    const build = () => ({
        status,
        headers: { get: (name) => (name in headers ? headers[name] : null) },
        clone: () => build(),
        json: async () => JSON.parse(body),
        text: async () => body,
    });

    return build();
}

function makeWindow(options) {
    const chromeElement = options.withChromeElement
        ? { attributes: {}, textContent: '', setAttribute(key, value) { this.attributes[key] = value; } }
        : null;

    const frameLocation = { assign: (url) => { observed.frameAssigned = url; } };
    const topLocation = { assign: (url) => { observed.topAssigned = url; } };

    const document = {
        getElementById: (id) => (id === CHROME_ELEMENT_ID ? chromeElement : null),
        dispatchEvent: (event) => {
            observed.events.push({ type: event.type, detail: event.detail });

            return true;
        },
    };

    function CustomEvent(type, init) {
        this.type = type;
        this.detail = init && init.detail;
    }

    const window = { document, CustomEvent, location: frameLocation };

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

    window.fetch = async () => makeResponse(options.status, options.headers, options.body);

    class FakeXhr {
        constructor() {
            this.listeners = {};
            this.status = 0;
            this.responseText = '';
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

const scenarios = {
    'fetch-redirect': {
        status: 401,
        headers: REENTRY_HEADERS,
        body: JSON.stringify({
            version: 1,
            error: 'console_reentry_required',
            reason: 'assertion_age_cap',
            reentry_url: 'https://scalpels.test/console/re-enter',
            return_to: '/orders?page=2',
        }),
        withChromeElement: true,
    },
    'fetch-redirect-framed': {
        framed: true,
        status: 401,
        headers: REENTRY_HEADERS,
        body: JSON.stringify({
            version: 1,
            error: 'console_reentry_required',
            reason: 'assertion_age_cap',
            reentry_url: 'https://scalpels.test/console/re-enter?tenant=acme',
            return_to: '/orders',
        }),
        withChromeElement: true,
    },
    'fetch-top-unreachable': {
        topUnreachable: true,
        status: 401,
        headers: REENTRY_HEADERS,
        body: JSON.stringify({
            version: 1,
            error: 'console_reentry_required',
            reason: 'assertion_age_cap',
            reentry_url: 'https://scalpels.test/console/re-enter',
            return_to: '/orders',
        }),
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
        body: JSON.stringify({
            version: 1,
            error: 'console_reentry_required',
            reason: 'not_authenticated',
            reentry_url: 'javascript:alert(1)',
            return_to: '/orders',
        }),
        withChromeElement: true,
    },
    'fetch-ordinary-401': {
        status: 401,
        headers: {},
        body: JSON.stringify({ message: 'Unauthenticated.' }),
        withChromeElement: true,
    },
    'xhr-redirect': {
        status: 401,
        headers: REENTRY_HEADERS,
        body: JSON.stringify({
            version: 1,
            error: 'console_reentry_required',
            reason: 'assertion_age_cap',
            reentry_url: 'https://scalpels.test/console/re-enter',
            return_to: '/orders',
        }),
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
} else {
    const response = await window.fetch('/livewire/update');

    observed.callerSawStatus = response.status;
    observed.callerGotSameResponse = typeof response.json === 'function';
    observed.callerSawBody = await response.text();
}

await settle();

observed.chromeElement = chromeElement
    ? { attributes: chromeElement.attributes, textContent: chromeElement.textContent }
    : null;

process.stdout.write(JSON.stringify(observed));
