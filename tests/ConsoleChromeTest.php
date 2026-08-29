<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Console\ActingPrincipalResolver;
use ArtisanBuild\BuiltForCloud\Console\ConsoleChrome;
use ArtisanBuild\BuiltForCloud\Console\ConsoleGuardConfiguration;
use ArtisanBuild\BuiltForCloud\Console\ConsoleRole;
use ArtisanBuild\BuiltForCloud\Console\DelegatedClaims;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ConsoleChromeScript;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\User;
use Carbon\CarbonImmutable;
use Illuminate\Contracts\View\View as ViewContract;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\View;

uses(RefreshDatabase::class);

/**
 * D11 and D4 in the template layer: ONE layout, branching internally on
 * the ONE resolved acting principal, rendering issuer-minted display
 * text inert.
 *
 * `/chrome-console` carries the production console stack — `bfc.console`
 * then Laravel's own `auth:bfc-console` — and renders the layout.
 * `/chrome-local` is a route guarded by the APP's own guard, and it
 * additionally reports what the delegated guard WOULD have said, which
 * is how AC4 can assert the chrome followed the resolved principal
 * rather than merely agreeing with it by luck.
 *
 * Time is frozen for every test in this file. Nothing here compares a
 * timestamp on purpose, but a delegated session carries an issued-at
 * marker that the guard measures against D7's cap, and a suite that
 * races a wall clock is a suite that goes red at a second boundary.
 */
$renderedViews = new ArrayObject;

beforeEach(function () use ($renderedViews): void {
    CarbonImmutable::setTestNow(CarbonImmutable::parse('2026-08-29 12:00:00'));

    $renderedViews->exchangeArray([]);

    // The structural record AC1 reads: which FILE each rendered view
    // resolved to, captured from the view layer itself rather than
    // inferred from the HTML.
    View::composer('*', function (ViewContract $view) use ($renderedViews): void {
        $renderedViews[$view->name()] = $view->getPath();
    });

    Route::middleware([StartSession::class, 'bfc.console', 'auth:'.ConsoleGuardConfiguration::GUARD])
        ->get('/chrome-console', fn () => view('bfc::layout'));

    Route::middleware([StartSession::class, 'auth:web'])->get('/chrome-local', function () {
        // Rendered FIRST, so the probe below cannot have influenced what
        // the layout saw.
        $rendered = view('bfc::layout')->render();

        return response($rendered)->withHeaders([
            // What the OTHER source would have said. On this route the
            // delegated guard still resolves a live delegated actor —
            // it is simply not the principal this request acts as.
            'X-Probe-Delegated-Guard' => auth(ConsoleGuardConfiguration::GUARD)->user()?->getAuthIdentifier() ?? 'none',
            'X-Probe-Resolved-Delegated' => app(ActingPrincipalResolver::class)->resolve()->delegated ? 'yes' : 'no',
        ]);
    });
});

afterEach(function (): void {
    CarbonImmutable::setTestNow();
});

function chromeLocalUser(): User
{
    return User::query()->create([
        'name' => 'Local Human',
        'email' => 'local@example.com',
        'password' => 'irrelevant',
    ]);
}

/**
 * The predicate AC5 asserts with, and the SAME predicate its positive
 * control is run against: the hostile bytes do not appear, and their
 * escaped form does.
 */
function chromeRendersInert(string $html, string $value): bool
{
    return ! str_contains($html, $value) && str_contains($html, e($value));
}

// ─── AC1: one layout file, both paths ───────────────────────────────────────

it('renders one and the same layout file for a local session and a delegated one', function () use ($renderedViews): void {
    $viewDirectory = dirname(__DIR__).'/resources/views';

    // ENUMERATED, not inferred from two happy renders: the package's
    // view namespace contains exactly these files, and exactly one of
    // them is a layout. A second layout would red this line before any
    // render happened.
    $files = array_values(array_diff((array) scandir($viewDirectory), ['.', '..']));
    sort($files);

    expect($files)->toBe(['chrome.blade.php', 'layout.blade.php']);

    // And the one name resolves to that one file.
    expect(realpath(view()->getFinder()->find('bfc::layout')))
        ->toBe(realpath($viewDirectory.'/layout.blade.php'));

    $user = chromeLocalUser();
    $actor = consoleActor(onBehalfOf: 'Acme Agency');

    $this->actingAs($user)->withSession(consoleSessionState($actor));
    $this->get('/chrome-console')->assertOk();

    $delegatedLayout = $renderedViews['bfc::layout'] ?? null;

    expect($renderedViews->getArrayCopy())->toHaveKey('bfc::chrome');

    $renderedViews->exchangeArray([]);
    $this->flushSession();

    $this->actingAs($user);
    $this->get('/chrome-local')->assertOk();

    $localLayout = $renderedViews['bfc::layout'] ?? null;

    // The delegated path rendered the chrome partial; the local path did
    // not. Same layout file, both times.
    expect($renderedViews->getArrayCopy())->not->toHaveKey('bfc::chrome')
        ->and($delegatedLayout)->not->toBeNull()
        ->and($localLayout)->toBe($delegatedLayout)
        ->and(realpath((string) $localLayout))->toBe(realpath($viewDirectory.'/layout.blade.php'));
});

// ─── AC2: a local login sees zero chrome ────────────────────────────────────

it('renders zero console chrome for a local authenticated session', function (): void {
    $user = chromeLocalUser();

    $html = $this->actingAs($user)->get('/chrome-local')->assertOk()->getContent();

    expect($html)->toBeString()
        ->not->toContain(ConsoleChrome::ELEMENT_ID)
        ->not->toContain('data-bfc-console-chrome')
        ->not->toContain('data-bfc-console-operator')
        ->not->toContain(ConsoleChrome::UNNAMED_OPERATOR)
        // No attribution, no operator identity, and no interceptor: a
        // local page carries none of the chrome's machinery either.
        ->not->toContain('/bfc/console/chrome.js');
});

// ─── AC3: a delegated session sees the full chrome ──────────────────────────

it('renders the delegated attribution the operator entered with', function (): void {
    config(['built-for-cloud.console.issuer' => 'https://scalpels.test']);

    $actor = consoleActor(displayName: 'Jane Operator', role: ConsoleRole::Member, onBehalfOf: 'Acme Agency');

    $html = (string) $this->withSession(consoleSessionState($actor))
        ->get('/chrome-console')->assertOk()->getContent();

    // D4's attribution in substance: who, for whom, and via whom.
    expect($html)->toContain(ConsoleChrome::ELEMENT_ID)
        ->toContain('Jane Operator')
        ->toContain('(Acme Agency)')
        ->toContain('via scalpels.test')
        // The role is this SESSION's role, from a two-case vocabulary.
        ->toContain('data-bfc-console-role="member"')
        // And the interceptor is on the page.
        ->toContain('src="/bfc/console/chrome.js"');
});

it('renders a delegated operator with no agency without inventing one', function (): void {
    $actor = consoleActor(displayName: 'Jane Operator', onBehalfOf: null);

    $html = (string) $this->withSession(consoleSessionState($actor))
        ->get('/chrome-console')->assertOk()->getContent();

    expect($html)->toContain('Jane Operator')
        ->not->toContain('data-bfc-console-agency');
});

// ─── AC4: the chrome follows the RESOLVED principal ─────────────────────────

it('follows the resolved acting principal, not the delegated guard the route does not name', function (): void {
    $user = chromeLocalUser();
    $actor = consoleActor(displayName: 'Jane Operator', onBehalfOf: 'Acme Agency');

    // BOTH sessions are live on this request, and the route is guarded
    // by the app's OWN guard — so the two sources genuinely differ.
    $response = $this->actingAs($user)
        ->withSession(consoleSessionState($actor))
        ->get('/chrome-local')
        ->assertOk();

    // What the other source would have said, observed inside the same
    // request: the delegated guard resolves this actor.
    expect($response->headers->get('X-Probe-Delegated-Guard'))->toBe($actor->getAuthIdentifier())
        // What the ONE resolution said.
        ->and($response->headers->get('X-Probe-Resolved-Delegated'))->toBe('no');

    // The chrome followed the resolution, not the guard.
    expect((string) $response->getContent())
        ->not->toContain(ConsoleChrome::ELEMENT_ID)
        ->not->toContain('Jane Operator')
        ->not->toContain('Acme Agency');
});

// ─── AC5: hostile display values render inert ───────────────────────────────

it('renders a hostile display name, agency and issuer inert', function (): void {
    $hostile = '<img src=x onerror=alert(1)>" onmouseover="alert(2)';
    $hostileAgency = '</span><script>alert(3)</script>';

    config(['built-for-cloud.console.issuer' => 'https://a<b"c.test/']);

    $actor = consoleActor();

    $html = (string) $this->withSession(consoleSessionState(
        $actor,
        claims: new DelegatedClaims($hostile, ConsoleRole::Admin, $hostileAgency),
    ))->get('/chrome-console')->assertOk()->getContent();

    // Every sink the chrome has: an element body, a `title` attribute
    // and the issuer label.
    expect(chromeRendersInert($html, $hostile))->toBeTrue()
        ->and(chromeRendersInert($html, $hostileAgency))->toBeTrue()
        ->and(chromeRendersInert($html, 'a<b"c.test'))->toBeTrue()
        // Nothing became markup: no tag opened and no attribute broke.
        ->and($html)->not->toContain('<img')
        ->and($html)->not->toContain('<script>alert(3)')
        ->and($html)->not->toContain('" onmouseover="');
});

it('proves the escaping assertion can fail against an unescaped sink', function (): void {
    // The positive control. The SAME predicate the test above uses is
    // run against a template that echoes the value raw — if it passed
    // there too, it would be proving nothing about the chrome.
    $hostile = '<img src=x onerror=alert(1)>" onmouseover="alert(2)';

    $escaped = Blade::render('<span title="{{ $value }}">{{ $value }}</span>', ['value' => $hostile]);
    $raw = Blade::render('<span title="{!! $value !!}">{!! $value !!}</span>', ['value' => $hostile]);

    expect(chromeRendersInert($escaped, $hostile))->toBeTrue()
        ->and(chromeRendersInert($raw, $hostile))->toBeFalse()
        ->and($raw)->toContain('<img');
});

// ─── AC6: charset and length limits on what the chrome will render ──────────

it('refuses a display claim that is over-long, control-bearing or invalid UTF-8 rather than truncating it', function (): void {
    $overLong = str_repeat('a', 121);
    $controlBearing = "Jane\u{0007}Operator";
    $invalidUtf8 = "Jane \xB1\x31 Operator";

    foreach ([$overLong, $controlBearing, $invalidUtf8] as $claim) {
        $actor = consoleActor(subject: 'operator_'.md5($claim));

        $html = (string) $this->withSession(consoleSessionState(
            $actor,
            claims: new DelegatedClaims($claim, ConsoleRole::Admin, $claim),
        ))->get('/chrome-console')->assertOk()->getContent();

        // The chrome still renders — this IS a delegated session — but
        // it names the operator with the neutral constant rather than a
        // trimmed or repaired version of a claim it will not show.
        expect($html)->toContain(ConsoleChrome::ELEMENT_ID)
            ->toContain(ConsoleChrome::UNNAMED_OPERATOR)
            ->not->toContain('data-bfc-console-agency')
            ->not->toContain(substr($claim, 0, 60));

        $this->flushSession();
    }
});

it('renders a claim exactly at the verifier bound, so the limit is a bound and not an off-by-one', function (): void {
    $atBound = str_repeat('b', 120);

    $actor = consoleActor();

    $html = (string) $this->withSession(consoleSessionState(
        $actor,
        claims: new DelegatedClaims($atBound, ConsoleRole::Admin, null),
    ))->get('/chrome-console')->assertOk()->getContent();

    expect($html)->toContain($atBound)
        ->not->toContain(ConsoleChrome::UNNAMED_OPERATOR);
});

// ─── The chrome and the interceptor agree on what they share ────────────────

it('keeps the chrome element id the interceptor script looks for', function (): void {
    // Two files, one string. The script reports an unavailable re-entry
    // by writing into the chrome's own element, so a rename on one side
    // would silently make that report land nowhere.
    expect((string) file_get_contents(ConsoleChromeScript::SOURCE))
        ->toContain("'".ConsoleChrome::ELEMENT_ID."'");
});
