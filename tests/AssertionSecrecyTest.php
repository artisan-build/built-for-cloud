<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Http\Controllers\ConsoleEnter;
use ArtisanBuild\BuiltForCloud\Tests\AssertionParameterScan;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\UnmarkedAssertionFrame;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Route;

uses(RefreshDatabase::class);

/**
 * A CONSOLE ASSERTION IS A LIVE CREDENTIAL, AND NO FRAME MAY LEAK ONE
 * INTO A STACK TRACE.
 *
 * PR3 marked `ConsoleGuard::redeem()` and that was right for the one
 * caller that existed. PR4 made `AssertionVerifier::verify()` reachable
 * from a new frame, and three frames on that path — `verify()`,
 * `keyIdOf()` and the endpoint's `spendAndRedeem()` — held the token
 * unmarked. With `zend.exception_ignore_args=0`, an ordinary setting, a
 * database failure inside the burn or a keyring lookup writes the
 * complete `v4.public…` token into the customer's own logs.
 *
 * Marking the frames somebody noticed would leave the next one to be
 * found the same way, so the rule is ENUMERATED over the whole console
 * assertion path.
 */
it('marks every frame in this package that holds console assertion bytes', function (): void {
    $classes = AssertionParameterScan::classesIn(
        dirname(__DIR__).'/src',
        AssertionParameterScan::ROOTS,
    );

    // The walk really visited the path, so a scanner that enumerated
    // nothing cannot report "clean".
    expect(count($classes))->toBeGreaterThan(15)
        ->and(AssertionParameterScan::unprotectedIn($classes))->toBe([]);

    // An exact SET, not merely "none unmarked": a frame REMOVED from
    // this list is drift too — it would mean the bytes now travel
    // somewhere this test no longer looks.
    expect(AssertionParameterScan::framesIn($classes))->toBe([
        'AssertionVerifier::keyIdOf($token)',
        'AssertionVerifier::verify($token)',
        // The three the name rule could never have seen. `__invoke` is
        // the one that mattered: it holds the submitted form, and the
        // fail-closed audit made it an exception path in the same round
        // that the name-matching scan was introduced.
        'ConsoleEnter::__invoke($request)',
        'ConsoleEnter::assertionToken($request)',
        'ConsoleEnter::forgetPresentedAssertion($request)',
        'ConsoleEnter::spendAndRedeem($token)',
        'ConsoleGuard::redeem($assertionToken)',
        // Not an assertion, but the same rule and the same reason: this
        // request carries a live operator bearer token.
        'ConsoleKeyDelivery::optionalFrom($request)',
    ]);
});

it('names an unmarked assertion frame when the walk meets one', function (): void {
    // Proven able to fail, on both scenarios: a new frame taking the
    // token without the attribute, and a frame holding the REQUEST —
    // the shape the first revision of this scan could not see at all,
    // because it matched parameter names and a request is called
    // `$request`.
    expect(AssertionParameterScan::unprotectedIn([UnmarkedAssertionFrame::class]))
        ->toBe([
            'UnmarkedAssertionFrame::handle($request)',
            'UnmarkedAssertionFrame::verify($token)',
        ]);

    expect(AssertionParameterScan::framesIn([UnmarkedAssertionFrame::class]))
        ->toBe([
            'UnmarkedAssertionFrame::guarded($request)',
            'UnmarkedAssertionFrame::handle($request)',
            'UnmarkedAssertionFrame::redeem($assertionToken)',
            'UnmarkedAssertionFrame::verify($token)',
        ]);
});

it('takes the presented assertion out of the request before anything can throw', function (): void {
    // The wide exposure is not the stack frame — PHP prints an object
    // argument as `Object(Illuminate\Http\Request)` and none of its
    // contents. It is a rich error reporter serializing request INPUT
    // alongside the trace, which no attribute touches. So the
    // credential is removed from the request object as soon as it is
    // read, and every failure path unwinds without it.
    $seen = [];

    Route::middleware([StartSession::class])->post('/console-enter-probe', function (Request $request) use (&$seen): array {
        $seen['before'] = $request->input('assertion');

        app(ConsoleEnter::class)($request);

        $seen['after'] = $request->input('assertion');

        return ['ok' => true];
    });

    $handoff = consoleHandoff('/orders');

    $this->post('/console-enter-probe', $handoff)->assertOk();

    expect($seen['before'])->toBe($handoff['assertion'])
        ->and($seen['after'])->toBeNull();
});
