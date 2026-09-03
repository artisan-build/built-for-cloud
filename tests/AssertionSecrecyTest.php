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
        'AuthenticateMcp::authenticateAssertion($assertionToken)',
        'AuthenticateMcp::authenticateAssertion($request)',
        'AuthenticateMcp::handle($request)',
        // The three the name rule could never have seen. `__invoke` is
        // the one that mattered: it holds the submitted form, and the
        // fail-closed audit made it an exception path in the same round
        // that the name-matching scan was introduced.
        'ConsoleEnter::__invoke($request)',
        'ConsoleEnter::assertionToken($presentedToken)',
        'ConsoleEnter::forgetPresentedAssertion($request)',
        'ConsoleEnter::spendAndRedeem($token)',
        'ConsoleGuard::redeem($assertionToken)',
        // Not an assertion, but the same rule and the same reason: this
        // request carries a live operator bearer token.
        'ConsoleKeyDelivery::optionalFrom($request)',
        // UNTYPED parameters, which the first two revisions of the rule
        // also could not see. PR3 marked them by hand; the enumeration
        // now says so.
        'DelegatedActorProvider::retrieveByToken($token)',
        'DelegatedActorProvider::updateRememberToken($token)',
        'RequestAssertion::principal($request)',
        'RequestAssertion::publish($request)',
    ]);
});

it('names the shapes it cannot reach, so the claim beside it stays true', function (): void {
    // NOT A PROOF — a statement of the bound, kept beside the scan so
    // the claim it supports cannot quietly grow past it. The walk turns
    // a file path into ONE class name and reflects that, so a package
    // function, an anonymous class or a standalone trait can introduce
    // an assertion-bearing frame that is never inspected. PHP has more
    // ways to make a frame than a file-and-classname walk can reach.
    $root = sys_get_temp_dir().'/bfc-frame-shapes-'.bin2hex(random_bytes(6));

    mkdir($root.'/Console', 0700, true);

    // A file whose name derives no class at all: a package function
    // taking the token, invisible to the walk.
    file_put_contents(
        $root.'/Console/helpers.php',
        "<?php\n\nnamespace ArtisanBuild\\BuiltForCloud\\Console;\n\nfunction leak(string \$token): void {}\n",
    );

    try {
        // The file is walked and yields nothing, because there is no
        // class of that name to reflect. That is the residue, named.
        expect(AssertionParameterScan::classesIn($root, ['Console']))->toBe([])
            ->and(AssertionParameterScan::framesIn([]))->toBe([]);
    } finally {
        unlink($root.'/Console/helpers.php');
        rmdir($root.'/Console');
        rmdir($root);
    }
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

it('takes the presented assertion out of the request before any validation runs', function (): void {
    // The wide exposure is not the stack frame — PHP prints an object
    // argument as `Object(Illuminate\Http\Request)` and none of its
    // contents. It is a rich error reporter serializing request INPUT
    // alongside the trace, which no attribute touches. So the
    // credential is removed in the THIRD statement of the endpoint,
    // preceded only by the two reads that make it possible.
    //
    // Both directions are driven, because the REFUSAL path is the one
    // an earlier revision got wrong: the missing-field check used to
    // run first, so a refusal unwound with the field still present.
    $seen = [];

    Route::middleware([StartSession::class])->post('/console-enter-probe', function (Request $request) use (&$seen): array {
        $seen['before'] = $request->input('assertion');

        try {
            app(ConsoleEnter::class)($request);
        } catch (Throwable $failure) {
            $seen['threw'] = $failure::class;
        }

        $seen['after'] = $request->input('assertion');

        return ['ok' => true];
    });

    $handoff = consoleHandoff('/orders');

    $this->post('/console-enter-probe', $handoff)->assertOk();

    expect($seen['before'])->toBe($handoff['assertion'])
        ->and($seen['after'])->toBeNull();

    // …and on the refusal path, where the value is present, is not a
    // string, and is refused before anything else looks at it.
    $seen = [];

    $this->post('/console-enter-probe', ['assertion' => ['not', 'a', 'string'], 'state' => $handoff['state']])
        ->assertOk();

    expect($seen['before'])->toBe(['not', 'a', 'string'])
        ->and($seen['after'])->toBeNull()
        ->and($seen)->not->toHaveKey('threw');
});
