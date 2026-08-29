<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Tests\AssertionParameterScan;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\UnmarkedAssertionFrame;

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
        'ConsoleEnter::spendAndRedeem($token)',
        'ConsoleGuard::redeem($assertionToken)',
    ]);
});

it('names an unmarked assertion frame when the walk meets one', function (): void {
    // Proven able to fail, on the exact scenario: a new frame taking the
    // token without the attribute, beside a marked one and beside an
    // identifier that is not a secret at all.
    expect(AssertionParameterScan::unprotectedIn([UnmarkedAssertionFrame::class]))
        ->toBe(['UnmarkedAssertionFrame::verify($token)']);

    expect(AssertionParameterScan::framesIn([UnmarkedAssertionFrame::class]))
        ->toBe(['UnmarkedAssertionFrame::redeem($assertionToken)', 'UnmarkedAssertionFrame::verify($token)']);
});
