<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Tests\AssertionParameterScan;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\UnmarkedAssertionFrame;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * A CONSOLE ASSERTION IS A LIVE CREDENTIAL, AND NO FRAME MAY LEAK ONE
 * INTO A STACK TRACE.
 *
 * The first marking round covered the one caller that existed, and a
 * later round made `AssertionVerifier::verify()` reachable from a new
 * frame whose path held the token unmarked. With
 * `zend.exception_ignore_args=0`, an ordinary setting, a database
 * failure inside the burn or a keyring lookup writes the complete
 * `v4.public…` token into the customer's own logs.
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
        'AuthenticateMcp::dispatchAsInstallationSystem($request)',
        'AuthenticateMcp::forgetCredential($request)',
        'AuthenticateMcp::handle($request)',
        // Not an assertion, but the same rule and the same reason: this
        // request carries a live operator bearer token.
        'ConsoleKeyDelivery::optionalFrom($request)',
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
