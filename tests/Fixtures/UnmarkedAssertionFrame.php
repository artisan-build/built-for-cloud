<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Tests\AssertionParameterScan;
use SensitiveParameter;

/**
 * The offence {@see AssertionParameterScan}
 * exists to name: a frame that takes console assertion bytes and does
 * not mark them, so a throw below it puts a live admin-minting
 * credential into a stack trace.
 *
 * It carries a marked frame and a non-secret `$tokenId` too, so the scan
 * is driven on all three answers rather than only the failing one.
 */
final class UnmarkedAssertionFrame
{
    public function redeem(#[SensitiveParameter] string $assertionToken): void {}

    public function verify(string $token): void {}

    /** An identifier, not a secret — and it does not end in `token`. */
    public function audit(string $tokenId): void {}
}
