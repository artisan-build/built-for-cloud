<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

/**
 * What `mint(Subject, MintOptions)` returns (PRD 1.6, FLT-R5): the summary
 * of what was minted AND the delivery shape the secret travels in. The
 * secret itself exists ONLY inside its sealed {@see MintedSecret} carrier —
 * this object carries the carrier, never a plaintext string — and leaves it
 * exactly once, at the transport boundary (TTY print / HTTP response
 * field).
 *
 * `basicUsername` is set only for the `basic_auth` shape: the `auth.json`
 * username half, which is presentation-only and grants nothing (the
 * credential id, so a support conversation can name the row).
 */
final readonly class MintResult
{
    public function __construct(
        public CredentialSummary $summary,
        public DeliveryShape $delivery,
        public ?MintedSecret $secret = null,
        public ?string $basicUsername = null,
    ) {}
}
