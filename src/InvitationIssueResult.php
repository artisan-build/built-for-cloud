<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

/**
 * What the invite verb hands its transports. The HUMAN path always
 * carries the issued invitation and its sealed {@see MintedSecret} for
 * the transport's single reveal. The INTEGRATION path always hands back
 * {@see acknowledged()} — whatever the gate decided — so no transport
 * can leak gate state (SEC-V3-05 non-enumeration); on that path delivery
 * to an addressed invitee happens inside the action, after commit.
 */
final readonly class InvitationIssueResult
{
    public function __construct(
        public ?string $invitationId,
        public ?MintedSecret $code,
        public ?string $email,
    ) {}

    /**
     * The integration path's ONE answer — applied, ignored-older, or
     * replayed alike: acknowledged, nothing revealed, indistinguishable
     * in shape from every other integration answer.
     */
    public static function acknowledged(): self
    {
        return new self(null, null, null);
    }
}
