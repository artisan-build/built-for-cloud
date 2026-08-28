<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

/**
 * What the invite verb hands its transports — ONE shape whatever the prior
 * state (SEC-V3-05 non-enumeration): every field nullable, and the
 * acknowledged-and-ignored outcome is the same three fields carrying null.
 * The code is a sealed {@see MintedSecret}; the transport reveals it once
 * or not at all.
 */
final readonly class InvitationIssueResult
{
    public function __construct(
        public ?string $invitationId,
        public ?MintedSecret $code,
        public ?string $email,
    ) {}

    /**
     * The version gate's answer for an event it will not apply — an older
     * version, or a replayed event id: acknowledged, nothing issued,
     * nothing revealed, indistinguishable in shape from any other answer.
     */
    public static function acknowledged(): self
    {
        return new self(null, null, null);
    }
}
