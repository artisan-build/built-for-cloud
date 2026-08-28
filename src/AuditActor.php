<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

/**
 * A polymorphic-ish actor description on an audit event: type + ref
 * strings, ids only. Absence (a null actor on the event) means the actor
 * is genuinely unknown — never guessed.
 */
final readonly class AuditActor
{
    public function __construct(
        public AuditActorType $type,
        public ?string $ref = null,
    ) {}

    public static function adminToken(string $tokenId): self
    {
        return new self(AuditActorType::AdminToken, $tokenId);
    }

    public static function boundUser(string $userId): self
    {
        return new self(AuditActorType::BoundUser, $userId);
    }

    public static function operatorIntegration(string $ref): self
    {
        return new self(AuditActorType::OperatorIntegration, $ref);
    }

    public static function cliOperator(): self
    {
        return new self(AuditActorType::CliOperator);
    }

    /**
     * The party that presented the code or credential itself — the only
     * honest attribution an unauthenticated claim surface has. The ref is
     * the id of what was presented, never who is presumed to hold it.
     */
    public static function credentialHolder(string $presentedId): self
    {
        return new self(AuditActorType::CredentialHolder, $presentedId);
    }
}
