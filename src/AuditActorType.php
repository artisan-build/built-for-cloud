<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

/**
 * The three principals D8 names — a bound user, an operator integration,
 * and the local CLI operator — plus the party a claim surface can
 * actually attribute: whoever presented the code or credential itself. No
 * user PII beyond ids/refs ever rides an actor.
 */
enum AuditActorType: string
{
    case BoundUser = 'bound_user';
    case OperatorIntegration = 'operator_integration';
    case CliOperator = 'cli_operator';
    case CredentialHolder = 'credential_holder';
}
