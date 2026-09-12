<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

enum CredentialPurpose: string
{
    case OperatorManagement = 'operator_management';
    case DashboardMetadata = 'dashboard_metadata';
    case Consumption = 'consumption';
    case Mcp = 'mcp';
    case Signing = 'signing';
    case SigningRoot = 'signing_root';
    case Enrollment = 'enrollment';
    case SystemDeployment = 'system_deployment';

    /** @return list<string> */
    public static function values(): array
    {
        return array_map(static fn (self $purpose): string => $purpose->value, self::cases());
    }

    public function allowedFor(CredentialKind $kind, SubjectType $subjectType): bool
    {
        return match ($kind) {
            CredentialKind::Hmac => $this === self::Signing,
            CredentialKind::Asymmetric => $this === self::Enrollment,
            CredentialKind::Bearer, CredentialKind::Basic => match ($subjectType) {
                SubjectType::Operator => in_array($this, [self::OperatorManagement, self::DashboardMetadata], true),
                SubjectType::Application, SubjectType::Installation => $this === self::SystemDeployment,
                SubjectType::ExternalConsumer, SubjectType::UserPrincipal => in_array($this, [self::Consumption, self::Mcp], true),
            },
        };
    }
}
