<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

enum CredentialPurpose: string
{
    public const string SIGNING_ROOT_SUBJECT_REF = 'bfc:signing-root';

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
                SubjectType::Application => $this === self::SystemDeployment,
                SubjectType::Installation => in_array($this, [self::SystemDeployment, self::Consumption, self::Mcp], true),
                SubjectType::ExternalConsumer, SubjectType::UserPrincipal => in_array($this, [self::Consumption, self::Mcp], true),
            },
        };
    }

    public function validForStorage(
        CredentialKind $kind,
        SubjectType $subjectType,
        string $subjectRef,
    ): bool {
        if ($subjectType === SubjectType::Installation && $subjectRef === self::SIGNING_ROOT_SUBJECT_REF) {
            return $kind === CredentialKind::Hmac && $this === self::SigningRoot;
        }

        return $this->allowedFor($kind, $subjectType)
            || ($kind === CredentialKind::Bearer
                && $subjectType === SubjectType::ExternalConsumer
                && $this === self::Enrollment);
    }
}
