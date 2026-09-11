<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

final readonly class ManagedTransitionRosterMember
{
    public function __construct(
        public string $scalpelsId,
        public string $membershipStatus,
        public string $role,
        public string $displayName,
        public string $contactEmail,
        public bool $contactEmailVerified,
    ) {}

    /** @return array<string, bool|string> */
    public function toArray(): array
    {
        return [
            'scalpels_id' => $this->scalpelsId,
            'membership_status' => $this->membershipStatus,
            'role' => $this->role,
            'display_name' => $this->displayName,
            'contact_email' => $this->contactEmail,
            'contact_email_verified' => $this->contactEmailVerified,
        ];
    }
}
