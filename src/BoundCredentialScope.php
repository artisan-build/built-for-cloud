<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;

/** The exact app-owned and installation-owned scope of a protocol credential. */
final readonly class BoundCredentialScope
{
    public function __construct(
        public string $appPurpose,
        public Subject $subject,
        public string $installation,
        public string $application,
        public string $audience,
    ) {
        self::assertString($this->appPurpose);
        self::assertString($this->subject->ref);
        self::assertString($this->installation);
        self::assertString($this->application);
        self::assertString($this->audience);

        if (preg_match('/\A[^,\s]{1,255}\z/uD', $this->audience) !== 1) {
            throw InvalidCredentialInput::invalidBoundScope();
        }
    }

    private static function assertString(string $value): void
    {
        if ($value === ''
            || strlen($value) > 255
            || ! mb_check_encoding($value, 'UTF-8')
            || preg_match('/[\x00-\x1F\x7F]/', $value) === 1) {
            throw InvalidCredentialInput::invalidBoundScope();
        }
    }
}
