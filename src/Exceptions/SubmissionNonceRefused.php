<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Exceptions;

use RuntimeException;

final class SubmissionNonceRefused extends RuntimeException
{
    public static function invalid(): self
    {
        return new self('This personal credential submission has expired or was already used. Reload the page and try again.');
    }
}
