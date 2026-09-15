<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Exceptions;

use RuntimeException;

final class AsymmetricEnrollmentUnavailable extends RuntimeException
{
    public function __construct()
    {
        parent::__construct('This asymmetric enrollment is unavailable.');
    }
}
