<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Exceptions;

use RuntimeException;

/** @internal Carries an exchange-only contest out of its rolled-back transaction to the O1 trigger. */
final class ManagedOwnerContested extends RuntimeException {}
