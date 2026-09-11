<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Exceptions;

use RuntimeException;

/** @internal Restarts an optimistic acquisition through the ordinary authority-first response path. */
final class ManagedOwnerAcquisitionNotApplicable extends RuntimeException {}
