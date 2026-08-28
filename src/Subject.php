<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

/**
 * A credential's subject: the thing a revocation costs. `ref` carries the
 * tenant partition key — tenancy lives here, never in a credential's name.
 */
final readonly class Subject
{
    public function __construct(
        public SubjectType $type,
        public string $ref,
    ) {}
}
