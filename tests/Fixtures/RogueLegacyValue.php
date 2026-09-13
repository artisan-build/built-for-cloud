<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

/**
 * Implements only the legacy Serializable interface, so it serialises in `C:` format.
 * Restricting allowed_classes turns it into __PHP_Incomplete_Class, and PHP then warns
 * that it has no unserialiser — which the application's error handler raises.
 */
class RogueLegacyValue implements \Serializable
{
    public function serialize(): string
    {
        return 'legacy';
    }

    public function unserialize(string $data): void {}
}
