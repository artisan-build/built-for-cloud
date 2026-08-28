<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Exceptions;

use RuntimeException;

/**
 * The invite verb's version gate could not decide an integration event
 * within its bounded attempts — every whole transactional attempt lost a
 * gate-row race to a concurrent delivery. Nothing was applied and no
 * partial state remains (each attempt rolled back whole), so retrying is
 * safe. The message is clean and secret-free: the HTTP transport maps
 * this to a `500 {"message": ...}`, the CLI to a failure exit — never a
 * raw unique-violation with driver detail.
 */
final class IntegrationEventContention extends RuntimeException
{
    public static function afterAttempts(int $attempts): self
    {
        return new self(sprintf(
            'The server could not decide this integration event after %d attempts against concurrent '
            .'deliveries. Nothing was applied; it is safe to retry.',
            $attempts,
        ));
    }
}
