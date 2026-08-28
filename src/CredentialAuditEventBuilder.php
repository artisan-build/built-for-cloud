<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use Illuminate\Database\Eloquent\Builder;
use LogicException;

/**
 * The audit stream's Eloquent builder: refuses `truncate()` on both the
 * static path (`CredentialAuditEvent::truncate()` resolves through here)
 * and the query path (`CredentialAuditEvent::query()->truncate()`).
 * TRUNCATE is DDL on mysql, where the row-level triggers never fire — so
 * the model layer must catch it before it reaches the driver.
 *
 * @extends Builder<CredentialAuditEvent>
 */
final class CredentialAuditEventBuilder extends Builder
{
    public function truncate(): void
    {
        throw new LogicException('The credential audit stream is append-only: the table is never truncated.');
    }
}
