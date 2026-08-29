<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Audit;

use ArtisanBuild\BuiltForCloud\CredentialAuditEventBuilder;
use Illuminate\Database\Eloquent\Builder;
use LogicException;

/**
 * The app-action stream's Eloquent builder: refuses `truncate()` on both
 * the static path ({@see AppActionEvent}`::truncate()` resolves through
 * here) and the query path (`AppActionEvent::query()->truncate()`).
 *
 * TRUNCATE is DDL on mysql, where the row-level triggers never fire — so
 * the model layer must catch it before it reaches the driver. This is the
 * shape the credential stream already ships
 * ({@see CredentialAuditEventBuilder}) and it
 * is copied deliberately rather than generalised: two audit streams with
 * one shared base class would make a change to either one a change to
 * both, and these two are meant to be able to diverge.
 *   Pinned by `tests/AppActionAuditTest.php` — "rejects truncate on both
 *   the static and the query-builder paths".
 *
 * @extends Builder<AppActionEvent>
 */
final class AppActionEventBuilder extends Builder
{
    public function truncate(): void
    {
        throw new LogicException('The app-action audit stream is append-only: the table is never truncated.');
    }
}
