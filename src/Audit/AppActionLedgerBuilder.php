<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Audit;

/**
 * {@see AppendOnlyBuilder} bound to {@see AppActionOutboxEntry}. It adds
 * nothing and overrides nothing — see {@see AppActionEventBuilder}.
 *
 * @extends AppendOnlyBuilder<AppActionOutboxEntry>
 */
final class AppActionLedgerBuilder extends AppendOnlyBuilder {}
