<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Audit;

/**
 * {@see AppendOnlyBuilder} bound to {@see AppActionEvent}. It adds
 * nothing and overrides nothing — every refusal, and the enumeration
 * they rest on, lives on the base so the event table and its dedup
 * ledger cannot drift apart on which operations they refuse.
 *
 * @extends AppendOnlyBuilder<AppActionEvent>
 */
final class AppActionEventBuilder extends AppendOnlyBuilder {}
