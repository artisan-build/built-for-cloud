<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Vitals;

use ArtisanBuild\BuiltForCloud\Contracts\DeclaresHeadlineStat;
use BackedEnum;

/**
 * The marker a consuming app's headline-label vocabulary implements
 * (Console PRD D15).
 *
 * It extends {@see BackedEnum} on purpose, and that is the whole
 * mechanism: **only an enum can implement this**, and an enum's case set
 * is fixed at compile time, in the app's repo, reviewable in one diff.
 *
 * The previous revision typed the vocabulary as `list<string>` and
 * checked membership at runtime. That is by CONVENTION, not by
 * construction, and it fails exactly where it matters: an app could
 * implement the hook as `Tag::pluck('slug')->all()`, and any
 * user-authored slug that happened to look identifier-shaped —
 * `customer-incident` — would be a legal member of its own vocabulary
 * and would reach the vendor. D15 says the vocabulary is "defined in the
 * app's repo at conversion time, **never runtime data**". A list cannot
 * express that. A case set can, so the type is now the enforcement.
 *
 * The residual latitude, stated because an unstated one reads as
 * covered: an app can still declare a HUGE enum, or write case names
 * that read as prose. {@see CollectVitals} answers the first with a hard
 * cap ({@see DeclaresHeadlineStat::MAX_LABELS}) and the second by
 * requiring every case's backing value to be a bounded identifier. What
 * remains — whether the vocabulary is a GOOD one — is the app's code
 * review, and nothing in a package can decide it.
 *
 * WHICH enum applies is settled separately, and structurally:
 * {@see DeclaresHeadlineStat::HEADLINE_VOCABULARY} is a class constant,
 * so it is a constant expression rather than something a method could
 * select from a request or a row.
 */
interface HeadlineLabel extends BackedEnum {}
