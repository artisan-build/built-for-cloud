<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Audit;

use ArtisanBuild\BuiltForCloud\MetadataShape;
use ArtisanBuild\BuiltForCloud\Vitals\HeadlineLabel;
use BackedEnum;

/**
 * The marker a consuming app's ACTION vocabulary implements (Console PRD
 * D17, D15's content boundary).
 *
 * It extends {@see BackedEnum} on purpose, and that is the whole
 * mechanism: **only an enum can implement this**, and an enum's case set
 * is fixed at compile time, in the app's repo, reviewable in one diff.
 * This is the same reasoning — and deliberately the same shape — as
 * {@see HeadlineLabel}, landed in PR6 for the vitals headline: a
 * `list<string>` of permitted action names would be by CONVENTION, and
 * an app could implement it as `Tag::pluck('slug')->all()`, at which
 * point any user-authored slug that happened to look identifier-shaped
 * would be a legal member of its own vocabulary and would reach the
 * audit stream — and, when a read transport eventually exists, the
 * vendor. A case set cannot be produced from runtime data, so the TYPE
 * is the enforcement.
 *
 * THE PACKAGE SHIPS NO APP VOCABULARY. {@see ConsoleAction} is the
 * package's OWN actions — the things this package itself does, of which
 * there is exactly one today — and it is not a starter set for an app to
 * extend or reuse. D17 puts the app's vocabulary in the app's repo at
 * conversion time, and inventing a fleet-wide one here would make every
 * app's audit vocabulary a package concern.
 *
 * THE RESIDUAL LATITUDE, stated because an unstated one reads as
 * covered: an enum type stops runtime data; it does not stop an app
 * writing prose INTO a case. {@see AppActionRecorder} answers that by
 * refusing any case whose backing value is not a bounded identifier
 * ({@see MetadataShape::TOKEN}), and it
 * refuses the whole emission rather than storing a trimmed version of
 * it. What remains — whether the vocabulary is a GOOD one, whether its
 * case NAMES read as prose — is the app's code review, and nothing in a
 * package can decide it.
 *   Pinned by `tests/AppActionAuditTest.php` — "refuses an action whose
 *   case is backed by prose rather than a bounded identifier", "refuses
 *   an action backed by an integer rather than an identifier" and
 *   "cannot be handed a free-text action at all, because the parameter
 *   is typed".
 */
interface AppAction extends BackedEnum {}
