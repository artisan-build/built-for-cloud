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
 * vendor. A case set cannot be produced from runtime data.
 *
 * **WHERE THAT TYPE IS THE ENFORCEMENT, EXACTLY.** It is enforcement on
 * the recorder's signature: {@see AppActionRecorder::record()} takes an
 * `AppAction`, so a caller on that path had an enum case in hand and a
 * string will not compile through it. It is NOT enforcement on the
 * TABLE — {@see AppActionEvent} is an ordinary Eloquent model, an app
 * can write a row directly, and what a row stores is a `string` column
 * naming a vocabulary rather than an enum instance. That path is
 * covered instead by the row validating itself on `creating`: the
 * vocabulary it names must be a real enum implementing this interface,
 * and the action must be one of that enum's cases. Two different
 * mechanisms for two different paths, and an earlier revision of this
 * paragraph claimed the first covered both.
 *   Pinned by `tests/AppActionAuditTest.php` — "refuses a direct model
 *   write that carries runtime prose as its action" and "refuses a
 *   direct model write whose action is not a case of the vocabulary it
 *   names".
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
 * writing prose INTO a case. {@see AppActionEvent} answers that on
 * every path through the model, by refusing any action whose stored
 * value is not a bounded identifier
 * ({@see MetadataShape::TOKEN}) — and refusing the whole write rather
 * than storing a trimmed version of it. What remains — whether the vocabulary is a GOOD one, whether its
 * case NAMES read as prose — is the app's code review, and nothing in a
 * package can decide it.
 *   Pinned by `tests/AppActionAuditTest.php` — "refuses an action whose
 *   case is backed by prose rather than a bounded identifier", "refuses
 *   an action backed by an integer rather than an identifier" and
 *   "cannot be handed a free-text action at all, because the parameter
 *   is typed".
 */
interface AppAction extends BackedEnum {}
