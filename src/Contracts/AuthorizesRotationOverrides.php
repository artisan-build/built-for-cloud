<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Contracts;

use ArtisanBuild\BuiltForCloud\RotationOverride;
use ArtisanBuild\BuiltForCloud\Subject;
use Illuminate\Http\Request;

/**
 * Opt-in extension of {@see CredentialDeclaration} — the SEPARATE
 * authorization a rotation override requires (PRD 1.7, D6 point 4: "any
 * privilege or lifetime override is a separately authorized operation").
 *
 * Unlike the package's other parallel contracts, whose absence means "the
 * gate's answer stands", this one FAILS CLOSED: a declaration that does
 * not implement it DENIES every override. The asymmetry is deliberate —
 * every other opt-in can only narrow what the admin gate already allows,
 * but an override WIDENS a rotation into a privilege change, and privilege
 * changes are never a default. Routine rotation (exact preservation) is
 * unaffected and stays authorized by the verb matrix's `rotate` answer.
 *
 * An authorized override must ALSO pass the same ceilings the mint verb
 * enforces ({@see ConstrainsMintedCredentials}): an override can never
 * produce a credential a mint of that shape could not have been
 * authorized for. This hook cannot widen past those ceilings — it is the
 * override's gate, not an exemption.
 *
 * `$subject` is the TARGET row's declared subject, exactly as the verb
 * matrix receives it (SEC-V3-07: nothing the caller supplies substitutes
 * for what the row declares); `$override` carries the requested delta.
 */
interface AuthorizesRotationOverrides
{
    public function authorizeRotationOverride(?Subject $subject, RotationOverride $override, Request $request): bool;
}
