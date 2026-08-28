<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Contracts;

use ArtisanBuild\BuiltForCloud\CredentialVerb;
use ArtisanBuild\BuiltForCloud\Subject;
use Illuminate\Http\Request;

/**
 * Opt-in extension of {@see CredentialDeclaration} — the executable per-verb
 * authority matrix (PRD 1.4, D2, SEC-V3-07).
 *
 * Why a separate opt-in interface rather than a new parameter on
 * `CredentialDeclaration::authorize()`: adding a parameter (or a method) to
 * that interface would break every existing implementor, and PHP interfaces
 * cannot carry a default implementation. The package's established
 * extension idiom ({@see DeclaresBurnMode}, {@see DeclaresHolderResolution})
 * is a parallel opt-in contract the framework `instanceof`-checks — existing
 * declarations keep compiling and keep their exact behaviour.
 *
 * A declaration that does not implement this interface allows every verb:
 * the credential-API surfaces are already operator-scope actions behind the
 * admin-token gate (and the guard + abilities middleware on guard routes),
 * so "no matrix declared" means "the gate's answer stands". Implementing it
 * can only NARROW that — a `false` here produces 403 even for an
 * otherwise-valid admin token. It can never widen past the guard or the
 * credential's abilities, because those are checked first.
 *
 * `$subject` is the TARGET row's declared subject — null when the row
 * predates subjects (declare-don't-guess) or when the verb has no single
 * target row (`issue` against the legacy store). It is an INPUT to the
 * decision, never the check itself: no permission is ever inferred from
 * `subject_type`, from `subject_ref`, or from possession of a credential
 * name, and a client-supplied subject in any request input must never reach
 * this hook as the target — the framework passes only what the ROW declares.
 */
interface AuthorizesCredentialVerbs
{
    public function authorizeVerb(CredentialVerb $verb, ?Subject $subject, Request $request): bool;
}
