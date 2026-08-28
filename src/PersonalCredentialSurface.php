<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Actions\ListCredentials;
use ArtisanBuild\BuiltForCloud\Actions\MintCredential;
use ArtisanBuild\BuiltForCloud\Actions\RevokeCredential;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresUnsupportedSummaryFields;
use ArtisanBuild\BuiltForCloud\Exceptions\CredentialVerbRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use ArtisanBuild\BuiltForCloud\Exceptions\RewrapInProgress;
use ArtisanBuild\BuiltForCloud\Exceptions\SelfServiceUnavailable;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageCredentials;
use ArtisanBuild\BuiltForCloud\Http\Controllers\PersonalCredentials;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAuthenticated;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

/**
 * The personal-credentials surface (PRD 1.17): "an authenticated human
 * manages their OWN machine credentials" — list mine, mint (revealed
 * once), revoke mine.
 *
 * UI-AGNOSTIC on purpose. The package ships this object and
 * {@see PersonalCredentials} (its HTTP transport); crate's Phase-2.3
 * Livewire screen and capstan's `/settings/tokens` render whatever their
 * own stack renders and call THESE methods — one surface, two front ends,
 * no second store and no second set of verbs. Beneath it are the very
 * same PR6 actions the operator surface runs.
 *
 * The ONE thing that makes it a self-service surface rather than a second
 * operator surface is where the subject comes from (SEC-V3-07): the app's
 * declaration derives it SERVER-SIDE from the authenticated request
 * ({@see CredentialDeclaration::resolveSubject()}). Where
 * {@see ManageCredentials} takes an admin's `subject_type`/`subject_ref`
 * as input, nothing a caller sends reaches this class's scoping — a
 * crafted `subject_ref` or `user_id` in a request body is not merely
 * rejected, it is never read.
 *
 * Consequently:
 *
 * - {@see mine()} lists ONLY rows carrying the derived subject;
 * - {@see mintMine()} mints for the derived subject, bound to the session
 *   user;
 * - {@see revokeMine()} revokes only inside the derived subject, and a row
 *   outside it is reported as NOT FOUND — indistinguishable from a row
 *   that never existed, because "that id belongs to someone else" is
 *   itself a disclosure.
 *
 * What stays PER APP is the MEANING, and it lives in the declaration, not
 * in a branch here (PRD 1.17, D2): a capstan user-bound credential
 * inherits its user's authority — the declaration's `authorize()` hook is
 * what says so — and dies with the user (PRD 1.15: offboarding revokes
 * every credential under the subject AND every credential bound to the
 * user); a crate key carries its own authority, because crate's
 * `authorize()` reads the credential's own abilities and never the
 * holder's role. The screen is identical; the declaration is the
 * difference.
 */
final readonly class PersonalCredentialSurface
{
    public function __construct(
        private ListCredentials $list,
        private MintCredential $mint,
        private RevokeCredential $revoke,
    ) {}

    /**
     * The subject this request acts for, or null when the app declares
     * none. Server-derived, always — a UI may call this to decide whether
     * to render the screen at all.
     */
    public function subject(Request $request): ?Subject
    {
        return $this->declaration()->resolveSubject($request);
    }

    /**
     * The caller's OWN credentials. Row-level verb-matrix filtering and
     * declared-unsupported nulling ride along from the shared list verb.
     *
     * @return list<CredentialSummary>
     *
     * @throws SelfServiceUnavailable
     */
    public function mine(Request $request): array
    {
        return ($this->list)($this->requireSubject($request));
    }

    /**
     * Mint for the caller. The subject is the derived one and the
     * `user_id` binding is the SESSION user's identifier — both stamped
     * here, so a `subject_type`, `subject_ref` or `user_id` a caller
     * supplied cannot reach the row whatever a front end passed in.
     *
     * @throws SelfServiceUnavailable
     * @throws CredentialVerbRefused
     * @throws InvalidCredentialInput
     * @throws RewrapInProgress
     */
    public function mintMine(Request $request, MintOptions $options): MintResult
    {
        $subject = $this->requireSubject($request);

        return ($this->mint)($subject, $this->selfBound($options), $this->actor());
    }

    /**
     * Revoke one of the caller's OWN credentials. The derived subject is
     * handed to the revoke verb as its scope, so the ownership check runs
     * inside the verb's own locked transaction rather than in a
     * check-then-act window here.
     *
     * @throws SelfServiceUnavailable
     * @throws CredentialVerbRefused
     */
    public function revokeMine(Request $request, string $id): RevokeOutcome
    {
        $subject = $this->requireSubject($request);

        return ($this->revoke)($id, $this->actor(), $subject);
    }

    /**
     * The summary fields this app's declaration expresses — what a front
     * end draws. A thinner declaration renders less (PRD 1.17): the
     * unsupported ones are not "null columns to hide", they are fields
     * this store structurally cannot answer, and
     * {@see CredentialSummary::$unsupported} carries the same
     * discrimination onto every row (PRD 1.6, declared unsupported, not
     * null).
     *
     * @return list<string>
     */
    public function renderableFields(): array
    {
        $unsupported = $this->unsupportedFields();

        return array_values(array_filter(
            CredentialSummary::DECLARABLE_FIELDS,
            static fn (string $field): bool => ! in_array($field, $unsupported, true),
        ));
    }

    /**
     * @return list<string>
     */
    public function unsupportedFields(): array
    {
        $declaration = $this->declaration();

        if (! $declaration instanceof DeclaresUnsupportedSummaryFields) {
            return [];
        }

        return array_values(array_intersect(
            $declaration->unsupportedSummaryFields(),
            CredentialSummary::DECLARABLE_FIELDS,
        ));
    }

    /**
     * @throws SelfServiceUnavailable
     */
    private function requireSubject(Request $request): Subject
    {
        return $this->subject($request) ?? throw SelfServiceUnavailable::noResolvableSubject();
    }

    /**
     * The user binding, stamped server-side. Rebuilt rather than mutated
     * because {@see MintOptions} is readonly and because rebuilding is
     * what makes the guarantee structural: whatever `userId` a caller put
     * in, the value that reaches the store is this one.
     */
    private function selfBound(MintOptions $options): MintOptions
    {
        return new MintOptions(
            kind: $options->kind,
            name: $options->name,
            abilities: $options->abilities,
            expiresAt: $options->expiresAt,
            userId: $this->sessionUserId(),
            codeTtlSeconds: $options->codeTtlSeconds,
        );
    }

    /**
     * D8's `bound_user` actor: the authenticated human's id, never their
     * name or email. Null when no session user is resolvable — an actor is
     * absent rather than guessed.
     */
    private function actor(): ?AuditActor
    {
        $userId = $this->sessionUserId();

        return $userId === null ? null : AuditActor::boundUser($userId);
    }

    private function sessionUserId(): ?string
    {
        $user = $this->sessionUser();

        if ($user === null) {
            return null;
        }

        $id = $user->getAuthIdentifier();

        return is_scalar($id) && (string) $id !== '' ? (string) $id : null;
    }

    /**
     * The authenticated human, resolved through the SAME facade the
     * package's session gate uses
     * ({@see EnsureUserIsAuthenticated}),
     * so the gate that admitted the request and the surface that acts on
     * it can never disagree about who is calling.
     */
    private function sessionUser(): ?Authenticatable
    {
        return Auth::user();
    }

    private function declaration(): CredentialDeclaration
    {
        return app(CredentialDeclaration::class);
    }
}
