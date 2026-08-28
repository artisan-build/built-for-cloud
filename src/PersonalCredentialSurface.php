<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Actions\ListCredentials;
use ArtisanBuild\BuiltForCloud\Actions\MintCredential;
use ArtisanBuild\BuiltForCloud\Actions\RevokeCredential;
use ArtisanBuild\BuiltForCloud\Contracts\ConstrainsMintedCredentials;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresSelfServiceMintPolicy;
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
    /**
     * The kinds a self-service mint may produce when the app declares no
     * policy: `bearer` alone. `hmac` and `asymmetric` deliver signing key
     * material and enrollment codes, and `basic` is an operator-shaped
     * delivery — none of them is something a logged-in human should be
     * able to reach by naming it.
     *
     * @var list<CredentialKind>
     */
    private const array DEFAULT_SELF_SERVICE_KINDS = [CredentialKind::Bearer];

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
     * Mint for the caller — FAIL-CLOSED on authority (rework Fix 2).
     *
     * Four of the six mint options are decided here, not by the caller:
     * the subject and the `user_id` binding come from the session, and
     * the ABILITIES and the KIND come from the app's self-service policy
     * ({@see DeclaresSelfServiceMintPolicy}). Only the free-text `name`,
     * the caller-chosen `expires_at` and the enrollment `code_ttl_seconds`
     * are the caller's, because none of them is an authority.
     *
     * The distinction that makes this safe: the OPERATOR mint derives
     * authority from an admin who chose it; the self-service mint derives
     * it from a declaration. A logged-in human asking for `mcp:admin` is
     * making a request, not an authorization, and this surface never reads
     * it — so a low-privilege user cannot mint themselves a powerful
     * credential, whatever they send and whatever a front end passes.
     *
     * @throws SelfServiceUnavailable
     * @throws CredentialVerbRefused
     * @throws InvalidCredentialInput
     * @throws RewrapInProgress
     */
    public function mintMine(Request $request, MintOptions $options): MintResult
    {
        $subject = $this->requireSubject($request);

        return ($this->mint)($subject, $this->selfServiceOptions($options, $subject), $this->actor());
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
     * The self-service mint's options, REBUILT rather than filtered —
     * rebuilding is what makes the guarantee structural rather than a
     * validation rule someone can find a hole in. Whatever `userId` or
     * `abilities` a caller put in, the values that reach the store are
     * the ones assembled here.
     *
     * - `abilities`: the policy's whole grant, never an intersection with
     *   what was asked for. No policy means NO abilities — the credential
     *   authenticates as its holder and holds no operator, MCP or signing
     *   power.
     * - `kind`: refused unless the policy offers it; `bearer` only by
     *   default, so `hmac` and `asymmetric` (which deliver signing key
     *   material and enrollment codes) cannot be reached by naming them.
     * - `expiresAt`: the CALLER's, still optional and still never
     *   defaulted (PRD 1.3 / D1b). Lifetime is not the escalation vector;
     *   an app that wants a ceiling declares one through
     *   {@see ConstrainsMintedCredentials},
     *   which the mint verb applies to both mint paths alike.
     *
     * @throws CredentialVerbRefused
     */
    private function selfServiceOptions(MintOptions $options, Subject $subject): MintOptions
    {
        $policy = $this->declaration();
        $policy = $policy instanceof DeclaresSelfServiceMintPolicy ? $policy : null;

        $kinds = $policy?->selfServiceKinds($subject) ?? self::DEFAULT_SELF_SERVICE_KINDS;

        if (! in_array($options->kind, $kinds, true)) {
            throw CredentialVerbRefused::selfServiceKind($options->kind);
        }

        $abilities = array_values(array_filter(
            $policy?->selfServiceAbilities($subject) ?? [],
            static fn (string $ability): bool => trim($ability) !== '',
        ));

        return new MintOptions(
            kind: $options->kind,
            name: $options->name,
            // The one canonical empty, matching MintOptions::fromInput():
            // null and [] both grant nothing, and summaries serialize null.
            abilities: $abilities === [] ? null : $abilities,
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
