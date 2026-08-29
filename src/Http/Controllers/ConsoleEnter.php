<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\Console\Assertion;
use ArtisanBuild\BuiltForCloud\Console\AssertionBurn;
use ArtisanBuild\BuiltForCloud\Console\AssertionRefusalReason;
use ArtisanBuild\BuiltForCloud\Console\AssertionVerifier;
use ArtisanBuild\BuiltForCloud\Console\ConsoleEntryRefusalReason;
use ArtisanBuild\BuiltForCloud\Console\ConsoleEntryState;
use ArtisanBuild\BuiltForCloud\Console\ConsoleGuard;
use ArtisanBuild\BuiltForCloud\Console\ConsoleGuardConfiguration;
use ArtisanBuild\BuiltForCloud\Console\DelegatedActor;
use ArtisanBuild\BuiltForCloud\Exceptions\AssertionRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\ConsoleEntryRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\DelegatedActorDeactivated;
use ArtisanBuild\BuiltForCloud\Http\Middleware\UniformConsoleKeyRefusal;
use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\Tests\AssertionParameterScan;
use Carbon\CarbonImmutable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use RuntimeException;
use SensitiveParameter;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * `POST /bfc/console/enter` — the door (Console PRD D12/D13). The vendor
 * auto-submits a form carrying a signed assertion and its signed state;
 * this deployment verifies, spends the mint, opens a delegated session,
 * and lands the operator on the path the state named.
 *
 * **POST, AND NEVER GET.** A GET assertion is a live credential in the
 * customer's own server and CDN logs, in browser history, and in the
 * `Referer` of the very next request the entered page makes. It is not
 * mounted on GET at all — not redirected, not refused: an unrouted verb
 * cannot be reached by a misconfigured link, and 405 is the answer.
 *   Pinned by `tests/ConsoleEnterTest.php` — "does not route GET at the
 *   enter path, so an assertion can never ride a query string".
 *
 * **THE BYTES ARE MARKED, AND THEN THEY ARE REMOVED.** Every frame in
 * this package that can hold the presented token — a parameter named
 * for one, and the `Request` that carries the submitted form — is
 * marked `#[SensitiveParameter]`, enumerated rather than remembered.
 * And the credential is taken OUT of the request object in the THIRD
 * STATEMENT of {@see __invoke()}, preceded only by the two reads that
 * make it possible and by nothing this endpoint throws from, because a
 * rich error reporter serializes request INPUT regardless of which
 * frames hold what. {@see forgetPresentedAssertion()} states that
 * ordering precisely and says what it reaches and what it does not.
 *
 * THE CLAIM IS NARROWER THAN "NO FRAME LEAKS THE CREDENTIAL", and it
 * has to be: the `Request` object travels through the whole framework
 * pipeline — routing, the middleware stack, the controller dispatcher —
 * and every one of those frames holds it. They are vendor frames and
 * this package cannot annotate them, which is equally true of every
 * bearer token a Laravel application receives. What IS enforced: no
 * frame THIS PACKAGE declares carries the credential unmarked, and the
 * object those vendor frames hold no longer carries it either.
 *
 * AND THE SCAN HAS A SHAPE IT CANNOT REACH, stated rather than chased:
 * it walks FILENAME-DERIVED classes, enums and interfaces under `src/`,
 * so a package FUNCTION, an ANONYMOUS CLASS or a standalone TRAIT could
 * introduce an assertion-bearing frame without ever being inspected.
 * PHP has more ways to make a frame than a file-and-class walk can
 * reach; that one is caught by reviewing a diff, not by this suite, and
 * a mutation-debt row names it.
 *   Pinned by `tests/AssertionSecrecyTest.php` — "marks every frame in
 *   this package that holds console assertion bytes", "names an
 *   unmarked assertion frame when the walk meets one", "names the
 *   shapes it cannot reach, so the claim beside it stays true" and
 *   "takes the presented assertion out of the request before any
 *   validation runs".
 *
 * **THE MINTING PATH IS {@see ConsoleGuard::redeem()}, AND ONLY THAT.**
 * This controller writes no session state of its own. It hands the
 * SIGNED BYTES over and lets the guard verify them again inside the
 * call that opens the session — which is why there is no ordering here
 * to get wrong, and why the package-wide writer scan still names exactly
 * one file.
 *
 * **The assertion is therefore verified twice, deliberately.** The
 * endpoint has to read three things before it can act — the mint id it
 * burns, the state digest it binds, and the return path it lands on —
 * and {@see ConsoleGuard::redeem()} will not accept an already-built
 * {@see Assertion}, because a method that did would accept a forged
 * one. The cost is one extra
 * Ed25519 verification on a page-load path; the alternative is the
 * escape PR3 deleted.
 *
 * THE ORDER, and each step is a security property that fails quietly if
 * it moves:
 *
 *  1. **Verify**, first, before anything is read or written. Every
 *     clock, claim, issuer, audience and signature rule is
 *     {@see AssertionVerifier}'s.
 *  2. **Bind the signed state** ({@see ConsoleEntryState}) and resolve
 *     the return path — before the mint is spent, so a mis-stated
 *     handoff does not consume an assertion that was otherwise good.
 *  3. **Record the handoff**, outside the transaction, so PR3's
 *     promise that a refusal cannot roll the record back survives
 *     being nested inside one.
 *  4. **Burn the mint id, then redeem, in ONE transaction.** The burn
 *     is an INSERT against a unique index, so a second presentation is
 *     refused BECAUSE the `jti` is spent rather than because something
 *     later noticed, and the two commit together: a redemption that
 *     fails does not spend the mint, and a burn that loses the race
 *     takes the redemption with it. {@see AssertionBurn} states what the
 *     suite does and does not prove about the race itself.
 *  5. **Redirect**, `303`, to the relative path — as a bare relative
 *     `Location`, never resolved against the request's Host, so a
 *     spoofed Host header cannot turn a validated in-app path into an
 *     absolute URL somewhere else.
 *   Pinned by `tests/ConsoleEnterTest.php` — "mints a delegated session
 *   from a valid handoff and lands on the requested relative path",
 *   "refuses a genuine second presentation of the same assertion,
 *   because the mint id is spent", "rolls the burn back with the
 *   redemption, so the two commit or fail together" and
 *   "leaves a contained actor's mint unspent, so every attempt audits as containment".
 *
 * **EVERY REFUSAL IS THE SAME ANSWER — BYTE FOR BYTE. THE TIMING IS
 * NOT.** Thirteen assertion reasons and eight entry reasons collapse
 * into one status and one body, so a party feeding tokens at this door
 * cannot READ which one it hit. The reason goes to the AUDIT record,
 * with the actor typed, and to nothing else.
 *
 * The bound is on what the ANSWER carries, and only that. Two timing
 * channels survive and neither is closed:
 *
 *  - a refusal decided BEFORE the Ed25519 verification (an unknown,
 *    pending or retired `kid`) returns measurably sooner than one
 *    decided after it — {@see AssertionRefused} states this;
 *  - a REPLAY is measurably SLOWER than a bad signature, a wrong
 *    audience or an expired token, because it is the only refusal that
 *    reaches the state binding, the shadow-actor upsert and a contended
 *    unique insert before it fails. A holder of a stolen assertion can
 *    therefore infer whether somebody has already redeemed it.
 *
 * Neither is padded, deliberately: constant-time padding on a page-load
 * path costs real latency to hide facts a prober largely supplies
 * itself, and the properties that make a stolen token worthless are the
 * per-deployment audience and the burn, not the shape of the clock. A
 * rate-limit `429` also still says `429`, because a limiter that lied
 * about being one would be unusable.
 *   Pinned by `tests/ConsoleEnterTest.php` — "answers a replayed, a
 *   wrong-deployment and an expired assertion with byte-identical
 *   responses".
 *
 * **NO CSRF TOKEN, AND THAT IS NOT AN OVERSIGHT.** The handoff is a
 * cross-site POST from the issuer's page; a `SameSite=Lax` session
 * cookie — Laravel's default — is not sent with one, so the app has no
 * session with that browser yet and there is no token it could have
 * planted. What stands in for it is D13's signed state: the return path
 * rides inside the vendor's signature rather than in a request field.
 * {@see ConsoleEntryState} states precisely what that closes (open
 * redirect, and moving a state between mints) and what it does not (an
 * attacker auto-submitting a mint of their OWN identity into a victim's
 * browser).
 *
 * **A REFUSAL IS NOT SERVED UNLESS IT WAS RECORDED.** The audit write
 * fails CLOSED: if it cannot commit, the request errors rather than
 * answering with the ordinary `403`. D13 says failures are audited, and
 * a promise that lapses during an audit-store outage — exactly when
 * someone is probing — is worth less than none. {@see audit()} states
 * the availability trade that buys.
 *   Pinned by `tests/ConsoleEnterTest.php` — "does not serve a refusal
 *   it could not record" and "records every refusal it serves, one row
 *   per refused entry".
 *
 * **WHAT THIS ENDPOINT DOES NOT AUDIT.** A SUCCESSFUL entry writes no
 * event to this stream. The credential lifecycle stream is
 * credential-scoped, and PRD D17 gives actor-typed app-action events
 * their own new stream, which is a later deliverable. What a successful
 * entry does leave is the shadow-actor row's refreshed
 * `last_handoff_*` copy and its `updated_at`
 * ({@see DelegatedActor::recordHandoff()}).
 * D13's requirement — that verification FAILURES are audited — is met
 * in full; the success side is named here rather than left to be
 * discovered.
 *
 * **THE DOOR IS MOUNTED OR ABSENT**, never present-and-refusing, and it
 * is rate-limited before anything else on the route runs.
 *   Pinned by `tests/ConsoleEnterSurfaceTest.php` — "the door is
 *   mounted by default in a console enabled app" and "routes off
 *   unmounts the door like every other package route";
 *   `tests/ConsoleDisabledTest.php` — "it mounts no enter door and
 *   advertises none"; `tests/ConsoleEnterForeignGuardTest.php` — "an
 *   app that owns the guard owns entry too"; and
 *   `tests/ConsoleEnterTest.php` — "rate-limits the door".
 */
final class ConsoleEnter
{
    /** The request field carrying the PASETO v4.public assertion. */
    public const string ASSERTION_FIELD = 'assertion';

    /**
     * The one status every refusal answers with. `403` rather than
     * `401`: what happened is "this entry is not permitted", and a
     * `401` invites a client to retry with a credential it has already
     * shown is not the right one — the same reading
     * {@see UniformConsoleKeyRefusal} made for the re-key surface.
     */
    public const int REFUSAL_STATUS = 403;

    /** The one machine-readable error the body carries. It names no reason. */
    public const string REFUSAL_ERROR = 'console_entry_refused';

    /** The refusal envelope's version, so a client may branch on shape. */
    public const int PAYLOAD_VERSION = 1;

    /**
     * The audit note every refusal writes, with the bounded reason
     * appended. The reason is always an {@see AssertionRefusalReason}
     * or a {@see ConsoleEntryRefusalReason} value — the two vocabularies
     * are disjoint — so the note carries no free text and nothing an
     * attacker influenced.
     */
    public const string AUDIT_NOTE = 'console entry refused (POST /bfc/console/enter): ';

    public function __construct(
        private readonly AssertionVerifier $verifier,
        private readonly LifecycleEventRecorder $recorder,
    ) {}

    public function __invoke(#[SensitiveParameter] Request $request): Response
    {
        // THE FIRST THREE STATEMENTS, in this order, and the order is
        // the point. Read the two fields; take the credential out of
        // the request. Nothing else precedes the removal — not the
        // clock, not the missing-field check, not one line of
        // validation — so every throwing path in this endpoint unwinds
        // with the request already scrubbed.
        // See forgetPresentedAssertion(), which states that ordering
        // precisely and what it does and does not reach.
        $presentedToken = $request->input(self::ASSERTION_FIELD);
        $state = $request->input(ConsoleEntryState::FIELD);

        $this->forgetPresentedAssertion($request);

        $now = CarbonImmutable::now();
        $mintId = null;

        try {
            $token = $this->assertionToken($presentedToken);

            $assertion = $this->verifier->verify($token);
            $mintId = $assertion->id;

            $entry = ConsoleEntryState::bind($assertion, $state);

            // PR3 records the handoff on its OWN commit, before the
            // decision, precisely so a refusal cannot roll the record
            // back — an operator has to be able to see that a contained
            // human attempted entry and with what claims. Nesting
            // redeem()'s transaction inside the burn's would undo that,
            // so the record is taken HERE, outside the transaction,
            // first. The upsert redeem() then performs is idempotent
            // and writes the identical row; this is storage, it
            // authenticates nothing, and no session can be created
            // from it.
            DelegatedActor::recordHandoff($assertion);

            $this->spendAndRedeem($assertion, $token, $now);

            // Housekeeping, after the commit and never able to fail the
            // entry: see AssertionBurn::prune().
            $this->prune($now);

            // A BARE RELATIVE Location. `redirect()` would resolve the
            // path against the request's root URL, which is derived
            // from the Host header — so a spoofed Host would turn a
            // validated in-app path into an absolute URL on someone
            // else's origin. A relative Location is same-origin by
            // construction, whatever the header said.
            return new RedirectResponse($entry->returnTo, 303);
        } catch (AssertionRefused $refused) {
            // The verifier decided. The mint id is deliberately NOT
            // reported: the server does not trust claims it refused to
            // verify, and it does not guess an actor.
            return $this->refuse($refused->reason->value, null);
        } catch (ConsoleEntryRefused $refused) {
            return $this->refuse($refused->reason->value, $refused->assertionId);
        } catch (DelegatedActorDeactivated) {
            return $this->refuse(ConsoleEntryRefusalReason::ActorDeactivated->value, $mintId);
        }
    }

    /**
     * Spend the mint and open the session, together or not at all.
     *
     * WHY THE COMPENSATION EXISTS, and why it is shaped by which
     * exception arrived rather than by a flag.
     * {@see ConsoleGuard::redeem()} already compensates everything that
     * can go wrong from its own first session write onwards — but it
     * compensates INSIDE this transaction now, so the one storage
     * effect that matters (destroying the prior session record, which
     * on the `database` session driver is a write) is undone again when
     * this transaction rolls back. And redeem() cannot see this
     * transaction at all: if the COMMIT fails, the database rolls back
     * — the burn row with it — while the session it wrote does not, and
     * Laravel's pipeline still renders the failure into a response, so
     * `StartSession` would hand the browser a cookie naming a live
     * delegated session for a mint this deployment never spent.
     *
     * So an unexpected failure fails CLOSED on the session:
     * {@see ConsoleGuard::logout()} forgets the principal and
     * invalidates the session, in memory and in the store, after the
     * rollback.
     *
     * THE THREE DECIDED REFUSALS ARE EXCLUDED, and that exclusion is
     * the security-relevant half. Each of them is thrown before any
     * session write — the verifier's before anything at all, the burn's
     * before the guard is called, and the containment refusal before
     * `redeem()` begins its own writes — so there is nothing to
     * compensate. They are also the ONLY outcomes a caller can produce
     * at will, and `logout()` invalidates the WHOLE session, a
     * co-resident local one included: compensating them would hand any
     * passer-by a way to log a legitimate local user out by posting a
     * bad token.
     *
     * The remaining catch is deliberately broad and therefore
     * over-approximates: a database failure during the burn also
     * invalidates a co-resident session, though nothing had been
     * written. That direction is chosen on purpose — it is fail-closed,
     * and it is not reachable on demand.
     *
     * @throws AssertionRefused|ConsoleEntryRefused|DelegatedActorDeactivated
     */
    private function spendAndRedeem(Assertion $assertion, #[SensitiveParameter] string $token, CarbonImmutable $now): void
    {
        try {
            DB::transaction(function () use ($assertion, $token, $now): void {
                AssertionBurn::burn($assertion, $now);

                $this->guard()->redeem($token);
            });
        } catch (AssertionRefused|ConsoleEntryRefused|DelegatedActorDeactivated $refused) {
            throw $refused;
        } catch (Throwable $failure) {
            $this->guard()->logout();

            throw $failure;
        }
    }

    /**
     * The presented assertion, as a non-empty string.
     *
     * It takes the VALUE rather than the request, because by the time
     * it runs the request no longer carries one: {@see __invoke()}
     * reads both fields and scrubs the credential before any validation
     * happens, so even the missing-field refusal below unwinds with the
     * request already clean.
     *
     * `mixed`, because that is what `Request::input()` returns and
     * pretending otherwise would move the type check somewhere it does
     * not belong. The parameter is still named for what it holds, which
     * is what {@see AssertionParameterScan}
     * requires of an untyped or `mixed` frame.
     *
     * The LENGTH bound is the verifier's own
     * ({@see AssertionVerifier::MAX_TOKEN_LENGTH}) and is left there
     * deliberately: one place decides what a token may look like.
     *
     * @throws ConsoleEntryRefused
     */
    private function assertionToken(#[SensitiveParameter] mixed $presentedToken): string
    {
        if (! is_string($presentedToken) || $presentedToken === '') {
            throw ConsoleEntryRefused::because(ConsoleEntryRefusalReason::MissingAssertion);
        }

        return $presentedToken;
    }

    /**
     * Take the presented assertion out of the request object, the
     * moment it has been read.
     *
     * **THIS MATTERS MORE THAN THE ATTRIBUTES DO, and the reason is
     * worth being precise about.** PHP's own stack trace renders an
     * object argument as `Object(Illuminate\Http\Request)` and prints
     * none of its contents, so the frame-level exposure is real but
     * narrow. The wide exposure is a rich error reporter — the kind
     * most applications install — which serializes the request's INPUT
     * alongside the trace, independently of which frames hold what. A
     * `#[SensitiveParameter]` does nothing about that; removing the
     * value does.
     *
     * WHEN IT RUNS, exactly — because an earlier revision of this
     * sentence said "before anything that can throw" and that was
     * FALSE: the clock and the missing-field check ran first. It is now
     * the THIRD STATEMENT of {@see __invoke()}, and the only things
     * preceding it are the two `Request::input()` reads that make it
     * possible. Everything in this endpoint that throws — the
     * missing-field refusal, verification, the state binding, the burn,
     * the redemption and the fail-closed audit — runs after it.
     *
     * That is a claim about this endpoint's throwing paths, not about
     * PHP: a fatal error or a timeout can land anywhere, and the two
     * `input()` calls are still calls. What is claimed, and what the
     * test drives, is that no path this code takes reaches a `throw`
     * with the credential still in the request.
     *
     * WHAT IT DOES NOT REACH, named rather than left to be found:
     *
     *  - **the raw request body**, if something has already caused
     *    Symfony to buffer it. The documented carrier is a form POST,
     *    where nothing does; a JSON-carrier caller whose body was read
     *    leaves the bytes there, and no PHP API clears that buffer.
     *  - **anything that copied the input earlier in the stack.** No
     *    package middleware does, but a host's might.
     *  - **the framework's own frames**, which hold this same `Request`
     *    object all the way down the pipeline and cannot be annotated
     *    by this package. What this method does is make the object they
     *    hold no longer carry the credential.
     */
    private function forgetPresentedAssertion(#[SensitiveParameter] Request $request): void
    {
        $request->request->remove(self::ASSERTION_FIELD);
        $request->query->remove(self::ASSERTION_FIELD);

        if ($request->isJson()) {
            $request->json()->remove(self::ASSERTION_FIELD);
        }
    }

    /**
     * The delegated guard, typed.
     *
     * It cannot fail behind this route: the route is mounted only when
     * {@see ConsoleGuardConfiguration::servesDelegatedEntry()} holds,
     * which is exactly "the reserved guard name resolves to THIS
     * package's driver". The check is here anyway because the
     * alternative is a type assumption, and a misconfiguration is worth
     * a loud server error rather than a silent one.
     */
    private function guard(): ConsoleGuard
    {
        $guard = Auth::guard(ConsoleGuardConfiguration::GUARD);

        if (! $guard instanceof ConsoleGuard) {
            throw new RuntimeException(
                'POST /bfc/console/enter requires the '.ConsoleGuardConfiguration::GUARD
                .' guard to be this package\'s delegated guard.',
            );
        }

        return $guard;
    }

    /**
     * Audit the refusal, then answer with the one uniform body — **in
     * that order, and only in that order.**
     *
     * {@see audit()} throws when it cannot record, and nothing here
     * catches it, so the `403` is not reachable without a committed
     * audit row. See that method for why.
     */
    private function refuse(string $reason, ?string $mintId): JsonResponse
    {
        $this->audit($reason, $mintId);

        return response()->json([
            'version' => self::PAYLOAD_VERSION,
            'error' => self::REFUSAL_ERROR,
        ], self::REFUSAL_STATUS);
    }

    /**
     * Record the refusal with the actor TYPED and the reason named
     * (D13), and **FAIL CLOSED**: if this cannot be written, the
     * ordinary refusal is not served.
     *
     * IT IS NOT BEST-EFFORT, and an earlier revision of this method was.
     * That revision swallowed every recorder, outbox and database
     * failure and returned the ordinary `403` anyway, which meant an
     * attacker operating during an audit-store outage could feed this
     * door verification attempts that left **no evidence at all** —
     * while the contract promised every refusal was recorded. A
     * guarantee that lapses exactly when someone is attacking is worth
     * less than no guarantee, because it is the one an operator
     * believed.
     *
     * So the exception propagates and the request becomes a `500`. That
     * is the same ruling the vitals read already carries: D16 refuses an
     * unaudited read, an app that cannot record cannot serve, and an app
     * that answers `500` is honestly unreachable rather than quietly
     * lying. It costs an availability trade that is stated rather than
     * hidden — **a deployment whose database is unwritable cannot refuse
     * an entry with a `403`; it errors instead** — and the trade is
     * cheap, because a deployment whose database is unwritable cannot
     * complete a successful entry either. Nothing an attacker can do
     * from outside makes this branch fire.
     *
     * It opens its OWN transaction because there is no state transition
     * to stay transactional with — the entry did not happen — and the
     * transaction the refusal came out of has rolled back.
     *
     * It does NOT drain the outbox. This is the one attacker-reachable
     * path on this route, a drain is O(claimable rows) and may send
     * mail, and hanging one off a refusal is the amplification lever the
     * vitals read was hardened against. The outbox row is still written
     * in the same transaction and is delivered by the next drain.
     *
     *   Pinned by `tests/ConsoleEnterTest.php` — "does not serve a
     *   refusal it could not record" and "records every refusal it
     *   serves, one row per refused entry".
     */
    private function audit(string $reason, ?string $mintId): void
    {
        DB::transaction(function () use ($reason, $mintId): void {
            $this->recorder->record(
                event: LifecycleEventType::DeniedAction,
                actor: AuditActor::assertionPresenter($mintId),
                note: self::AUDIT_NOTE.$reason,
                drainAfterCommit: false,
            );
        });
    }

    /**
     * Drop burn rows for assertions that expired long enough ago to be
     * unable to change any answer. Never able to fail an entry the
     * operator already earned.
     */
    private function prune(CarbonImmutable $now): void
    {
        try {
            AssertionBurn::prune($now);
        } catch (Throwable) {
            // Housekeeping. The next successful entry tries again, and
            // a table that keeps its rows is correct, merely larger.
        }
    }
}
