<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\Actions\FileConsoleKey;
use ArtisanBuild\BuiltForCloud\Actions\RetireConsoleKey;
use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyDelivery;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyFiled;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyRetired;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyring;
use ArtisanBuild\BuiltForCloud\Exceptions\ConsoleKeyRefused;
use ArtisanBuild\BuiltForCloud\Http\Middleware\UniformConsoleKeyRefusal;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

/**
 * The two console key-custody verbs (Console PRD D12): the re-key that
 * gives an ALREADY-CLAIMED deployment a countersigning key — or a
 * replacement one — without re-onboarding it, and the retirement that
 * finishes the rotation the re-key opened.
 *
 * They share a controller because they share everything that decides how
 * they answer: one gate (`console:key:write`), one uniform
 * pre-authorization refusal, one actor reading, one refusal envelope.
 * The rules each verb enforces are in its own action.
 *
 * ## The re-key
 *
 * It exists because the claim-time exchange only helps deployments that
 * have not claimed yet, and by the time the Console ships the fleet is
 * already claimed. sink runs this verb first, against a live deployment
 * (PRD §5-bis item 5), which is the constraint that shapes it: it must
 * be safe to run at any moment, on a deployment that is serving traffic.
 * That is what make-before-break buys — {@see FileConsoleKey} activates
 * the new key and retires nothing, so every assertion in flight under
 * the outgoing key keeps verifying.
 *
 * **"Already claimed" is enforced, not assumed** (rework A6). An earlier
 * revision argued the gate was the check, on the reasoning that an
 * unclaimed deployment has issued no credential. That was false:
 * `bfc:install:operator-credential` mints an operator credential from
 * the host, before and independently of any ownership claim. The
 * ownership row is now locked and checked inside the filing transaction
 * by {@see FileConsoleKey}, and an unclaimed deployment refuses.
 *
 * **The gate is `console:key:write`, its own ability** (rework B2). A
 * re-key is a rotation in shape, and this route was first specified on
 * the `credential:rotate` family for that reason. The shape was the
 * wrong thing to reason from: folding it into that family would have
 * given every credential ALREADY ISSUED with `credential:rotate` the
 * power to install a delegated-admin trust root, silently, on upgrade,
 * with nobody's decision. `credential:admin` — the explicit break-glass
 * — still satisfies it ({@see OperatorAbility::adminEquivalent}).
 *
 * Every pre-authorization refusal on these routes is normalized to one
 * status and body by {@see UniformConsoleKeyRefusal}; the audit stream
 * keeps the distinction.
 *
 * ## The retirement
 *
 * {@see self::retire()} is the operator path over
 * {@see ConsoleKeyring::retire()}, which until this release was
 * reachable only from PHP running inside the app — so a fleet that had
 * re-keyed could start trusting the incoming key over HTTP and never
 * stop trusting the outgoing one.
 *
 * **The same gate, and that is a decision rather than an inheritance.**
 * Retirement ends a signing authority where filing begins one, and it is
 * tempting to read "ending" as the more consequential half. It is not,
 * on this ring: whoever holds `console:key:write` can already file and
 * activate a key of its own and enter this deployment as a delegated
 * admin, which is strictly more than denying entry. A separate ability
 * would also have meant no credential in the field could retire
 * anything until it was reissued — leaving the rotation half-finished
 * on exactly the deployments this verb exists for.
 */
final class ManageConsoleKeys
{
    /**
     * The response key a retirement answers under. Deliberately NOT
     * {@see ConsoleKeyDelivery::FIELD}: that name is the shape of a
     * DELIVERY, and a consumer branching on it must not find a retired
     * key wearing it.
     */
    public const string RETIRED_FIELD = 'console_key_retired';

    public function __construct(
        private readonly FileConsoleKey $fileConsoleKey,
        private readonly RetireConsoleKey $retireConsoleKey,
    ) {}

    /**
     * File and activate a new countersigning key.
     *
     * The request body is the flat pair (`key_id`, `public_key`) — the
     * whole subject of this route — where the claim envelopes nest the
     * same two fields under `console_key` because they carry other
     * things too. Both parse through {@see ConsoleKeyDelivery}, so the
     * two shapes cannot come to mean different things.
     */
    public function reKey(Request $request): JsonResponse
    {
        $actor = $this->actor($request);

        try {
            $delivery = ConsoleKeyDelivery::fromPayload($request->only(['key_id', 'public_key']));
        } catch (ConsoleKeyRefused $refused) {
            // Nothing was read from the database and nothing opened a
            // transaction, so this refusal audits on its own.
            $this->fileConsoleKey->recordRefusal($refused, $actor, $this->presentedKeyId($request));

            return $this->refusalResponse($refused);
        }

        try {
            $filed = DB::transaction(
                fn (): ConsoleKeyFiled => ($this->fileConsoleKey)($delivery, $actor),
            );
        } catch (ConsoleKeyRefused $refused) {
            // The `kid` was already on file. The transaction rolled back
            // — no row was written, and the material behind the existing
            // key id is untouched — so the refusal audits outside it.
            $this->fileConsoleKey->recordRefusal($refused, $actor, $delivery->keyId);

            return $this->refusalResponse($refused);
        }

        return response()->json([ConsoleKeyDelivery::FIELD => $filed->toArray()], 201);
    }

    /**
     * Stop trusting one filed key.
     *
     * The `kid` rides the PATH — the verb acts on a row that already
     * exists, the way `POST /bfc/credentials/{id}/rotate` does, where
     * the re-key's flat body carries a key that does not exist yet. A
     * `kid` is bounded to `[A-Za-z0-9._-]`, so it needs no encoding to
     * be a path segment and cannot carry a separator.
     *
     * The body carries one optional boolean,
     * `confirm_last_active_key`. Anything other than a literal `true` is
     * absence: a caller confirming the end of delegated entry says so,
     * and a truthy string is not that. Absence is the safe reading, and
     * the refusal it produces names what to send.
     */
    public function retire(Request $request, string $keyId): JsonResponse
    {
        $actor = $this->actor($request);

        try {
            $retired = DB::transaction(
                fn (): ConsoleKeyRetired => ($this->retireConsoleKey)(
                    $keyId,
                    $actor,
                    $request->input('confirm_last_active_key') === true,
                ),
            );
        } catch (ConsoleKeyRefused $refused) {
            // The transaction rolled back — no row changed — so the
            // refusal audits on its own.
            $this->retireConsoleKey->recordRefusal($refused, $actor, $keyId);

            return $this->refusalResponse($refused);
        }

        // 200, not 201 and not 204: nothing was created, and the body is
        // the point — `newly_retired` and what still verifies are what
        // an operator reads to know where the rotation stands.
        return response()->json([self::RETIRED_FIELD => $retired->toArray()]);
    }

    /**
     * The refusal envelope: the contract's ordinary `{"message": ...}`
     * prose shape, with the reason's server-authored text. It never
     * echoes delivered material.
     */
    private function refusalResponse(ConsoleKeyRefused $refused): JsonResponse
    {
        return response()->json(['message' => $refused->getMessage()], $refused->reason->status());
    }

    /**
     * The `key_id` as presented, for the refusal audit note only.
     * {@see FileConsoleKey::recordRefusal()} drops it unless it is
     * well-formed, so a hostile string never reaches the audit row.
     */
    private function presentedKeyId(Request $request): ?string
    {
        $keyId = $request->input('key_id');

        return is_string($keyId) ? $keyId : null;
    }

    /**
     * Which store authenticated, the same reading
     * {@see ManageCredentials} performs: a legacy admin `api_tokens` row
     * audits as an `admin_token` actor, a unified-store operator
     * credential as an `operator_integration` actor. Ids only.
     */
    private function actor(Request $request): ?AuditActor
    {
        $tokenId = $request->attributes->get('bfc.actor_token_id');

        if (is_string($tokenId) && $tokenId !== '') {
            return AuditActor::adminToken($tokenId);
        }

        $credentialId = $request->attributes->get('bfc.actor_credential_id');

        return is_string($credentialId) && $credentialId !== '' ? AuditActor::operatorIntegration($credentialId) : null;
    }
}
