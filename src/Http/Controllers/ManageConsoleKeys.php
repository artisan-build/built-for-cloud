<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\Actions\FileConsoleKey;
use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyDelivery;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyFiled;
use ArtisanBuild\BuiltForCloud\Exceptions\ConsoleKeyRefused;
use ArtisanBuild\BuiltForCloud\Http\Middleware\UniformConsoleKeyRefusal;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

/**
 * The re-key verb (Console PRD D12): the retrofit path that gives an
 * ALREADY-CLAIMED deployment a countersigning key — or a replacement one
 * — without re-onboarding it.
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
 * Every pre-authorization refusal on this route is normalized to one
 * status and body by {@see UniformConsoleKeyRefusal}; the audit stream
 * keeps the distinction.
 */
final class ManageConsoleKeys
{
    public function __construct(private readonly FileConsoleKey $fileConsoleKey) {}

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
