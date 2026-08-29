<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\Actions\FileConsoleKey;
use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyDelivery;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyRefusal;
use ArtisanBuild\BuiltForCloud\Events\OwnershipReleasePending;
use ArtisanBuild\BuiltForCloud\Events\OwnershipTransferred;
use ArtisanBuild\BuiltForCloud\Exceptions\ConsoleKeyRefused;
use ArtisanBuild\BuiltForCloud\Ownership;
use ArtisanBuild\BuiltForCloud\OwnershipClaim;
use ArtisanBuild\BuiltForCloud\OwnershipClaimMinter;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\TokenGenerator;
use ArtisanBuild\BuiltForCloud\TokenRegistry;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

final class ManageOwnership
{
    public function __construct(
        private readonly TokenGenerator $generator,
        private readonly TokenRegistry $tokens,
        private readonly OwnershipClaimMinter $claims,
        private readonly FileConsoleKey $fileConsoleKey,
    ) {}

    /**
     * Claim ownership of this instance, OPTIONALLY countersigning it in
     * the same act (Console PRD D12 — the claim-time key exchange the
     * contract reserved).
     *
     * The `console_key` field is additive and optional: a claim that
     * omits it behaves in every respect as it did before this release,
     * down to the response keys. A claim that carries it files and
     * activates the vendor's per-deployment PUBLIC key on this app's
     * keyring, and the response names the filed key id.
     *
     * Delivery and claim succeed or fail TOGETHER. The filing happens
     * inside the claim's own transaction, so a refused key rolls the
     * whole claim back: no owner token is minted, the claim code stays
     * unconsumed and presentable, and no keyring row is created. The
     * alternative — claiming anyway and reporting the key failure —
     * would burn a single-use claim code on a deployment that ended up
     * unkeyed, with no way back except re-onboarding, which is the exact
     * outcome the re-key verb exists to avoid.
     *
     * **Why this surface needs no separate key-custody authority**, when
     * the onboarding exchange does (rework B1): presenting a valid
     * ownership claim code already yields an admin-ability owner token
     * in this same response. The holder is becoming the deployment's
     * owner; letting it also name the key that may enter as a delegated
     * admin escalates nothing it does not already have. The onboarding
     * exchange is the opposite case — a routine `scope=consume` code
     * yields no admin at all — which is why authority is explicit there
     * and implicit here.
     *
     * This is also the ONE path exempt from
     * {@see ConsoleKeyRefusal::Unclaimed},
     * and it is exempt by construction rather than by an exception:
     * ownership is established earlier in this very transaction, so by
     * the time the filing runs, the deployment IS claimed.
     */
    public function claim(Request $request): JsonResponse
    {
        /** @var array{token: string, notify_callback?: string|null} $validated */
        $validated = $request->validate([
            'token' => ['required', 'string'],
            'notify_callback' => ['nullable', 'url'],
        ]);

        // Parsed BEFORE the transaction: it is pure (a charset check and
        // an Ed25519 point check, no reads, no writes), so malformed
        // material refuses without ever locking a claim row.
        try {
            $delivery = ConsoleKeyDelivery::optionalFrom($request);
        } catch (ConsoleKeyRefused $refused) {
            $this->fileConsoleKey->recordRefusal($refused, null, null);

            return response()->json(['message' => $refused->getMessage()], $refused->reason->status());
        }

        // Carried OUT of the rolled-back transaction so a refusal can
        // still be audited against the party that presented the code.
        $presentedClaimId = null;

        try {
            return DB::transaction(function () use ($validated, $delivery, &$presentedClaimId): JsonResponse {
                return $this->performClaim($validated, $delivery, $presentedClaimId);
            });
        } catch (ConsoleKeyRefused $refused) {
            $this->fileConsoleKey->recordRefusal(
                $refused,
                is_string($presentedClaimId) ? AuditActor::credentialHolder($presentedClaimId) : null,
                $delivery?->keyId,
            );

            return response()->json(['message' => $refused->getMessage()], $refused->reason->status());
        }
    }

    /**
     * The claim itself, inside the caller's transaction.
     *
     * @param  array{token: string, notify_callback?: string|null}  $validated
     * @param  string|null  $presentedClaimId  written with the presenting claim's id, so a refusal that rolls this transaction back can still be audited against it
     *
     * @param-out string $presentedClaimId
     *
     * @throws ConsoleKeyRefused when a delivered key cannot be filed — rolling the whole claim back
     */
    private function performClaim(array $validated, ?ConsoleKeyDelivery $delivery, ?string &$presentedClaimId): JsonResponse
    {
        $claim = $this->lockClaim($validated['token']);

        if ($claim === null) {
            abort(401);
        }

        $presentedClaimId = (string) $claim->getKey();

        $ownership = Ownership::query()->lockForUpdate()->first();
        $isPendingTransfer = $ownership !== null && $ownership->pending_claim_id === $claim->getKey();

        if ($ownership !== null && $ownership->owner_token_id !== null && ! $isPendingTransfer) {
            return response()->json(['message' => 'already claimed'], 409);
        }

        $generated = $this->generator->generate();
        $ownerToken = $this->tokens->store('owner', $generated->hash, abilities: [Scope::Admin->value]);
        $webhookSecret = bin2hex(random_bytes(32));
        $now = now();
        $oldCallbackUrl = $ownership?->notify_callback;
        $oldWebhookSecret = $ownership?->webhook_secret;

        if ($ownership === null) {
            $ownership = Ownership::query()->create([
                'owner_token_id' => $ownerToken->getKey(),
                'notify_callback' => $validated['notify_callback'] ?? null,
                'webhook_secret' => $webhookSecret,
                'pending_claim_id' => null,
            ]);
        } else {
            if ($isPendingTransfer && $ownership->owner_token_id !== null) {
                ApiToken::query()->whereKey($ownership->owner_token_id)->update([
                    'expires_at' => $now,
                    'revoked_at' => $now,
                ]);
            }

            $ownership->forceFill([
                'owner_token_id' => $ownerToken->getKey(),
                'notify_callback' => array_key_exists('notify_callback', $validated)
                    ? $validated['notify_callback']
                    : $ownership->notify_callback,
                'webhook_secret' => $webhookSecret,
                'pending_claim_id' => null,
            ])->save();

            if ($isPendingTransfer && $oldWebhookSecret !== null) {
                event(new OwnershipTransferred(
                    callbackUrl: $oldCallbackUrl,
                    secret: $oldWebhookSecret,
                    event: 'ownership.transferred',
                    payload: ['product' => config('built-for-cloud.product')],
                ));
            }
        }

        $claim->forceFill(['consumed_at' => $now])->save();

        // Additive, and ABSENT rather than null when no key was
        // delivered: a consumer pinned to the pre-console response
        // sees byte-identical keys.
        $consoleKey = $delivery === null
            ? []
            : [ConsoleKeyDelivery::FIELD => ($this->fileConsoleKey)(
                $delivery,
                AuditActor::credentialHolder((string) $claim->getKey()),
            )->toArray()];

        return response()->json([
            'owner_token' => $generated->plaintext,
            'webhook_secret' => $webhookSecret,
            'product' => config('built-for-cloud.product'),
            ...$consoleKey,
        ], 201);
    }

    public function release(Request $request): JsonResponse
    {
        $request->validate([]);

        return DB::transaction(function (): JsonResponse {
            $ownership = Ownership::query()->lockForUpdate()->first();

            if ($ownership === null || $ownership->owner_token_id === null) {
                return response()->json(['message' => 'ownership is not claimed'], 409);
            }

            if ($ownership->pending_claim_id !== null) {
                $this->consumeClaimById($ownership->pending_claim_id);
            }

            [$swapToken, $claim] = $this->claims->mint();

            $ownership->forceFill([
                'pending_claim_id' => $claim->getKey(),
            ])->save();

            if ($ownership->webhook_secret !== null) {
                event(new OwnershipReleasePending(
                    callbackUrl: $ownership->notify_callback,
                    secret: $ownership->webhook_secret,
                    event: 'ownership.release_pending',
                    payload: ['product' => config('built-for-cloud.product')],
                ));
            }

            return response()->json(['ownership_claim_code' => $swapToken], 201);
        });
    }

    public function cancelTransfer(): JsonResponse
    {
        return DB::transaction(function (): JsonResponse {
            $ownership = Ownership::query()->lockForUpdate()->first();

            if ($ownership !== null && $ownership->pending_claim_id !== null) {
                $this->consumeClaimById($ownership->pending_claim_id);

                $ownership->forceFill(['pending_claim_id' => null])->save();
            }

            return response()->json(['ok' => true]);
        });
    }

    private function lockClaim(string $plainTextToken): ?OwnershipClaim
    {
        /** @var OwnershipClaim|null $claim */
        $claim = OwnershipClaim::query()
            ->pending()
            ->where('token_hash', OwnershipClaim::hashToken($plainTextToken))
            ->lockForUpdate()
            ->first();

        return $claim;
    }

    private function consumeClaimById(string $claimId): void
    {
        /** @var OwnershipClaim|null $claim */
        $claim = OwnershipClaim::query()
            ->whereKey($claimId)
            ->lockForUpdate()
            ->first();

        if ($claim !== null && $claim->consumed_at === null) {
            $claim->forceFill(['consumed_at' => now()])->save();
        }
    }
}
