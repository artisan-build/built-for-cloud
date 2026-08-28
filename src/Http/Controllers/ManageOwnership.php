<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\Events\OwnershipReleasePending;
use ArtisanBuild\BuiltForCloud\Events\OwnershipTransferred;
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
    ) {}

    public function claim(Request $request): JsonResponse
    {
        /** @var array{token: string, notify_callback?: string|null} $validated */
        $validated = $request->validate([
            'token' => ['required', 'string'],
            'notify_callback' => ['nullable', 'url'],
        ]);

        return DB::transaction(function () use ($validated): JsonResponse {
            $claim = $this->lockClaim($validated['token']);

            if ($claim === null) {
                abort(401);
            }

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

            return response()->json([
                'owner_token' => $generated->plaintext,
                'webhook_secret' => $webhookSecret,
                'product' => config('built-for-cloud.product'),
            ], 201);
        });
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
