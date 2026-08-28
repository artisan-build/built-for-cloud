<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\BurnMode;
use ArtisanBuild\BuiltForCloud\ClaimError;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresBurnMode;
use ArtisanBuild\BuiltForCloud\Contracts\DurableCredentialMinter;
use ArtisanBuild\BuiltForCloud\MintedSecret;
use ArtisanBuild\BuiltForCloud\OnboardingToken;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\TokenRegistry;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Illuminate\Validation\Rule;
use Throwable;

/**
 * The claim-code primitive over `onboarding_tokens` (PRD 1.1 + 1.2): a
 * short-lived, optionally addressed, single-use code exchanged for a
 * durable credential, speaking the hitch claim contract's vocabulary and
 * error enum on the claim surfaces.
 */
final class ManageOnboarding
{
    /**
     * Package-enforced bounds on the CODE's lifetime only (D1b): 60 seconds
     * to 7 days. Durable-credential TTL stays caller-chosen and unbounded —
     * the short life belongs on the code, not on the token it buys.
     */
    private const int TTL_MIN_SECONDS = 60;

    private const int TTL_MAX_SECONDS = 604800;

    public function __construct(
        private readonly TokenRegistry $tokens,
        private readonly DurableCredentialMinter $minter,
        private readonly CredentialDeclaration $declaration,
    ) {}

    public function issue(Request $request): JsonResponse
    {
        /** @var array{email?: string|null, scope?: string|null, ttl_seconds: int} $validated */
        $validated = $request->validate([
            'email' => ['nullable', 'email'],
            'scope' => ['nullable', 'string', Rule::in(Scope::values())],
            'ttl_seconds' => ['required', 'integer', 'between:'.self::TTL_MIN_SECONDS.','.self::TTL_MAX_SECONDS],
        ]);

        return DB::transaction(function () use ($validated): JsonResponse {
            $email = $validated['email'] ?? null;
            $scope = $validated['scope'] ?? Scope::Consume->value;

            // Issuing supersedes any pending code for the same address+scope,
            // but deliberately does NOT touch the live durable credential
            // (D1d): a code sitting in an inbox must not break a working
            // integration on send day. Exchange revokes instead.
            if ($email !== null) {
                $this->supersedePendingOnboarding($email, $scope);
            }

            $claimCode = $this->mintClaimCode($email, $scope, (int) $validated['ttl_seconds']);

            return response()->json([
                'claim_code' => $claimCode->reveal(),
                'email' => $email,
            ], 201);
        });
    }

    public function exchange(Request $request): JsonResponse
    {
        /** @var array{token: string, version?: int|null} $validated */
        $validated = $request->validate([
            'token' => ['required', 'string'],
            'version' => ['nullable', 'integer'],
        ]);

        if (($validated['version'] ?? 1) !== 1) {
            return ClaimError::UnsupportedVersion->respond('This server speaks claim contract version 1.');
        }

        $presented = $validated['token'];

        if (preg_match('/^[0-9a-f]{64}$/', $presented) !== 1) {
            return ClaimError::InvalidCode->respond('That code is not in the expected format. Check it for typos and try again.');
        }

        try {
            return $this->performExchange($presented);
        } catch (Throwable $exception) {
            // The claim contract's server_error: clients print `message`
            // verbatim and treat the failure as retryable. Laravel's
            // exception renderer must never answer on this surface — a debug
            // page carries exception and query detail.
            return $this->serverError($exception);
        }
    }

    private function performExchange(string $presented): JsonResponse
    {
        return DB::transaction(function () use ($presented): JsonResponse {
            /** @var OnboardingToken|null $code */
            $code = OnboardingToken::query()
                ->where('token_hash', OnboardingToken::hashToken($presented))
                ->lockForUpdate()
                ->first();

            if ($code === null) {
                return ClaimError::CodeNotFound->respond('No claim code matches the one presented. Ask the issuer for a new one.');
            }

            if ($code->consumed_at !== null) {
                return ClaimError::CodeAlreadyClaimed->respond('This code was already used to set up a working connection. Ask the issuer to revoke it and issue a new one.');
            }

            if ($code->expires_at->lessThanOrEqualTo(now())) {
                return ClaimError::CodeExpired->respond('This code has expired. Ask the issuer for a new one.');
            }

            // Under `at_exchange` (a provider with no observable first use),
            // redemption IS the burn: a conditional update gated on affected
            // rows, inside this locked transaction. Zero rows means a
            // concurrent exchange won.
            if ($this->burnMode() === BurnMode::AtExchange) {
                $consumed = OnboardingToken::query()
                    ->whereKey($code->getKey())
                    ->whereNull('consumed_at')
                    ->update(['consumed_at' => now()]);

                if ($consumed === 0) {
                    return ClaimError::CodeAlreadyClaimed->respond('This code was already used to set up a working connection. Ask the issuer to revoke it and issue a new one.');
                }
            }

            // A re-claim before first use lands here too (make-before-break):
            // mint fresh and invalidate the pending durable — hashed storage
            // cannot return the same token — so at most one live token per
            // code ever exists. Exchange performs BOTH revocations (D1d): by
            // the code's own durable link, and by name+scope for the live
            // durable that issue no longer revokes.
            if ($code->durable_token_id !== null) {
                $this->revokeDurableById($code->durable_token_id);
            }

            $name = $code->email ?? 'claim-'.$code->id;

            $this->revokeActiveDurable($name, $code->scope, $code->id);

            $minted = $this->minter->mint($name, $code->scope);

            $code->forceFill(['durable_token_id' => $minted->token->getKey()])->save();

            return response()->json([
                'durable_token' => $minted->secret->reveal(),
                'name' => $name,
            ], 201);
        });
    }

    public function verify(Request $request): JsonResponse
    {
        $bearer = $request->bearerToken();

        if ($bearer === null || $bearer === '') {
            return ClaimError::InvalidCode->respond('The request presented no credential to verify.');
        }

        try {
            // Resolution is the burn point for `first_use` providers: the
            // atomic first-use transition inside resolveModel() consumes the
            // claim code that minted this credential.
            $durableToken = $this->tokens->resolveModel($bearer);
        } catch (Throwable $exception) {
            return $this->serverError($exception);
        }

        if ($durableToken === null) {
            return ClaimError::CodeNotFound->respond('No live credential matches the one presented.');
        }

        // Best-effort attribution; never breaks the request.
        $this->tokens->recordClientIdentityFromRequest($request, $durableToken);

        return response()->json([
            'ok' => true,
            'name' => $durableToken->name,
            'scope' => $durableToken->abilities[0] ?? null,
        ]);
    }

    private function serverError(Throwable $exception): JsonResponse
    {
        try {
            // Only the exception CLASS reaches the log: a driver message can
            // echo bound values, and the bindings on this surface include
            // presented codes.
            Log::warning('Built for Cloud could not serve a claim surface.', [
                'exception' => $exception::class,
            ]);
        } catch (Throwable) {
            // Failing to log must not replace the contract-shaped response.
        }

        return ClaimError::ServerError->respond('The server hit an unexpected error. It is safe to retry.');
    }

    private function burnMode(): BurnMode
    {
        return $this->declaration instanceof DeclaresBurnMode
            ? $this->declaration->burnMode()
            : BurnMode::FirstUse;
    }

    private function supersedePendingOnboarding(string $email, string $scope): void
    {
        /** @var list<OnboardingToken> $tokens */
        $tokens = OnboardingToken::query()
            ->pending()
            ->where('email', $email)
            ->where('scope', $scope)
            ->lockForUpdate()
            ->get()
            ->all();

        foreach ($tokens as $token) {
            // A pending code's durable link is a never-used make-before-break
            // token; superseding the code invalidates it. A durable that has
            // been USED belongs to a consumed code and is never touched here.
            if ($token->durable_token_id !== null) {
                $this->revokeDurableById($token->durable_token_id);
            }

            $token->forceFill(['consumed_at' => now()])->save();
        }
    }

    /**
     * The D1d name+scope sweep: revoke the live durable the code replaces.
     * Names are free text with no unique index (deliberately), so the sweep
     * is BOUNDED to keep an accidental name collision from killing an
     * unrelated integration:
     *
     * - A row superseded by rotation survives: `rotated_at` is provenance
     *   only `TokenRegistry::rotate()` asserts, and the grace expiry that
     *   verb set already bounds the row. No shape heuristic — a crafted
     *   short-TTL token of the same name+scope carries no marker and dies
     *   in the sweep like any other collision.
     * - A durable linked to a DIFFERENT unconsumed code survives: it is
     *   governed by that code's own make-before-break lifecycle.
     *
     * The residual collision domain — same free-text name, same scope,
     * outside these exclusions — remains and is documented in the release
     * note; the unified store's subject binding (PRD 1.19) dissolves it.
     */
    private function revokeActiveDurable(string $name, string $scope, string $exchangingCodeId): void
    {
        /** @var list<ApiToken> $tokens */
        $tokens = ApiToken::query()
            ->resolvable()
            ->where('name', $name)
            ->lockForUpdate()
            ->get()
            ->all();

        /** @var list<string> $linkedToOtherCodes */
        $linkedToOtherCodes = OnboardingToken::query()
            ->whereKeyNot($exchangingCodeId)
            ->whereNull('consumed_at')
            ->whereNotNull('durable_token_id')
            ->pluck('durable_token_id')
            ->all();

        foreach ($tokens as $token) {
            if (! $token->hasAbility($scope)) {
                continue;
            }

            if (in_array($token->getKey(), $linkedToOtherCodes, true)) {
                continue;
            }

            if ($token->rotated_at !== null) {
                continue;
            }

            $this->revokeLockedDurable($token);
        }
    }

    private function revokeDurableById(string $tokenId): void
    {
        /** @var ApiToken|null $token */
        $token = ApiToken::query()
            ->whereKey($tokenId)
            ->lockForUpdate()
            ->first();

        if ($token !== null) {
            $this->revokeLockedDurable($token);
        }
    }

    private function revokeLockedDurable(ApiToken $token): void
    {
        $now = now();

        $token->forceFill([
            'expires_at' => $now,
            'revoked_at' => $now,
        ])->save();
    }

    /**
     * Mint a claim code: the plaintext never exists outside its sealed
     * carrier, and only the hash reaches storage. Expiry is exactly issue
     * time + ttl_seconds — no hidden defaults.
     */
    private function mintClaimCode(?string $email, string $scope, int $ttlSeconds): MintedSecret
    {
        do {
            $claimCode = new MintedSecret(bin2hex(random_bytes(32)));
        } while (OnboardingToken::query()->where('token_hash', $claimCode->hash())->exists());

        OnboardingToken::query()->create([
            'id' => (string) Str::uuid(),
            'email' => $email,
            'scope' => $scope,
            'token_hash' => $claimCode->hash(),
            'expires_at' => now()->addSeconds($ttlSeconds),
        ]);

        return $claimCode;
    }
}
