<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\Actions\RotateCredential;
use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\AuditReason;
use ArtisanBuild\BuiltForCloud\Auth\CredentialResolver;
use ArtisanBuild\BuiltForCloud\BurnMode;
use ArtisanBuild\BuiltForCloud\ClaimError;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresBurnMode;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresDurableStore;
use ArtisanBuild\BuiltForCloud\Contracts\DurableCredentialMinter;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialUsageRecorder;
use ArtisanBuild\BuiltForCloud\DurableStore;
use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
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
        private readonly LifecycleEventRecorder $recorder,
    ) {}

    /**
     * Resolved per call, never via the constructor: the router caches
     * controller instances per route, so an injected declaration (or the
     * minter derived from it) would outlive a rebinding — a long-lived
     * worker would keep exchanging into the store an app's declaration no
     * longer targets. ManageTokens and the guard resolve the same way.
     */
    private function declaration(): CredentialDeclaration
    {
        return app(CredentialDeclaration::class);
    }

    private function minter(): DurableCredentialMinter
    {
        return app(DurableCredentialMinter::class);
    }

    public function issue(Request $request): JsonResponse
    {
        /** @var array{email?: string|null, scope?: string|null, ttl_seconds: int} $validated */
        $validated = $request->validate([
            'email' => ['nullable', 'email'],
            'scope' => ['nullable', 'string', Rule::in(Scope::values())],
            'ttl_seconds' => ['required', 'integer', 'between:'.self::TTL_MIN_SECONDS.','.self::TTL_MAX_SECONDS],
        ]);

        $actor = $this->requestActor($request);

        return DB::transaction(function () use ($validated, $actor): JsonResponse {
            $email = $validated['email'] ?? null;
            $scope = $validated['scope'] ?? Scope::Consume->value;
            $ttlSeconds = (int) $validated['ttl_seconds'];

            // Issuing supersedes any pending code for the same address+scope,
            // but deliberately does NOT touch the live durable credential
            // (D1d): a code sitting in an inbox must not break a working
            // integration on send day. Exchange revokes instead.
            if ($email !== null) {
                foreach ($this->supersedePendingOnboarding($email, $scope) as [$durableId, $supersededCodeId]) {
                    $this->recorder->record(
                        event: LifecycleEventType::Revoked,
                        credentialId: $durableId,
                        codeId: $supersededCodeId,
                        actor: $actor,
                        reason: AuditReason::Superseded,
                    );
                }
            }

            [$claimCode, $codeRow] = $this->mintClaimCode($email, $scope, $ttlSeconds);

            $this->recorder->record(
                event: LifecycleEventType::Issued,
                codeId: $codeRow->id,
                actor: $actor,
                recipient: $email,
                codeTtlSeconds: $ttlSeconds,
            );

            return response()->json([
                'claim_code' => $claimCode->reveal(),
                'email' => $email,
            ], 201);
        });
    }

    /**
     * The actor an admin surface can honestly attribute: the admin token
     * that authenticated this request, stashed by the middleware. Null when
     * nothing was stashed — never guessed.
     */
    private function requestActor(Request $request): ?AuditActor
    {
        $tokenId = $request->attributes->get('bfc.actor_token_id');

        return is_string($tokenId) && $tokenId !== '' ? AuditActor::adminToken($tokenId) : null;
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
            //
            // Every revocation acts on the store the durable was RECORDED
            // into, never on whatever the declaration currently targets: a
            // declaration switching stores between exchanges must not
            // strand a still-live durable in the old one.
            $revokedIds = [];

            if ($code->durable_token_id !== null) {
                $revokedIds[] = $this->revokeDurableById($code->durable_token_id, $code->durableStore());
            }

            $name = $code->email ?? 'claim-'.$code->id;

            // The sweep's store set — the stated choice (Fix 3): the
            // CURRENT target store plus the recorded store of this code's
            // own linked durable. That covers the store transition exactly
            // (the pre-switch durable's store is recorded on the code)
            // without extending the documented name-collision domain into
            // a store this code never touched.
            $sweepStores = [$this->durableStore()];

            if ($code->durable_token_id !== null && ! in_array($code->durableStore(), $sweepStores, true)) {
                $sweepStores[] = $code->durableStore();
            }

            foreach ($sweepStores as $sweepStore) {
                $revokedIds = [...$revokedIds, ...$this->revokeActiveDurable($name, $code->scope, $code->id, $sweepStore)];
            }

            $revokedIds = array_values(array_filter($revokedIds));

            $minted = $this->minter()->mint($name, $code->scope);

            $code->forceFill([
                'durable_token_id' => $minted->token->getKey(),
                'durable_store' => $this->durableStore(),
            ])->save();

            // The stream, same transaction (SEC-V3-09): the exchange itself,
            // then each revocation it performed with its supersession
            // lineage (old -> new). The only actor an unauthenticated claim
            // surface can honestly attribute is the bearer of the code.
            $actor = AuditActor::credentialHolder($code->id);
            $newId = (string) $minted->token->getKey();

            $this->recorder->record(
                event: LifecycleEventType::Exchanged,
                credentialId: $newId,
                codeId: $code->id,
                actor: $actor,
                recipient: $code->email,
            );

            foreach (array_unique($revokedIds) as $revokedId) {
                $this->recorder->record(
                    event: LifecycleEventType::Revoked,
                    credentialId: $revokedId,
                    codeId: $code->id,
                    actor: $actor,
                    reason: AuditReason::Superseded,
                    supersededByCredentialId: $newId,
                );
            }

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

        if ($this->durableStore() === DurableStore::Credentials) {
            return $this->verifyUnifiedDurable($request, $bearer);
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

    /**
     * The verify surface for a declaration whose durables live in the
     * unified store: the same wire contract, resolved against
     * `credentials`. Usage recording is the burn point here exactly as
     * `resolveModel()` is for `api_tokens` — a first use consumes the
     * claim code in the same transaction, and a row that died between the
     * resolving read and the usage write does not verify.
     */
    private function verifyUnifiedDurable(Request $request, string $bearer): JsonResponse
    {
        try {
            $credential = app(CredentialResolver::class)->resolve(CredentialKind::Bearer, $bearer);

            if ($credential !== null && ! app(CredentialUsageRecorder::class)->recordUsage($credential)) {
                $credential = null;
            }
        } catch (Throwable $exception) {
            return $this->serverError($exception);
        }

        if ($credential === null) {
            return ClaimError::CodeNotFound->respond('No live credential matches the one presented.');
        }

        return response()->json([
            'ok' => true,
            'name' => $credential->name,
            'scope' => $credential->abilities[0] ?? null,
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
        $declaration = $this->declaration();

        return $declaration instanceof DeclaresBurnMode
            ? $declaration->burnMode()
            : BurnMode::FirstUse;
    }

    /**
     * Which store the seam mints into (PRD 1.0): `api_tokens` unless the
     * declaration opts into the unified store. The exchange's
     * make-before-break revocations follow the SAME answer — a code's
     * durable link and the name+scope sweep both act on the store the
     * durable actually lives in.
     */
    private function durableStore(): DurableStore
    {
        $declaration = $this->declaration();

        return $declaration instanceof DeclaresDurableStore
            ? $declaration->durableCredentialStore()
            : DurableStore::ApiTokens;
    }

    /**
     * @return list<array{string, string}> [revoked durable id, superseded code id] pairs
     */
    private function supersedePendingOnboarding(string $email, string $scope): array
    {
        /** @var list<OnboardingToken> $tokens */
        $tokens = OnboardingToken::query()
            ->pending()
            ->where('email', $email)
            ->where('scope', $scope)
            ->lockForUpdate()
            ->get()
            ->all();

        $revoked = [];

        foreach ($tokens as $token) {
            // A pending code's durable link is a never-used make-before-break
            // token; superseding the code invalidates it — in the store it
            // was RECORDED into. A durable that has been USED belongs to a
            // consumed code and is never touched here.
            if ($token->durable_token_id !== null && $this->revokeDurableById($token->durable_token_id, $token->durableStore()) !== null) {
                $revoked[] = [$token->durable_token_id, $token->id];
            }

            $token->forceFill(['consumed_at' => now()])->save();
        }

        return $revoked;
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
    /**
     * @return list<string> the ids of the durables actually revoked
     */
    private function revokeActiveDurable(string $name, string $scope, string $exchangingCodeId, DurableStore $store): array
    {
        if ($store === DurableStore::Credentials) {
            return $this->revokeActiveUnifiedDurable($name, $scope, $exchangingCodeId);
        }

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

        $revoked = [];

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

            $revoked[] = (string) $token->getKey();
        }

        return $revoked;
    }

    /**
     * The unified-store half of the D1d sweep: same exclusions, expressed
     * on `credentials` columns. The tenancy key here is `subject_ref` (the
     * unified minter sets it from the claim's name), the scope is an
     * ability, and — exactly as on `api_tokens` — a row superseded by
     * rotation survives, because the sweep killing it would break the
     * make-before-break window rotation exists to provide.
     *
     * The exemption requires the SHAPE the rotate verb actually leaves,
     * not the marker alone ({@see inRotationGrace}): a bare `rotated_at`
     * with no bounded expiry describes an INCOMPLETE cutover (failure
     * path B) — a row nothing bounds — and sparing it would exempt it
     * from the sweep forever. Such a row is swept like any ordinary
     * collision.
     *
     * @return list<string> the ids of the durables actually revoked
     */
    private function revokeActiveUnifiedDurable(string $name, string $scope, string $exchangingCodeId): array
    {
        /** @var list<Credential> $credentials */
        $credentials = Credential::query()
            ->where('kind', CredentialKind::Bearer->value)
            ->where('subject_ref', $name)
            ->active()
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

        $revoked = [];

        foreach ($credentials as $credential) {
            if (! $credential->hasAbility($scope)) {
                continue;
            }

            if (in_array($credential->getKey(), $linkedToOtherCodes, true)) {
                continue;
            }

            if ($this->inRotationGrace($credential)) {
                continue;
            }

            $credential->forceFill(['revoked_at' => now()])->save();

            $revoked[] = (string) $credential->getKey();
        }

        return $revoked;
    }

    /**
     * Whether a row carries the honest rotation-grace shape: the
     * `rotated_at` stamp AND a bounded expiry consistent with the grace
     * horizon (non-null, no later than the stamp plus the maximum grace
     * window). Only the rotate verb leaves this combination — the stamp
     * arrives with (or before) an expiry the verb bounds — so the sweep
     * can trust the shape where it must not trust the marker alone.
     */
    private function inRotationGrace(Credential $credential): bool
    {
        return $credential->rotated_at !== null
            && $credential->expires_at !== null
            && ! $credential->expires_at->isAfter(
                $credential->rotated_at->copy()->addSeconds(RotateCredential::GRACE_SECONDS),
            );
    }

    /**
     * Revoke a linked durable in the store it was RECORDED into (never the
     * currently declared store — the linkage outlives declaration changes).
     *
     * @return string|null the revoked durable's id, or null when no row matched
     */
    private function revokeDurableById(string $tokenId, DurableStore $store): ?string
    {
        if ($store === DurableStore::Credentials) {
            /** @var Credential|null $credential */
            $credential = Credential::query()
                ->whereKey($tokenId)
                ->lockForUpdate()
                ->first();

            if ($credential === null) {
                return null;
            }

            $credential->forceFill(['revoked_at' => $credential->revoked_at ?? now()])->save();

            return (string) $credential->getKey();
        }

        /** @var ApiToken|null $token */
        $token = ApiToken::query()
            ->whereKey($tokenId)
            ->lockForUpdate()
            ->first();

        if ($token === null) {
            return null;
        }

        $this->revokeLockedDurable($token);

        return (string) $token->getKey();
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
     *
     * @return array{MintedSecret, OnboardingToken}
     */
    private function mintClaimCode(?string $email, string $scope, int $ttlSeconds): array
    {
        do {
            $claimCode = new MintedSecret(bin2hex(random_bytes(32)));
        } while (OnboardingToken::query()->where('token_hash', $claimCode->hash())->exists());

        $codeRow = OnboardingToken::query()->create([
            'id' => (string) Str::uuid(),
            'email' => $email,
            'scope' => $scope,
            'token_hash' => $claimCode->hash(),
            'expires_at' => now()->addSeconds($ttlSeconds),
        ]);

        return [$claimCode, $codeRow];
    }
}
