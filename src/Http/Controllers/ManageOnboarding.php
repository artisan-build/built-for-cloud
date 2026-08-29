<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\Actions\FileConsoleKey;
use ArtisanBuild\BuiltForCloud\Actions\RotateCredential;
use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\AuditReason;
use ArtisanBuild\BuiltForCloud\Auth\CredentialResolver;
use ArtisanBuild\BuiltForCloud\BurnMode;
use ArtisanBuild\BuiltForCloud\ClaimError;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyDelivery;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyRefusal;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresBurnMode;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresDurableStore;
use ArtisanBuild\BuiltForCloud\Contracts\DurableCredentialMinter;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\CredentialUsageRecorder;
use ArtisanBuild\BuiltForCloud\DurableStore;
use ArtisanBuild\BuiltForCloud\Exceptions\ConsoleKeyRefused;
use ArtisanBuild\BuiltForCloud\Hmac\HmacKeyring;
use ArtisanBuild\BuiltForCloud\Hmac\HmacWriterBarrier;
use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\MintedSecret;
use ArtisanBuild\BuiltForCloud\OnboardingToken;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\TokenRegistry;
use Carbon\CarbonInterface;
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
        private readonly FileConsoleKey $fileConsoleKey,
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

    /**
     * Mint a claim code, OPTIONALLY carrying console key-custody
     * authority (Console PRD D12, rework B1).
     *
     * `console_key_authority` is what lets the resulting code deliver a
     * countersigning key at exchange. It defaults to FALSE, and that
     * default is the security property: filing a key installs a standing
     * authority to mint delegated-ADMIN entry into this deployment, so a
     * routine `scope=consume` code handed to a low-privilege integration
     * must not be able to do it. Before this flag existed, it could.
     *
     * The authority is set HERE, on an admin-gated surface, by the
     * operator who decides to grant it — never by the party redeeming
     * the code, and never mass-assignable ({@see OnboardingToken}). It
     * is spent by the first key it files, whatever the app's burn mode
     * says about re-presenting the code.
     */
    public function issue(Request $request): JsonResponse
    {
        /** @var array{email?: string|null, scope?: string|null, ttl_seconds: int, console_key_authority?: bool|null} $validated */
        $validated = $request->validate([
            'email' => ['nullable', 'email'],
            'scope' => ['nullable', 'string', Rule::in(Scope::values())],
            'ttl_seconds' => ['required', 'integer', 'between:'.self::TTL_MIN_SECONDS.','.self::TTL_MAX_SECONDS],
            'console_key_authority' => ['nullable', 'boolean'],
        ]);

        $actor = $this->requestActor($request);

        return DB::transaction(function () use ($validated, $actor): JsonResponse {
            $email = $validated['email'] ?? null;
            $scope = $validated['scope'] ?? Scope::Consume->value;
            $ttlSeconds = (int) $validated['ttl_seconds'];
            $consoleKeyAuthority = (bool) ($validated['console_key_authority'] ?? false);

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

            [$claimCode, $codeRow] = $this->mintClaimCode($email, $scope, $ttlSeconds, $consoleKeyAuthority);

            $this->recorder->record(
                event: LifecycleEventType::Issued,
                codeId: $codeRow->id,
                actor: $actor,
                recipient: $email,
                codeTtlSeconds: $ttlSeconds,
                // Granting key-custody authority is the interesting half
                // of an issue, so the audit row says so rather than
                // leaving it to be inferred from a later filing.
                note: $consoleKeyAuthority ? 'issued with console key-custody authority (one key)' : null,
            );

            return response()->json([
                'claim_code' => $claimCode->reveal(),
                'email' => $email,
                // Additive and echoed only when granted, so a consumer
                // pinned to the pre-console shape sees identical keys.
                ...($consoleKeyAuthority ? ['console_key_authority' => true] : []),
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

    /**
     * The hitch claim-contract route (PRD 1.12 / OSS-8 / EXEC-11):
     * `POST /bfc/claim`, the wire face of `hitch/docs/claim-contract.md`
     * over the SAME claim-code primitive the onboarding exchange runs —
     * request field `claim_code`, success `200 {"version", "token",
     * "name", "expires_at"}`, the stable error enum, make-before-break.
     * Mounted unconditionally at a fixed `/bfc/` path: never behind a
     * configurable prefix, never behind its own env flag (the
     * surface-selection key can only unmount the whole HTTP surface
     * family, PRD 1.14).
     *
     * A code that redeems a SIGNING KEY is refused here before any state
     * changes — the hitch contract's success shape has a required `token`
     * a signing-key delivery cannot honestly fill; its exchange surface
     * is `POST /bfc/onboarding/exchange`.
     */
    public function claim(Request $request): JsonResponse
    {
        // The contract shapes every failure, so validation never falls
        // through to Laravel's 422: a missing or non-string code is the
        // enum's `invalid_code`, and a version this server does not speak
        // is `unsupported_version` whatever type it arrived as. `version`
        // is REQUIRED on this surface (rework Fix 9): hitch's contract
        // states "version is an integer in the body", so a request
        // without one speaks a contract this server cannot identify —
        // refused, never defaulted. (The onboarding exchange keeps its
        // documented default; only this hitch-conformant face is strict.)
        if (! $request->has('version')) {
            return ClaimError::UnsupportedVersion->respond('The claim contract requires an explicit integer version in the request body; this server speaks version 1.');
        }

        if ($request->input('version') !== 1) {
            return ClaimError::UnsupportedVersion->respond('This server speaks claim contract version 1.');
        }

        $presented = $request->input('claim_code');

        if (! is_string($presented) || preg_match('/^[0-9a-f]{64}$/', $presented) !== 1) {
            return ClaimError::InvalidCode->respond('That claim code is not in the expected format. Check it for typos and try again.');
        }

        try {
            return $this->performExchange($presented, hitchShape: true);
        } catch (Throwable $exception) {
            return $this->serverError($exception);
        }
    }

    /**
     * The onboarding exchange, OPTIONALLY carrying the claim-time
     * countersigning-key exchange the contract reserved (Console PRD
     * D12).
     *
     * `console_key` is additive and optional. Without it this surface
     * behaves exactly as it did before this release, response keys
     * included; with it, the vendor's per-deployment PUBLIC key is filed
     * and activated on this app's keyring inside the exchange's own
     * transaction, and the response names the filed key id.
     *
     * **Not every code may deliver one** (rework B1). Filing a key
     * installs a standing authority to mint delegated-ADMIN entry into
     * this deployment, so the code must have been issued with explicit
     * `console_key_authority`, and must not have spent it already. The
     * check runs inside the locked transaction BEFORE the burn, so an
     * unauthorized attempt costs the code nothing. A `scope=consume`
     * code — the routine one an operator hands an integration — carries
     * no such authority and never will unless someone asks for it.
     *
     * A refused key rolls the WHOLE exchange back — no durable minted,
     * no signing key delivered, and (under `at_exchange`) the code
     * unburned and still presentable. Half-succeeding would spend a
     * single-use code on a deployment that ended up unkeyed.
     *
     * The hitch claim face ({@see claim()}) deliberately does NOT read
     * this field: `/bfc/claim` speaks a wire contract published by
     * another project, and console key custody is not part of it.
     */
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

        // Parsed before anything is locked or burned: the check is pure
        // (charset plus an Ed25519 point test), so malformed material
        // refuses without touching the code.
        try {
            $delivery = ConsoleKeyDelivery::optionalFrom($request);
        } catch (ConsoleKeyRefused $refused) {
            $this->fileConsoleKey->recordRefusal($refused, null, null);

            return response()->json(['message' => $refused->getMessage()], $refused->reason->status());
        }

        try {
            // A code that delivers an hmac signing key runs its WHOLE
            // exchange under the shared rewrap lock (check-through-commit
            // — see {@see HmacWriterBarrier}): a concurrent exchange can
            // turn a first delivery into a re-key inside the transaction,
            // and a re-key's ciphertext commit must never straddle the
            // rewrap's verified zero-count. While a rewrap run holds the
            // lock, signing-key deliveries answer the claim contract's
            // retryable server_error.
            if ($this->presentedDeliversSigningKey($presented)) {
                return app(HmacWriterBarrier::class)->locked(
                    write: fn (): JsonResponse => $this->performExchange($presented, delivery: $delivery),
                    onBusy: static fn (): JsonResponse => ClaimError::ServerError->respond(
                        'A signing-key storage cutover is running on this server, so signing-key deliveries are briefly paused. It is safe to retry shortly.',
                    ),
                );
            }

            return $this->performExchange($presented, delivery: $delivery);
        } catch (ConsoleKeyRefused $refused) {
            // The `kid` was already on file. The transaction rolled
            // back: no durable, no burn, no keyring row, and the
            // material behind the existing key id is untouched.
            // The presenter is re-read rather than carried out of the
            // rolled-back transaction: the code row survives the
            // rollback (it is what refused to change), and reading it
            // here keeps the barrier path's arrow closures free of
            // by-reference plumbing.
            $this->fileConsoleKey->recordRefusal($refused, $this->codeHolderActor($presented), $delivery?->keyId);

            return response()->json(['message' => $refused->getMessage()], $refused->reason->status());
        } catch (Throwable $exception) {
            // The claim contract's server_error: clients print `message`
            // verbatim and treat the failure as retryable. Laravel's
            // exception renderer must never answer on this surface — a debug
            // page carries exception and query detail.
            return $this->serverError($exception);
        }
    }

    /**
     * The barrier pre-read: does the presented code redeem against an
     * hmac credential? Advisory only — every authoritative check happens
     * again inside the locked transaction; over-acquiring for a code
     * that then refuses is harmless.
     */
    private function presentedDeliversSigningKey(string $presented): bool
    {
        /** @var OnboardingToken|null $code */
        $code = OnboardingToken::query()
            ->where('token_hash', OnboardingToken::hashToken($presented))
            ->first(['id', 'durable_token_id', 'durable_store', 'consumed_at']);

        if ($code === null
            || $code->consumed_at !== null
            || $code->durable_token_id === null
            || $code->durableStore() !== DurableStore::Credentials) {
            return false;
        }

        return Credential::query()
            ->whereKey($code->durable_token_id)
            ->where('kind', CredentialKind::Hmac->value)
            ->exists();
    }

    /**
     * @param  ConsoleKeyDelivery|null  $delivery  the OPTIONAL claim-time countersigning key; always null on the hitch face
     *
     * @throws ConsoleKeyRefused when a delivered key cannot be filed — rolling the whole exchange back
     */
    private function performExchange(string $presented, bool $hitchShape = false, ?ConsoleKeyDelivery $delivery = null): JsonResponse
    {
        return DB::transaction(function () use ($presented, $hitchShape, $delivery): JsonResponse {
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

            // Key-custody authority, re-read from the LOCKED row and
            // checked BEFORE anything burns, mints or files (rework B1).
            //
            // Its position is the point. A filed key is a standing
            // authority to enter this deployment as an admin, so a code
            // that may not file one must not be able to spend itself
            // trying: this throws, the transaction rolls back, and the
            // code is left exactly as it was found. Checking it later —
            // after the burn, next to the filing — would have burned a
            // legitimate code on an unauthorized delivery attempt.
            //
            // Locked, not cached: `mayFileConsoleKey()` also asks whether
            // the authority has already been spent, and that answer is
            // only meaningful under the row lock taken above.
            if ($delivery instanceof ConsoleKeyDelivery && ! $code->mayFileConsoleKey()) {
                throw ConsoleKeyRefused::because(ConsoleKeyRefusal::NotAuthorized);
            }

            // The hitch claim surface cannot deliver a signing key (its
            // success shape REQUIRES a bearer `token`), so a signing-key
            // code refuses HERE — authoritatively, inside the locked
            // transaction, and BEFORE any burn: a refused code must stay
            // presentable on the surface that can serve it.
            if ($hitchShape && $this->codeLinksToSigningKey($code)) {
                return ClaimError::InvalidCode->respond('This code redeems a signing key, which this claim surface cannot deliver. Exchange it at POST /bfc/onboarding/exchange instead.');
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

            // The hmac delivery leg (PRD 1.21, SEC-V3-01): a code linked to
            // a PENDING hmac row delivers THAT key and returns here —
            // nothing below (the durable mint, the D1d sweep) applies to a
            // signing-key delivery, and NOTHING about signing state
            // changes: activation is a separate operator-authorized verb.
            $hmacDelivery = $this->deliverPendingSigningKey($code);

            if ($hmacDelivery !== null) {
                // A REFUSED signing-key delivery files no console key:
                // the exchange did not succeed, and a key filed against
                // a failed exchange is custody nobody was told arrived.
                return $hmacDelivery->isSuccessful()
                    ? $this->withConsoleKey($hmacDelivery, $delivery, $code)
                    : $hmacDelivery;
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

            if ($hitchShape) {
                // The hitch claim contract's success shape (200, not 201
                // — the contract fixes the status): the durable secret as
                // `token`, the suggested `name` (advisory; the client's
                // --name always wins), and the durable's own expiry as
                // RFC 3339 or null. Additive growth is allowed; these
                // four fields are the contract.
                /** @var CarbonInterface|null $expiresAt */
                $expiresAt = $minted->token->expires_at;

                return response()->json([
                    'version' => 1,
                    'token' => $minted->secret->reveal(),
                    'name' => $name,
                    'expires_at' => $expiresAt?->toRfc3339String(),
                ]);
            }

            return $this->withConsoleKey(response()->json([
                'durable_token' => $minted->secret->reveal(),
                'name' => $name,
            ], 201), $delivery, $code);
        });
    }

    /**
     * File a delivered countersigning key and add the additive
     * `console_key` field to a SUCCESSFUL exchange response.
     *
     * With no delivery the response is returned untouched — byte for
     * byte the shape this surface answered with before this release,
     * which is the whole promise of an additive slot.
     *
     * @throws ConsoleKeyRefused when the `kid` is already on file — rolling the exchange back
     */
    private function withConsoleKey(JsonResponse $response, ?ConsoleKeyDelivery $delivery, OnboardingToken $code): JsonResponse
    {
        if ($delivery === null) {
            return $response;
        }

        $filed = ($this->fileConsoleKey)($delivery, AuditActor::credentialHolder($code->id));

        // The authority is single-use, independently of the burn mode.
        // Under `first_use` the code stays presentable until the durable
        // it minted is first used, so without this stamp one authorized
        // code could file a second key under a fresh key id — and every
        // filed key is its own standing admin-entry authority.
        $code->forceFill(['console_key_filed_at' => now()])->save();

        /** @var array<string, mixed> $data */
        $data = $response->getData(true);
        $data[ConsoleKeyDelivery::FIELD] = $filed->toArray();

        return $response->setData($data);
    }

    /**
     * The party that presented a code, for a refusal audit written after
     * the exchange rolled back. Null when no code matches — the actor is
     * then genuinely unknown and is never guessed.
     */
    private function codeHolderActor(string $presented): ?AuditActor
    {
        /** @var OnboardingToken|null $code */
        $code = OnboardingToken::query()
            ->where('token_hash', OnboardingToken::hashToken($presented))
            ->first(['id']);

        return $code === null ? null : AuditActor::credentialHolder($code->id);
    }

    /**
     * Whether the code's linked durable is an hmac signing key — the
     * authoritative, in-transaction form of the advisory
     * {@see presentedDeliversSigningKey} pre-read, consulted by the hitch
     * claim surface to refuse before anything burns. Any lifecycle state
     * counts: even a dead signing-key link is not something this surface
     * can honestly answer for.
     */
    private function codeLinksToSigningKey(OnboardingToken $code): bool
    {
        if ($code->durable_token_id === null || $code->durableStore() !== DurableStore::Credentials) {
            return false;
        }

        return Credential::query()
            ->whereKey($code->durable_token_id)
            ->where('kind', CredentialKind::Hmac->value)
            ->exists();
    }

    /**
     * The hmac claim exchange (PRD 1.21 amendment 3, REVERSED by
     * SEC-V3-01): deliver the PENDING signing key — decrypted through the
     * keyring, audited (`exchanged` + `delivered`, ids only) — and change
     * NOTHING about signing state. An inbox interceptor who redeems the
     * link learns a key that signs nothing and verifies nothing.
     *
     * Where the code burns follows the app's declared burn mode, exactly
     * as on the bearer exchange: under `at_exchange` the generic burn
     * above already consumed it, so a second presentation — the
     * legitimate receiver behind an interceptor — fails loudly as
     * `code_already_claimed`. Under `first_use` (the default) the code
     * stays presentable until ACTIVATION consumes it (activation is this
     * kind's first observable use), and a re-claim before activation —
     * the dropped-response case — RE-KEYS the same pending row
     * (make-before-break): the fresh key is delivered, the superseded
     * plaintext no longer matches the stored ciphertext and is dead, so
     * at most one live pending delivery per code ever exists. Re-keying
     * IN PLACE (never a fresh row) keeps the rotation lineage and the
     * code linkage true.
     *
     * Returns null when the code's linked durable is not a pending hmac
     * row — every other exchange shape falls through to the durable mint.
     */
    private function deliverPendingSigningKey(OnboardingToken $code): ?JsonResponse
    {
        if ($code->durable_token_id === null || $code->durableStore() !== DurableStore::Credentials) {
            return null;
        }

        /** @var Credential|null $credential */
        $credential = Credential::query()
            ->whereKey($code->durable_token_id)
            ->lockForUpdate()
            ->first();

        if ($credential === null || $credential->kind !== CredentialKind::Hmac) {
            return null;
        }

        // A dead or already-cut-over link target delivers nothing. Mostly
        // unreachable (revocation and activation both consume the linked
        // code), so this is the defensive fail-closed answer.
        if ($credential->revoked_at !== null
            || ($credential->expires_at !== null && ! $credential->expires_at->isAfter(now()))
            || $credential->status !== CredentialStatus::Pending) {
            return ClaimError::CodeNotFound->respond('This code no longer redeems a deliverable signing key. Ask the issuer for a new one.');
        }

        $keyring = app(HmacKeyring::class);
        $rekeyed = $credential->delivered_at !== null;

        if ($rekeyed) {
            // The mid-cutover pause (SEC-V3-08): a re-key produces a
            // fresh ciphertext, and every ciphertext-producing path
            // refuses while the store carries mixed key-versions. The
            // check-through-commit exclusion against a RUNNING rewrap is
            // the writer barrier around the whole exchange (see
            // exchange()); this in-transaction check covers the rest of
            // the staged cutover window, when no sweep holds the lock.
            // The claim contract has no retry-later value, so this
            // answers as the retryable server_error.
            if ($keyring->cutoverInProgress()) {
                return ClaimError::ServerError->respond('A signing-key storage cutover is in progress on this server, so redelivery is paused. It is safe to retry shortly.');
            }

            $signingKey = bin2hex(random_bytes(32));
            $encrypted = $keyring->encrypt($signingKey);

            Credential::query()->whereKey($credential->id)->update([
                'secret_ciphertext' => $encrypted->ciphertext,
                'secret_key_version' => $encrypted->keyVersion,
            ]);
        } else {
            // First delivery: the exact key the mint (or rotation)
            // sealed away, read back through the keyring.
            $signingKey = $keyring->decrypt(
                (string) $credential->secret_ciphertext,
                $credential->secret_key_version,
            );
        }

        // Stamp the delivery generation + its fingerprint (SEC-V3-01
        // rework): the receiver quotes the fingerprint back out-of-band,
        // and activation requires EXACTLY the row's current one — so a
        // re-key between confirmation and activation makes the stale
        // confirmation refuse instead of activating a key the confirmer
        // never saw.
        $generation = $credential->delivered_generation + 1;
        $fingerprint = $keyring->deliveryFingerprint($signingKey, $generation);

        Credential::query()->whereKey($credential->id)->update([
            'delivered_at' => now(),
            'delivered_generation' => $generation,
            'delivery_fingerprint' => $fingerprint,
        ]);

        $actor = AuditActor::credentialHolder($code->id);

        $this->recorder->record(
            event: LifecycleEventType::Exchanged,
            credentialId: $credential->id,
            codeId: $code->id,
            actor: $actor,
            recipient: $code->email,
        );

        $this->recorder->record(
            event: LifecycleEventType::Delivered,
            credentialId: $credential->id,
            codeId: $code->id,
            actor: $actor,
            recipient: $code->email,
            note: $rekeyed
                ? 'redelivery: generation '.$generation.' ('.$fingerprint.'); the pending key was re-keyed and every prior delivery of this code is dead'
                : 'delivery generation '.$generation.' ('.$fingerprint.')',
        );

        // The single reveal of this delivery. The key is PENDING: the
        // receiver installs it, confirms the DELIVERY FINGERPRINT
        // out-of-band, and only the activation verb — fed that exact
        // fingerprint — cuts signing over.
        return response()->json([
            'signing_key' => $signingKey,
            'key_id' => $credential->id,
            'kind' => CredentialKind::Hmac->value,
            'status' => CredentialStatus::Pending->value,
            'delivery_fingerprint' => $fingerprint,
        ], 201);
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
    private function mintClaimCode(?string $email, string $scope, int $ttlSeconds, bool $consoleKeyAuthority = false): array
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

        // forceFill, not the create array: `console_key_authority` is
        // deliberately not mass-assignable, so it can only be set on this
        // admin-gated path and never by anything a request body reaches.
        if ($consoleKeyAuthority) {
            $codeRow->forceFill(['console_key_authority' => true])->save();
        }

        return [$claimCode, $codeRow];
    }
}
