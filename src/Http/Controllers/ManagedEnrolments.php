<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\AuthorityState;
use ArtisanBuild\BuiltForCloud\Exceptions\ManagedAuthRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\ManagedEnrolmentRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\RewrapInProgress;
use ArtisanBuild\BuiltForCloud\Hmac\HmacWriterBarrier;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCurrentOwnerCredential;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\Invitation;
use ArtisanBuild\BuiltForCloud\ManagedAuthRefusalReason;
use ArtisanBuild\BuiltForCloud\ManagedClientSecretStore;
use ArtisanBuild\BuiltForCloud\ManagedEnrolmentConflict;
use ArtisanBuild\BuiltForCloud\ManagedEnrolmentRequest;
use ArtisanBuild\BuiltForCloud\ManagedEnrolmentRequestKind;
use ArtisanBuild\BuiltForCloud\ManagedTransition;
use ArtisanBuild\BuiltForCloud\ManagedTransitionDirection;
use ArtisanBuild\BuiltForCloud\ManagedTransitions;
use ArtisanBuild\BuiltForCloud\ManagedTransitionStatus;
use ArtisanBuild\BuiltForCloud\User;
use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;
use Throwable;

/**
 * The P1 managed-enrolment verbs: enrol a pristine installation, rotate
 * the persisted managed-auth client secret, and disconnect through the
 * existing exit-transition machinery. Authenticated by
 * {@see EnsureCurrentOwnerCredential}
 * — the current ownership-linked credential, never a mere admin
 * bearer. Every response is `no-store`; the delivered secret is never
 * echoed, logged, or placed in an audit note.
 *
 * Idempotency is the retained ledger ({@see ManagedEnrolmentRequest}):
 * a caller UUID that has committed replays its committed response
 * byte-for-byte; the same UUID with different non-secret facts is a
 * `binding_conflict`, never a second mutation. The digest of a
 * presented secret is compared against the LEDGER's commit-time digest
 * — the frozen digest of the request that actually committed — so the
 * original exact request stays replayable even after later rotations
 * moved the live secret on. Ledger rows survive disconnect; every
 * later enrolment needs a fresh UUID.
 */
final class ManagedEnrolments extends OperatorRouteController
{
    private const int MAX_SAFE_INTEGER = 9_007_199_254_740_991;

    public function __construct(
        private readonly ManagedClientSecretStore $secrets,
        private readonly ManagedTransitions $transitions,
    ) {}

    public function enrol(Request $request): JsonResponse
    {
        try {
            /** @var array{enrolment_id: string, expected_generation: int, issuer: string, connection_id: string, organization_id: string, installation_id: string, authority_base_url: string, managed_client_secret: string, client_secret_generation: int} $validated */
            $validated = $this->validateBounded($request, [
                'enrolment_id' => ['required', 'string', 'uuid'],
                'expected_generation' => ['required', 'integer', 'min:1', 'max:'.self::MAX_SAFE_INTEGER],
                'issuer' => ['required', 'string', 'max:255', 'url:https'],
                'connection_id' => ['required', 'string', 'max:255'],
                'organization_id' => ['required', 'string', 'max:255'],
                'installation_id' => ['required', 'string', 'max:255'],
                'authority_base_url' => ['required', 'string', 'max:2048', function (string $attribute, mixed $value, Closure $fail): void {
                    self::httpsOrigin($value) || $fail('The authority base URL must be an HTTPS origin.');
                }],
                'managed_client_secret' => ['required', 'string', 'max:512'],
                'client_secret_generation' => ['required', 'integer', 'in:1'],
            ]);

            $replay = $this->committedReplay(
                $validated['enrolment_id'],
                ManagedEnrolmentRequestKind::Enrolment,
                $this->enrolmentFacts($validated),
                $validated['managed_client_secret'],
                withReason: false,
            );

            if ($replay !== null) {
                return $replay;
            }

            return app(HmacWriterBarrier::class)->locked(
                write: fn (): JsonResponse => DB::transaction(function () use ($validated): JsonResponse {
                    $authority = DB::table('bfc_authority')
                        ->where('key', InstallationAuthority::KEY)
                        ->lockForUpdate()
                        ->first();

                    if (! is_object($authority)) {
                        throw $this->refuse(ManagedEnrolmentConflict::NotPristine);
                    }

                    if ($authority->mode === AuthorityMode::Managed->value) {
                        throw $this->refuse(ManagedEnrolmentConflict::AlreadyManaged);
                    }

                    $this->assertPristine($authority);

                    if ((int) $authority->generation !== $validated['expected_generation']) {
                        throw $this->refuse(ManagedEnrolmentConflict::StaleGeneration);
                    }

                    // One locked transaction: secret custody, the five
                    // binding facts, and the CAS standalone/N →
                    // managed/N+1 — the database trigger's rule is the
                    // wire rule. Nothing partial survives a refusal.
                    $this->secrets->install($validated['managed_client_secret']);

                    DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->update([
                        'issuer' => $validated['issuer'],
                        'connection_id' => $validated['connection_id'],
                        'organization_id' => $validated['organization_id'],
                        'installation_id' => $validated['installation_id'],
                        'authority_base_url' => $validated['authority_base_url'],
                        'updated_at' => now(),
                    ]);

                    $changed = InstallationAuthority::change(
                        AuthorityState::fromRaw($authority->mode, (int) $authority->generation),
                        AuthorityMode::Managed,
                    );

                    if ($changed === null) {
                        throw $this->refuse(ManagedEnrolmentConflict::StaleGeneration);
                    }

                    $response = [
                        'enrolment_id' => $validated['enrolment_id'],
                        'mode' => $changed->mode->value,
                        'generation' => $changed->generation,
                        'client_secret_generation' => 1,
                        'enrolled_at' => now()->toISOString(),
                    ];

                    ManagedEnrolmentRequest::query()->create([
                        'id' => $validated['enrolment_id'],
                        'kind' => ManagedEnrolmentRequestKind::Enrolment,
                        'issuer' => $validated['issuer'],
                        'connection_id' => $validated['connection_id'],
                        'installation_id' => $validated['installation_id'],
                        'organization_id' => $validated['organization_id'],
                        'authority_base_url' => $validated['authority_base_url'],
                        'expected_generation' => $validated['expected_generation'],
                        'expected_client_secret_generation' => $validated['client_secret_generation'],
                        'secret_retry_digest' => $this->secrets->retryDigest($validated['managed_client_secret'], 1),
                        'committed_response' => $response,
                        'committed_at' => now(),
                    ]);

                    return $this->json($response, 201);
                }),
                onBusy: fn (): JsonResponse => $this->conflictResponse(ManagedEnrolmentConflict::KeyCutoverInProgress, withReason: false),
            );
        } catch (ManagedEnrolmentRefused $refused) {
            return $this->refusedResponse($refused);
        } catch (ManagedAuthRefused $refused) {
            // The store's own fail-closed backstops (double install,
            // stale CAS, missing row) surface here.
            return $this->conflictResponse($this->storeConflict($refused), withReason: false);
        } catch (RewrapInProgress) {
            return $this->conflictResponse(ManagedEnrolmentConflict::KeyCutoverInProgress, withReason: false);
        }
    }

    public function rotateClientSecret(Request $request): JsonResponse
    {
        try {
            /** @var array{rotation_id: string, issuer: string, connection_id: string, installation_id: string, expected_generation: int, expected_client_secret_generation: int, managed_client_secret: string} $validated */
            $validated = $this->validateBounded($request, [
                'rotation_id' => ['required', 'string', 'uuid'],
                'issuer' => ['required', 'string', 'max:255', 'url:https'],
                'connection_id' => ['required', 'string', 'max:255'],
                'installation_id' => ['required', 'string', 'max:255'],
                'expected_generation' => ['required', 'integer', 'min:1', 'max:'.self::MAX_SAFE_INTEGER],
                'expected_client_secret_generation' => ['required', 'integer', 'min:1', 'max:'.self::MAX_SAFE_INTEGER],
                'managed_client_secret' => ['required', 'string', 'max:512'],
            ]);

            $replay = $this->committedReplay(
                $validated['rotation_id'],
                ManagedEnrolmentRequestKind::ClientSecretRotation,
                $this->rotationFacts($validated),
                $validated['managed_client_secret'],
                withReason: false,
            );

            if ($replay !== null) {
                return $replay;
            }

            return app(HmacWriterBarrier::class)->locked(
                write: fn (): JsonResponse => DB::transaction(function () use ($validated): JsonResponse {
                    $authority = $this->lockedManagedAuthority();

                    if ($this->bindingTriple($authority) !== [$validated['issuer'], $validated['connection_id'], $validated['installation_id']]) {
                        throw $this->refuse(ManagedEnrolmentConflict::BindingConflict);
                    }

                    $this->assertNoActiveTransition();

                    if ((int) $authority->generation !== $validated['expected_generation']) {
                        throw $this->refuse(ManagedEnrolmentConflict::StaleGeneration);
                    }

                    // The compare-and-swap on the secret row's OWN
                    // counter: the authority generation never moves
                    // here. Rotation mid-rewrap refuses retry-later.
                    $generation = $this->secrets->rotate($validated['expected_client_secret_generation'], $validated['managed_client_secret']);

                    $response = [
                        'rotation_id' => $validated['rotation_id'],
                        'mode' => AuthorityMode::Managed->value,
                        'generation' => (int) $authority->generation,
                        'client_secret_generation' => $generation,
                        'rotated_at' => now()->toISOString(),
                    ];

                    ManagedEnrolmentRequest::query()->create([
                        'id' => $validated['rotation_id'],
                        'kind' => ManagedEnrolmentRequestKind::ClientSecretRotation,
                        'issuer' => $validated['issuer'],
                        'connection_id' => $validated['connection_id'],
                        'installation_id' => $validated['installation_id'],
                        'expected_generation' => $validated['expected_generation'],
                        'expected_client_secret_generation' => $validated['expected_client_secret_generation'],
                        'secret_retry_digest' => $this->secrets->retryDigest($validated['managed_client_secret'], $generation),
                        'committed_response' => $response,
                        'committed_at' => now(),
                    ]);

                    return $this->json($response);
                }),
                onBusy: fn (): JsonResponse => $this->conflictResponse(ManagedEnrolmentConflict::KeyCutoverInProgress, withReason: false),
            );
        } catch (ManagedEnrolmentRefused $refused) {
            return $this->refusedResponse($refused);
        } catch (ManagedAuthRefused $refused) {
            return $this->conflictResponse($this->storeConflict($refused), withReason: false);
        } catch (RewrapInProgress) {
            return $this->conflictResponse(ManagedEnrolmentConflict::KeyCutoverInProgress, withReason: false);
        }
    }

    public function disconnect(Request $request): JsonResponse
    {
        try {
            /** @var array{disconnect_id: string, issuer: string, connection_id: string, installation_id: string, expected_generation: int} $validated */
            $validated = $this->validateBounded($request, [
                'disconnect_id' => ['required', 'string', 'uuid'],
                'issuer' => ['required', 'string', 'max:255', 'url:https'],
                'connection_id' => ['required', 'string', 'max:255'],
                'installation_id' => ['required', 'string', 'max:255'],
                'expected_generation' => ['required', 'integer', 'min:1', 'max:'.self::MAX_SAFE_INTEGER],
            ]);

            $existing = ManagedEnrolmentRequest::query()->find($validated['disconnect_id']);

            if ($existing !== null) {
                if ($existing->kind !== ManagedEnrolmentRequestKind::Disconnect
                    || $this->disconnectFacts($existing) !== $this->disconnectFacts($validated)) {
                    throw $this->refuse(ManagedEnrolmentConflict::BindingConflict, withReason: true);
                }

                if ($existing->committed_response !== null) {
                    return $this->json($existing->committed_response);
                }
            }

            // The initiating actor: the single active local Owner
            // (the installation-wide owner slot). Accessibility is NOT
            // preflighted here — ruling A1 pins the refusal on the
            // exit path's own roster/mapping guard, evaluated with the
            // fetched roster in hand (the roster's verification of the
            // Owner's address is the deciding bit on an install where
            // nobody has a local password or verified email).
            $actor = $this->exitActor();

            if ($actor === null) {
                throw $this->refuse(ManagedEnrolmentConflict::OwnerNotAccessible, withReason: true);
            }

            // Exact retries resume the recorded transition while it is
            // still live. A guard-refused disconnect durably abandoned
            // its row (below), so its retry — typically after the
            // operator repaired the Owner's reachability — prepares a
            // FRESH transition and re-points the ledger link at it.
            $transition = null;

            if ($existing !== null && is_string($existing->managed_transition_id)) {
                $candidate = ManagedTransition::query()->find($existing->managed_transition_id);

                if ($candidate !== null
                    && ! in_array($candidate->status, [ManagedTransitionStatus::Acknowledged, ManagedTransitionStatus::Abandoned], true)) {
                    $transition = $candidate;
                }
            }

            // A fresh request — or a retry whose recorded transition is
            // no longer resumable (nothing linked, or the row durably
            // abandoned or already acknowledged) — revalidates against
            // CURRENT locked authority before preparing anything: managed
            // mode, the request/ledger binding triple, the recorded
            // expected generation, and no other active transition.
            // Without this, an abandoned request recorded against an
            // earlier binding could exit a LATER disconnect/re-adopt
            // lifecycle it never named (quality-review round 1). A live
            // resume is deliberately exempt — its transition already
            // carries the locked snapshot it drives on.
            if ($existing === null || $transition === null) {
                $authority = $this->lockedManagedAuthority();

                if ($this->bindingTriple($authority) !== [$validated['issuer'], $validated['connection_id'], $validated['installation_id']]) {
                    throw $this->refuse(ManagedEnrolmentConflict::BindingConflict, withReason: true);
                }

                if ((int) $authority->generation !== $validated['expected_generation']) {
                    throw $this->refuse(ManagedEnrolmentConflict::StaleGeneration, withReason: true);
                }

                $this->assertNoActiveTransition();
            }

            if ($transition === null) {
                try {
                    $transition = $this->transitions->prepare($actor, ManagedTransitionDirection::Exit);
                } catch (ManagedAuthRefused $refused) {
                    throw $this->fromTransitionRefusal($refused);
                } catch (Throwable) {
                    // A crash between the transition's creation and its
                    // first authority leg leaves a resumable row this
                    // request can no longer name — link it into the ledger
                    // and answer pending, so the exact retry drives it on
                    // instead of discovering a transition it cannot reach.
                    $stuck = $this->activeTransition();

                    if ($stuck === null) {
                        throw new ManagedEnrolmentRefused(ManagedEnrolmentConflict::TransitionInProgress, withReason: true);
                    }

                    if ($existing === null) {
                        ManagedEnrolmentRequest::query()->create([
                            'id' => $validated['disconnect_id'],
                            'kind' => ManagedEnrolmentRequestKind::Disconnect,
                            'issuer' => $validated['issuer'],
                            'connection_id' => $validated['connection_id'],
                            'installation_id' => $validated['installation_id'],
                            'expected_generation' => $validated['expected_generation'],
                            'managed_transition_id' => $stuck->id,
                        ]);
                    }

                    return $this->json($this->pendingDisconnect($validated['disconnect_id'], $stuck), 202);
                }
            }

            if ($existing === null) {
                ManagedEnrolmentRequest::query()->create([
                    'id' => $validated['disconnect_id'],
                    'kind' => ManagedEnrolmentRequestKind::Disconnect,
                    'issuer' => $validated['issuer'],
                    'connection_id' => $validated['connection_id'],
                    'installation_id' => $validated['installation_id'],
                    'expected_generation' => $validated['expected_generation'],
                    'managed_transition_id' => $transition->id,
                ]);
            } elseif ($transition->id !== $existing->managed_transition_id) {
                $existing->forceFill(['managed_transition_id' => $transition->id])->save();
            }

            try {
                $transition = $this->driveExit($actor, $transition);
            } catch (ManagedAuthRefused $refused) {
                if ($refused->recordsFailedAttempt) {
                    // An AUTHORITY-side failure the client wraps —
                    // transport or an authority refusal on a leg. The
                    // disconnect is durably in flight either way: answer
                    // pending; the exact retry resumes, the abandon
                    // route remains reachable before commit.
                    return $this->json($this->pendingDisconnect($validated['disconnect_id'], $transition->refresh()), 202);
                }

                if ($refused->reason === ManagedAuthRefusalReason::OwnerNotAccessible) {
                    // Ruling A1: the exit roster/mapping guard refused
                    // with the fetched roster in hand. The commit rolled
                    // back (authority untouched); the transition row is
                    // durably abandoned — never left active — and the
                    // retry prepares a fresh one.
                    return $this->abandonGuardedDisconnect($actor, $validated['disconnect_id'], $transition);
                }

                throw $this->fromTransitionRefusal($refused);
            } catch (RewrapInProgress $refused) {
                throw $this->refuse(ManagedEnrolmentConflict::KeyCutoverInProgress, withReason: true);
            } catch (Throwable) {
                // Durable pending state (202): the transition has landed
                // in a resumable phase and the exact retry drives it on.
                return $this->json($this->pendingDisconnect($validated['disconnect_id'], $transition->refresh()), 202);
            }

            if ($transition->status !== ManagedTransitionStatus::Acknowledged) {
                return $this->json($this->pendingDisconnect($validated['disconnect_id'], $transition), 202);
            }

            return $this->json($this->completeDisconnect($validated['disconnect_id']));
        } catch (ManagedEnrolmentRefused $refused) {
            return $this->refusedResponse($refused);
        }
    }

    /**
     * Advance an exit transition toward its terminal state,
     * idempotently: the same ladder a resume walks from any durable
     * phase.
     */
    private function driveExit(User $actor, ManagedTransition $transition): ManagedTransition
    {
        if ($transition->status === ManagedTransitionStatus::Preparing) {
            $transition = $this->transitions->recover($transition);
        }

        if ($transition->status === ManagedTransitionStatus::Prepared) {
            $transition = $this->transitions->fetchRoster($transition);
        }

        if ($transition->status === ManagedTransitionStatus::Rostered) {
            $transition = $this->transitions->proposeDefault($transition);
        }

        return $this->transitions->complete($actor, $transition);
    }

    /**
     * Post-acknowledgement cleanup, one transaction: the persisted
     * secret and the five connection facts leave storage together with
     * the ledger's committed outcome. Idempotency history is RETAINED —
     * every later enrolment needs a fresh UUID.
     *
     * @return array<string, mixed>
     */
    private function completeDisconnect(string $disconnectId): array
    {
        $authority = InstallationAuthority::current();

        $response = [
            'disconnect_id' => $disconnectId,
            'status' => 'completed',
            'mode' => $authority->mode->value,
            'generation' => $authority->generation,
            'disconnected_at' => now()->toISOString(),
        ];

        DB::transaction(function () use ($disconnectId, $response): void {
            $this->secrets->clear();

            DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->update([
                'issuer' => null,
                'connection_id' => null,
                'organization_id' => null,
                'installation_id' => null,
                'authority_base_url' => null,
                'updated_at' => now(),
            ]);

            ManagedEnrolmentRequest::query()->whereKey($disconnectId)->update([
                'committed_response' => $response,
                'committed_at' => now(),
            ]);
        });

        return $response;
    }

    /**
     * The durable pending state (202): the transition id an operator
     * can watch or abandon (before commit), the CURRENT authority
     * state, and the transition's durable phase.
     *
     * @return array<string, mixed>
     */
    private function pendingDisconnect(string $disconnectId, ManagedTransition $transition): array
    {
        $authority = InstallationAuthority::current();

        return [
            'disconnect_id' => $disconnectId,
            'status' => 'pending',
            'transition_id' => $transition->id,
            'mode' => $authority->mode->value,
            'generation' => $authority->generation,
            'phase' => match ($transition->status) {
                ManagedTransitionStatus::Preparing,
                ManagedTransitionStatus::Prepared,
                ManagedTransitionStatus::Rostered,
                ManagedTransitionStatus::Proposed => 'prepared',
                ManagedTransitionStatus::Staging,
                ManagedTransitionStatus::Staged => 'staged',
                ManagedTransitionStatus::Committed => 'committed',
                ManagedTransitionStatus::Acknowledging,
                ManagedTransitionStatus::Acknowledged,
                ManagedTransitionStatus::Abandoned => 'acknowledging',
            },
        ];
    }

    /**
     * Exact-retry replay against the RETAINED ledger. A known caller
     * UUID replays its committed response only when the presented
     * non-secret facts AND the digest of the presented secret match the
     * LEDGER's commit-time record — the frozen digest of the request
     * that committed, so the original exact request stays replayable
     * even after later rotations replaced the live secret. Anything
     * else under a known UUID is a binding conflict; a committed
     * outcome whose connection the authority has since left is a
     * conflict too (state moved on — never a rollback).
     *
     * @param  array<string, int|string|null>  $facts
     */
    private function committedReplay(string $requestId, ManagedEnrolmentRequestKind $kind, array $facts, string $secret, bool $withReason): ?JsonResponse
    {
        /** @var ManagedEnrolmentRequest|null $row */
        $row = ManagedEnrolmentRequest::query()->find($requestId);

        if ($row === null || $row->committed_response === null) {
            return null;
        }

        $recorded = [
            'kind' => $row->kind->value,
            'issuer' => $row->issuer,
            'connection_id' => $row->connection_id,
            'installation_id' => $row->installation_id,
            'organization_id' => $row->organization_id,
            'authority_base_url' => $row->authority_base_url,
            'expected_generation' => (int) $row->expected_generation,
            'expected_client_secret_generation' => $row->expected_client_secret_generation === null ? null : (int) $row->expected_client_secret_generation,
        ];

        // The digest generation is the generation the COMMIT landed at:
        // 1 for an enrolment, expected+1 for a rotation.
        $digestGeneration = $kind === ManagedEnrolmentRequestKind::ClientSecretRotation
            ? ((int) $recorded['expected_client_secret_generation']) + 1
            : 1;

        if ($recorded !== $facts
            || ! hash_equals((string) $row->secret_retry_digest, $this->secrets->retryDigest($secret, $digestGeneration))) {
            return $this->conflictResponse(ManagedEnrolmentConflict::BindingConflict, $withReason);
        }

        // The committed outcome is only replayable while the authority
        // still carries that connection: after disconnect (or a later
        // enrolment elsewhere) the state has moved past this row.
        $authority = DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->first();

        if (! is_object($authority)
            || $authority->mode !== AuthorityMode::Managed->value
            || $authority->issuer !== $row->issuer
            || $authority->connection_id !== $row->connection_id
            || $authority->installation_id !== $row->installation_id) {
            return $this->conflictResponse(ManagedEnrolmentConflict::BindingConflict, $withReason);
        }

        return $this->json($row->committed_response);
    }

    /**
     * @param  array<string, int|string>  $validated
     * @return array<string, int|string|null>
     */
    private function enrolmentFacts(array $validated): array
    {
        return [
            'kind' => ManagedEnrolmentRequestKind::Enrolment->value,
            'issuer' => $validated['issuer'],
            'connection_id' => $validated['connection_id'],
            'installation_id' => $validated['installation_id'],
            'organization_id' => $validated['organization_id'],
            'authority_base_url' => $validated['authority_base_url'],
            'expected_generation' => $validated['expected_generation'],
            'expected_client_secret_generation' => $validated['client_secret_generation'],
        ];
    }

    /**
     * @param  array<string, int|string>  $validated
     * @return array<string, int|string|null>
     */
    private function rotationFacts(array $validated): array
    {
        return [
            'kind' => ManagedEnrolmentRequestKind::ClientSecretRotation->value,
            'issuer' => $validated['issuer'],
            'connection_id' => $validated['connection_id'],
            'installation_id' => $validated['installation_id'],
            'organization_id' => null,
            'authority_base_url' => null,
            'expected_generation' => $validated['expected_generation'],
            'expected_client_secret_generation' => $validated['expected_client_secret_generation'],
        ];
    }

    /**
     * @param  array{issuer: string, connection_id: string, installation_id: string, expected_generation: int}|ManagedEnrolmentRequest  $row
     * @return array{issuer: string, connection_id: string, installation_id: string, expected_generation: int}
     */
    private function disconnectFacts(array|ManagedEnrolmentRequest $row): array
    {
        return [
            'issuer' => (string) ($row instanceof ManagedEnrolmentRequest ? $row->issuer : $row['issuer']),
            'connection_id' => (string) ($row instanceof ManagedEnrolmentRequest ? $row->connection_id : $row['connection_id']),
            'installation_id' => (string) ($row instanceof ManagedEnrolmentRequest ? $row->installation_id : $row['installation_id']),
            'expected_generation' => (int) ($row instanceof ManagedEnrolmentRequest ? $row->expected_generation : $row['expected_generation']),
        ];
    }

    private function assertPristine(object $authority): void
    {
        if (User::query()->exists()
            || Invitation::query()->pending()->exists()
            || $authority->issuer !== null
            || $authority->connection_id !== null
            || $authority->organization_id !== null
            || $authority->installation_id !== null
            || $authority->authority_base_url !== null
            || $this->secrets->exists()) {
            throw $this->refuse(ManagedEnrolmentConflict::NotPristine);
        }

        $this->assertNoActiveTransition();
    }

    private function assertNoActiveTransition(): void
    {
        if ($this->activeTransition() !== null) {
            throw $this->refuse(ManagedEnrolmentConflict::TransitionInProgress);
        }
    }

    private function activeTransition(): ?ManagedTransition
    {
        /** @var ManagedTransition|null $transition */
        $transition = ManagedTransition::query()
            ->whereNotIn('status', [ManagedTransitionStatus::Acknowledged->value, ManagedTransitionStatus::Abandoned->value])
            ->orderByDesc('created_at')
            ->orderByDesc('id')
            ->first();

        return $transition;
    }

    private function lockedManagedAuthority(): object
    {
        $authority = DB::table('bfc_authority')
            ->where('key', InstallationAuthority::KEY)
            ->lockForUpdate()
            ->first();

        if (! is_object($authority) || $authority->mode !== AuthorityMode::Managed->value) {
            throw $this->refuse(ManagedEnrolmentConflict::NotManaged);
        }

        return $authority;
    }

    /** @return list<string> */
    private function bindingTriple(object $authority): array
    {
        return [(string) $authority->issuer, (string) $authority->connection_id, (string) $authority->installation_id];
    }

    /**
     * The initiating actor for the exit path: the single active local
     * Owner (the unique installation-wide owner slot). The transition
     * machinery re-asserts this under lock at prepare and commit. This
     * is deliberately NOT an accessibility check — ruling A1 pins the
     * owner_not_accessible refusal on the exit path's own roster
     * mapping guard, not on a local preflight.
     */
    private function exitActor(): ?User
    {
        /** @var User|null $owner */
        $owner = User::query()
            ->whereNotNull('owner_slot')
            ->where('status', 'active')
            ->first();

        return $owner;
    }

    /**
     * Complete the A1 refusal: durably abandon the guard-refused
     * transition through the same legs the Owner abandon route walks
     * (authority state check, keyed abandon call, local status
     * advance), then answer the bounded 409. If the abandonment legs
     * are themselves unreachable, the disconnect stays durably in
     * flight (202) — the pre-commit abandon route remains the remedy.
     */
    private function abandonGuardedDisconnect(User $actor, string $disconnectId, ManagedTransition $transition): JsonResponse
    {
        try {
            // The guard refused inside the commit transaction: the row
            // advanced to its durable pre-commit phase while the caught
            // model may lag — re-read it before the abandonment legs.
            $this->transitions->abandonPreCommit($actor, $transition->refresh());
        } catch (Throwable) {
            return $this->json($this->pendingDisconnect($disconnectId, $transition->refresh()), 202);
        }

        throw $this->refuse(ManagedEnrolmentConflict::OwnerNotAccessible, withReason: true);
    }

    private function fromTransitionRefusal(ManagedAuthRefused $refused): ManagedEnrolmentRefused
    {
        $conflict = match ($refused->getMessage()) {
            'transition_in_progress' => ManagedEnrolmentConflict::TransitionInProgress,
            'transition_state_conflict' => ManagedEnrolmentConflict::StaleGeneration,
            default => ManagedEnrolmentConflict::OwnerNotAccessible,
        };

        return $this->refuse($conflict, withReason: true);
    }

    /** The custody store's backstop refusals, mapped onto the same vocabulary. */
    private function storeConflict(ManagedAuthRefused $refused): ManagedEnrolmentConflict
    {
        return match ($refused->getMessage()) {
            'stale_generation' => ManagedEnrolmentConflict::StaleGeneration,
            'not_managed' => ManagedEnrolmentConflict::NotManaged,
            'already_managed' => ManagedEnrolmentConflict::AlreadyManaged,
            default => ManagedEnrolmentConflict::BindingConflict,
        };
    }

    private function refuse(ManagedEnrolmentConflict $conflict, bool $withReason = false): ManagedEnrolmentRefused
    {
        return new ManagedEnrolmentRefused($conflict, $withReason);
    }

    private function refusedResponse(ManagedEnrolmentRefused $refused): JsonResponse
    {
        return $this->conflictResponse($refused->conflict, $refused->withReason);
    }

    private function conflictResponse(ManagedEnrolmentConflict $conflict, bool $withReason): JsonResponse
    {
        $body = array_filter([
            'error' => $conflict->value,
            'reason' => $withReason ? $conflict->value : null,
            'message' => match ($conflict) {
                ManagedEnrolmentConflict::OwnerNotAccessible => 'No single accessible local Owner would remain to receive this installation.',
                ManagedEnrolmentConflict::TransitionInProgress => 'A managed transition is already active for this installation.',
                ManagedEnrolmentConflict::BindingConflict => 'The request binding disagrees with locked stored state for this caller UUID.',
                ManagedEnrolmentConflict::StaleGeneration => 'An expected generation counter disagrees with locked stored state.',
                ManagedEnrolmentConflict::NotManaged => 'This installation is not managed.',
                ManagedEnrolmentConflict::AlreadyManaged => 'This installation is already managed.',
                ManagedEnrolmentConflict::NotPristine => 'This installation is not pristine; use the Owner-driven adopt path.',
                ManagedEnrolmentConflict::KeyCutoverInProgress => 'A staged APP_KEY rewrap holds the writer barrier; retry once it completes.',
            },
        ], static fn (mixed $value): bool => $value !== null);

        return $this->json($body, 409);
    }

    /** @param array<string, mixed> $response */
    private function json(array $response, int $status = 200): JsonResponse
    {
        return response()->json($response, $status)->header('Cache-Control', 'no-store');
    }

    /**
     * Bounded input: the declared fields validated, and NOTHING else —
     * an unknown key is refused before any secret-bearing payload goes
     * further. Validation messages never reflect values.
     *
     * @param  array<string, list<string|Closure>>  $rules
     * @return array<string, mixed>
     */
    private function validateBounded(Request $request, array $rules): array
    {
        if (array_diff(array_keys($request->input()), array_keys($rules)) !== []) {
            throw ValidationException::withMessages(['request' => 'The request carries unknown fields.']);
        }

        return $request->validate($rules);
    }

    private static function httpsOrigin(mixed $value): bool
    {
        if (! is_string($value) || $value === '') {
            return false;
        }

        $parts = parse_url($value);

        return is_array($parts)
            && ($parts['scheme'] ?? null) === 'https'
            && is_string($parts['host'] ?? null)
            && $parts['host'] !== ''
            && ! array_key_exists('query', $parts)
            && ! array_key_exists('fragment', $parts)
            && ! array_key_exists('user', $parts)
            && ! array_key_exists('pass', $parts)
            && in_array($parts['path'] ?? '', ['', '/'], true);
    }
}
