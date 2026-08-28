<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Actions;

use ArtisanBuild\BuiltForCloud\Actions\Concerns\ConsultsDeclaration;
use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\AuditReason;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialVerb;
use ArtisanBuild\BuiltForCloud\DurableStore;
use ArtisanBuild\BuiltForCloud\Exceptions\CredentialVerbRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\IntegrationEventContention;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use ArtisanBuild\BuiltForCloud\IntegrationEntitlement;
use ArtisanBuild\BuiltForCloud\IntegrationEvent;
use ArtisanBuild\BuiltForCloud\Invitation;
use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\OffboardedSubject;
use ArtisanBuild\BuiltForCloud\OffboardOptions;
use ArtisanBuild\BuiltForCloud\OffboardResult;
use ArtisanBuild\BuiltForCloud\OnboardingToken;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Throwable;

/**
 * The offboard verb — FULL ACCOUNT CONTAINMENT (PRD 1.15, SEC-V3-04):
 * ONE implementation consumed by BOTH transports
 * (`bfc:subject:offboard --local` and `POST /bfc/subjects/offboard`).
 * Deactivate a subject and, in one action:
 *
 * - revoke EVERY bound credential in EVERY lifecycle state — active,
 *   rotation-grace, and pending (unexchanged enrollments and pending
 *   hmac signing keys included), in BOTH stores (`credentials` and
 *   subject-stamped `api_tokens` rows);
 * - consume the outstanding claim codes and cancel the pending
 *   invitations addressed to the principal (and, for an
 *   integration-driven offboard, its namespace+subject history);
 * - delete the principal's password-reset tokens;
 * - invalidate sessions (below); and
 * - write the containment REGISTRY rows ({@see OffboardedSubject}), on
 *   which the `bfc` guard and the auth-foundation middleware reject the
 *   offboarded subject and its deactivated bound users on every request
 *   thereafter.
 *
 * SESSION COMPENSATION, stated (the PRD demands the statement): only a
 * database session store on the DEFAULT connection can share the
 * credential transaction — those rows are deleted atomically with the
 * revocations. A database store on ANOTHER connection is deleted in an
 * after-commit hook (it cannot join the transaction), and any other
 * driver's storage cannot be enumerated per user at all. Every such case
 * is SURFACED, never silent (rework Fix 3): the result's
 * `incompleteSteps` names it, the direct-path response reports
 * `fully_contained: false`, and a deferred delete's failure is logged
 * class-only. The registry row — which DOES commit with the revocations
 * — is the containment either way: the `bfc` guard, the operator gate,
 * the hmac verifier, and the auth-foundation middleware (`bfc.auth` AND
 * `bfc.admin`) reject the principal whatever still sits in session
 * storage, invalidating a surviving session on its first appearance.
 * THE HONEST BOUNDARY: a consuming app's OWN plain `auth`-guarded routes
 * are outside the package's reach — the app must consult
 * {@see OffboardedSubject::userIsOffboarded} (or stack the package
 * middleware) on them; the package cannot invalidate an arbitrary
 * session store it does not own.
 *
 * IDEMPOTENT: a second offboard of a contained subject is a no-op — the
 * same result shape with zero counts, and NO duplicate audit rows (one
 * death, one event, exactly as the revoke verb behaves).
 *
 * The integration path (an operator's system emits `offboarded` events)
 * rides PR8's SHARED version gate tables: `event_kind` `offboard` in the
 * same `integration_events` / `integration_entitlements` the invite verb
 * uses, so one monotonic entitlement version per (namespace, external
 * subject) orders invites and offboards TOGETHER — an offboard event
 * older than the version an invite already advanced is transactionally
 * acknowledged-and-ignored, and a replayed event id answers idempotently.
 * The uniform acknowledgement reveals nothing about the decision.
 */
final class OffboardSubject
{
    use ConsultsDeclaration;

    public const string EVENT_KIND = 'offboard';

    /**
     * The principal-traversal hard ceiling (rework 3 Fix 3): discovery
     * iterates to a FIXED POINT (a round that adds no new principal ends
     * the walk — cycles terminate naturally because a known user is never
     * "new"), and this ceiling only exists so pathological data cannot
     * loop unbounded. Each round discovers at least one new account or
     * stops, so the ceiling equals the longest accepted-invitation chain
     * the walk will follow; hitting it is SURFACED as an incomplete step,
     * never silently truncated.
     */
    public const int PRINCIPAL_TRAVERSAL_CEILING = 100;

    public function __construct(private readonly LifecycleEventRecorder $recorder) {}

    public function __invoke(OffboardOptions $options, ?AuditActor $actor = null): OffboardResult
    {
        if ($options->carriesIntegrationEvent() && ! $options->integrationEventComplete()) {
            throw InvalidCredentialInput::partialIntegrationEvent();
        }

        if ($options->entitlementVersion !== null
            && ($options->entitlementVersion < 1 || $options->entitlementVersion > IssueInvitation::MAX_ENTITLEMENT_VERSION)) {
            throw InvalidCredentialInput::entitlementVersionOutOfBounds();
        }

        $subject = $this->targetSubject($options);

        if (! $this->verbAllowed(CredentialVerb::Offboard, $subject)) {
            throw CredentialVerbRefused::byMatrix(CredentialVerb::Offboard);
        }

        // BOTH paths ride the bounded contention rescue: each retry
        // re-decides in a fresh transaction against whatever a concurrent
        // writer committed — a gate-row race on the integration path, or
        // the registry's unique subject key on a concurrent first
        // offboard (rework Fix 6; the retry re-reads the winner's row as
        // already-contained). No attempt leaves partial state.
        $decide = $options->integrationEventComplete()
            ? fn (): OffboardResult => $this->decideIntegrationEvent($options, $subject, $actor)
            : fn (): OffboardResult => $this->contain($subject, $actor);

        for ($attempt = 1; $attempt <= IssueInvitation::GATE_ATTEMPTS; $attempt++) {
            try {
                /** @var OffboardResult */
                return DB::transaction($decide);
            } catch (UniqueConstraintViolationException) {
                // Loop; the next attempt re-decides from scratch.
            }
        }

        throw IntegrationEventContention::afterAttempts(IssueInvitation::GATE_ATTEMPTS);
    }

    /**
     * The offboard TARGET (rework Fix 4). Direct path: the caller-named
     * subject (required by the options). Integration path: DERIVED
     * server-side from the gated (namespace, external_subject) identity —
     * `Subject(external_consumer, external_subject)`, the exact binding
     * {@see IssueInvitation::subjectFor} uses — so the identity the
     * version gate checks IS the identity that gets contained; a decoy
     * external_subject can never pass its own (empty) gate while a
     * different victim named in subject_ref is offboarded. A supplied
     * subject pair on the integration path must MATCH the derivation or
     * the whole request is refused.
     */
    private function targetSubject(OffboardOptions $options): Subject
    {
        if (! $options->integrationEventComplete()) {
            if ($options->subjectType === null || $options->subjectRef === null) {
                // Unreachable through fromInput(); the fail-closed answer
                // for a hand-constructed options object.
                throw InvalidCredentialInput::missingSubjectRef();
            }

            return new Subject($options->subjectType, $options->subjectRef);
        }

        $externalSubject = (string) $options->externalSubject;

        if (($options->subjectType !== null && $options->subjectType !== SubjectType::ExternalConsumer)
            || ($options->subjectRef !== null && $options->subjectRef !== $externalSubject)) {
            throw InvalidCredentialInput::integrationSubjectMismatch();
        }

        return new Subject(SubjectType::ExternalConsumer, $externalSubject);
    }

    /**
     * The SEC-V3-05 gate, verbatim in shape from the invite verb, with
     * this verb's event kind: replayed event ids answer first and
     * idempotently; a version not newer than the latest accepted for the
     * (namespace, external subject) is recorded and IGNORED — the
     * containment does not run; a newer version advances the shared
     * entitlement row and applies. Every branch answers the same uniform
     * acknowledgement.
     */
    private function decideIntegrationEvent(OffboardOptions $options, Subject $subject, ?AuditActor $actor): OffboardResult
    {
        $replayed = IntegrationEvent::query()
            ->where('integration_namespace', $options->integrationNamespace)
            ->where('event_id', $options->eventId)
            ->lockForUpdate()
            ->exists();

        if ($replayed) {
            return OffboardResult::acknowledged();
        }

        /** @var IntegrationEntitlement|null $entitlement */
        $entitlement = IntegrationEntitlement::query()
            ->where('integration_namespace', $options->integrationNamespace)
            ->where('external_subject', $options->externalSubject)
            ->lockForUpdate()
            ->first();

        // The gate and the TARGET are one identity (rework 3 Fix 2). The
        // contained subject is the bare external_subject (PR8's invite
        // binding), but every gate effect is keyed on the (namespace,
        // external_subject) PAIR — so a namespace with NO entitlement
        // history for an external subject that already has history under
        // another namespace is REFUSED: a decoy namespace cannot ride its
        // own empty gate to contain a victim whose real gate stands at a
        // higher version. A namespace that HAS its own history is ordered
        // by that history exactly as before (several namespaces may
        // legitimately share an external-subject string; each is bound by
        // its own gate once established). Nothing is recorded or advanced
        // on the refusal.
        if ($entitlement === null) {
            $boundElsewhere = IntegrationEntitlement::query()
                ->where('external_subject', $options->externalSubject)
                ->where('integration_namespace', '!=', $options->integrationNamespace)
                ->exists();

            if ($boundElsewhere) {
                throw InvalidCredentialInput::integrationNamespaceNotBound();
            }
        }

        if ($entitlement !== null && $options->entitlementVersion <= $entitlement->entitlement_version) {
            $this->recordEvent($options, applied: false);

            return OffboardResult::acknowledged();
        }

        if ($entitlement === null) {
            IntegrationEntitlement::query()->create([
                'integration_namespace' => $options->integrationNamespace,
                'external_subject' => $options->externalSubject,
                'entitlement_version' => $options->entitlementVersion,
            ]);
        } else {
            $entitlement->forceFill(['entitlement_version' => $options->entitlementVersion])->save();
        }

        $contained = $this->contain($subject, $actor, $options->integrationNamespace);

        // An applying offboard also cancels every pending invitation its
        // own (namespace, subject) history issued — a stolen invite code
        // must not outlive the offboard event.
        $this->cancelPendingInvitations(
            Invitation::query()->whereIn('id', IntegrationEvent::query()
                ->where('integration_namespace', $options->integrationNamespace)
                ->where('external_subject', $options->externalSubject)
                ->where('applied', true)
                ->whereNotNull('invitation_id')
                ->pluck('invitation_id')
                ->all()),
        );

        $this->recordEvent($options, applied: true);

        // The containment status rides the acknowledgement (rework 3
        // fold): an applying event that could not complete a step reports
        // it exactly like the direct path — never a clean ack for an
        // incomplete sweep.
        return OffboardResult::acknowledged($contained->incompleteSteps);
    }

    private function recordEvent(OffboardOptions $options, bool $applied): void
    {
        IntegrationEvent::query()->create([
            'integration_namespace' => $options->integrationNamespace,
            'event_id' => $options->eventId,
            'external_subject' => $options->externalSubject,
            'event_kind' => self::EVENT_KIND,
            'entitlement_version' => $options->entitlementVersion,
            'applied' => $applied,
            'invitation_id' => null,
        ]);
    }

    /**
     * The containment itself, inside the caller's transaction.
     */
    private function contain(Subject $subject, ?AuditActor $actor, ?string $integrationNamespace = null): OffboardResult
    {
        $alreadyContained = OffboardedSubject::query()
            ->forSubject($subject)
            ->where('user_id', OffboardedSubject::SUBJECT_ROW)
            ->lockForUpdate()
            ->exists();

        // 1 — every bound credential, every lifecycle state, both stores.
        /** @var list<Credential> $credentials */
        $credentials = Credential::query()
            ->where('subject_type', $subject->type->value)
            ->where('subject_ref', $subject->ref)
            ->lockForUpdate()
            ->get()
            ->all();

        $revoked = 0;
        $boundUserIds = [];

        foreach ($credentials as $credential) {
            if ($credential->user_id !== null) {
                $boundUserIds[] = $credential->user_id;
            }

            // Outstanding codes die with the SUBJECT, not with the write
            // (rework Fix 7): a code linked to a row someone already
            // revoked is still a live code until it is consumed here.
            $this->consumeLinkedCodes((string) $credential->getKey(), DurableStore::Credentials);

            if ($credential->revoked_at !== null) {
                continue;
            }

            $credential->forceFill(['revoked_at' => now()])->save();
            $this->auditRevocation((string) $credential->getKey(), $actor);
            $revoked++;
        }

        /** @var list<ApiToken> $legacyTokens */
        $legacyTokens = ApiToken::query()
            ->where('subject_type', $subject->type->value)
            ->where('subject_ref', $subject->ref)
            ->lockForUpdate()
            ->get()
            ->all();

        foreach ($legacyTokens as $token) {
            $this->consumeLinkedCodes((string) $token->getKey(), DurableStore::ApiTokens);

            if ($token->revoked_at !== null) {
                continue;
            }

            $token->forceFill(['expires_at' => now(), 'revoked_at' => now()])->save();
            $this->auditRevocation((string) $token->getKey(), $actor);
            $revoked++;
        }

        // 2 — the principal's users: every user a credential binds, every
        // account an accepted invitation of this principal CREATED, plus
        // (for a human principal) the account whose email IS the ref.
        [$userIds, $emails, $traversalComplete] = $this->resolvePrincipals($subject, array_values(array_unique($boundUserIds)), $integrationNamespace);

        // 3 — outstanding claim codes addressed to the principal, with
        // their never-used make-before-break durables.
        $consumedCodes = $this->consumeAddressedCodes($emails, $actor);

        // 4 — pending invitations addressed to the principal.
        $canceledInvitations = $emails === [] ? 0 : $this->cancelPendingInvitations(
            Invitation::query()->whereIn('email', $emails),
        );

        // 5 — password-reset tokens.
        $deletedResetTokens = $this->deleteResetTokens($emails);

        // 6 — sessions (see the compensation statement in the class doc).
        // A step this transaction cannot complete is SURFACED, never
        // silently swallowed (rework Fix 3): named in the result and
        // logged, ids-free, so nobody reads a compensated offboard as a
        // fully contained one.
        [$deletedSessions, $incompleteStep] = $this->invalidateSessions($userIds);

        $incompleteSteps = [];

        if (! $traversalComplete) {
            // The traversal ceiling was hit (rework 3 Fix 3): principals
            // beyond it exist and were NOT contained. Surfaced like every
            // other incomplete step; re-running the idempotent verb
            // resumes the walk from the (already-registered) frontier.
            $incompleteSteps[] = 'principals:traversal-ceiling';
        }

        if ($incompleteStep !== null) {
            $incompleteSteps[] = $incompleteStep;
        }

        if ($incompleteSteps !== []) {
            Log::warning('Built for Cloud offboard could not complete every containment step in-transaction; the registry rejection stands. Re-run the offboard after fixing the store to retry.', [
                'incomplete_steps' => $incompleteSteps,
            ]);
        }

        // 7 — the registry rows the guards enforce, committed WITH the
        // revocations above: the containment survives whatever a
        // compensated step could not reach transactionally.
        $deactivatedUsers = $this->writeRegistry($subject, $userIds, $alreadyContained);

        // D8's one audit shape: a single subject-level `offboarded` event
        // carrying the acting principal — on the FIRST containment only
        // (the idempotent repeat writes nothing, like every other verb).
        if (! $alreadyContained) {
            $this->recorder->record(
                event: LifecycleEventType::Offboarded,
                actor: $actor,
                reason: AuditReason::Offboarding,
                note: 'subject offboarded: '.$subject->type->value.':'.$subject->ref,
            );
        }

        return new OffboardResult(
            acknowledged: false,
            applied: ! $alreadyContained,
            revokedCredentials: $revoked,
            consumedCodes: $consumedCodes,
            canceledInvitations: $canceledInvitations,
            deletedResetTokens: $deletedResetTokens,
            deletedSessions: $deletedSessions,
            deactivatedUsers: $deactivatedUsers,
            incompleteSteps: $incompleteSteps,
        );
    }

    /**
     * The principal set: the bound user ids from the subject's
     * credentials (already collected); every account an ACCEPTED
     * invitation of this principal created (rework Fix 1 — `used_by` is
     * the account an acceptance ceremony made, followed both through the
     * integration event history's invitation ids and through addressed
     * invitations of the principal's emails); the human account whose
     * email is the ref (user_principal subjects); and every email those
     * users carry — plus the ref itself as an address, which is what
     * claim codes and invitations are keyed on for human principals.
     *
     * The user↔email expansion runs to a FIXED POINT (rework 3 Fix 3):
     * users yield their emails, emails yield the accounts their accepted
     * invitations created, and the walk ends when a round adds no new
     * account — cycles terminate naturally (a known user is never "new"),
     * and the finite user/invitation set bounds the rounds. The
     * {@see self::PRINCIPAL_TRAVERSAL_CEILING} exists only against
     * pathological data; hitting it returns `complete = false`, which the
     * caller surfaces as an incomplete step. Already-registered
     * principals seed the walk, so a re-run after a ceiling hit RESUMES
     * from the registered frontier instead of re-truncating the same
     * prefix.
     *
     * @param  list<string>  $boundUserIds
     * @return array{list<string>, list<string>, bool} [user ids, emails, traversal complete]
     */
    private function resolvePrincipals(Subject $subject, array $boundUserIds, ?string $integrationNamespace): array
    {
        /** @var list<string> $registered */
        $registered = OffboardedSubject::query()
            ->forSubject($subject)
            ->where('user_id', '!=', OffboardedSubject::SUBJECT_ROW)
            ->pluck('user_id')
            ->all();

        $userIds = [...$boundUserIds, ...$registered];
        $emails = [$subject->ref];

        // The integration identity's accepted-invitation accounts: the
        // applied event history maps (namespace, external_subject) to
        // invitation ids; `used_by` names each created account. Bound by
        // namespace, so another integration's user who happens to share
        // the external subject string is never swept.
        if ($integrationNamespace !== null) {
            /** @var list<string> $invitedUserIds */
            $invitedUserIds = Invitation::query()
                ->whereIn('id', IntegrationEvent::query()
                    ->where('integration_namespace', $integrationNamespace)
                    ->where('external_subject', $subject->ref)
                    ->where('applied', true)
                    ->whereNotNull('invitation_id')
                    ->pluck('invitation_id')
                    ->all())
                ->whereNotNull('used_by')
                ->pluck('used_by')
                ->all();

            $userIds = [...$userIds, ...array_map(strval(...), $invitedUserIds)];
        }

        $model = config('auth.providers.users.model');
        $instance = null;

        if (is_string($model) && class_exists($model) && is_subclass_of($model, Model::class)) {
            /** @var Model $candidate */
            $candidate = new $model;

            if (Schema::hasTable($candidate->getTable())) {
                $instance = $candidate;
            }
        }

        if ($instance !== null && $subject->type === SubjectType::UserPrincipal) {
            /** @var Model|null $byEmail */
            $byEmail = $instance::query()->where('email', $subject->ref)->first();

            if ($byEmail !== null) {
                $userIds[] = (string) $byEmail->getKey();
            }
        }

        $complete = false;

        for ($round = 0; $round < self::PRINCIPAL_TRAVERSAL_CEILING; $round++) {
            $userIds = array_values(array_unique($userIds));

            if ($instance !== null && $userIds !== []) {
                /** @var list<string> $userEmails */
                $userEmails = $instance::query()
                    ->whereIn($instance->getKeyName(), $userIds)
                    ->pluck('email')
                    ->filter(static fn (mixed $email): bool => is_string($email) && $email !== '')
                    ->values()
                    ->all();

                $emails = [...$emails, ...$userEmails];
            }

            $emails = array_values(array_unique($emails));

            /** @var list<string> $acceptedByEmail */
            $acceptedByEmail = Invitation::query()
                ->whereIn('email', $emails)
                ->whereNotNull('used_by')
                ->pluck('used_by')
                ->all();

            $newUserIds = array_values(array_diff(array_map(strval(...), $acceptedByEmail), $userIds));

            if ($newUserIds === []) {
                // The fixed point: this round's email set was computed
                // from the FULL user set and discovered nothing new.
                $complete = true;

                break;
            }

            $userIds = [...$userIds, ...$newUserIds];
        }

        return [array_values(array_unique($userIds)), array_values(array_unique($emails)), $complete];
    }

    /**
     * Consume every still-pending claim code linked to the given durable,
     * in the store it was RECORDED into.
     */
    private function consumeLinkedCodes(string $durableId, DurableStore $store): void
    {
        OnboardingToken::query()
            ->where('durable_token_id', $durableId)
            ->where(function (Builder $query) use ($store): void {
                $query->where('durable_store', $store->value);

                if ($store === DurableStore::ApiTokens) {
                    // NULL backfills to api_tokens (pre-toggle linkage).
                    $query->orWhereNull('durable_store');
                }
            })
            ->whereNull('consumed_at')
            ->update(['consumed_at' => now()]);
    }

    /**
     * Consume the pending claim codes ADDRESSED to the principal, and
     * revoke each one's never-used make-before-break durable in the store
     * it was recorded into.
     *
     * @param  list<string>  $emails
     */
    private function consumeAddressedCodes(array $emails, ?AuditActor $actor): int
    {
        if ($emails === []) {
            return 0;
        }

        /** @var list<OnboardingToken> $codes */
        $codes = OnboardingToken::query()
            ->whereIn('email', $emails)
            ->whereNull('consumed_at')
            ->lockForUpdate()
            ->get()
            ->all();

        foreach ($codes as $code) {
            $code->forceFill(['consumed_at' => now()])->save();

            if ($code->durable_token_id === null) {
                continue;
            }

            if ($code->durableStore() === DurableStore::Credentials) {
                $updated = Credential::query()
                    ->whereKey($code->durable_token_id)
                    ->whereNull('revoked_at')
                    ->update(['revoked_at' => now()]);
            } else {
                $updated = ApiToken::query()
                    ->whereKey($code->durable_token_id)
                    ->whereNull('revoked_at')
                    ->update(['expires_at' => now(), 'revoked_at' => now()]);
            }

            if ($updated > 0) {
                $this->auditRevocation($code->durable_token_id, $actor);
            }
        }

        return count($codes);
    }

    /**
     * Cancel every still-pending invitation the query selects — a
     * conditional update, so it composes with a concurrent accept exactly
     * as the invite verb's supersession does.
     *
     * @param  Builder<Invitation>  $pending
     */
    private function cancelPendingInvitations(Builder $pending): int
    {
        return $pending
            ->whereNull('accepted_at')
            ->update(['accepted_at' => now()]);
    }

    /**
     * @param  list<string>  $emails
     */
    private function deleteResetTokens(array $emails): int
    {
        if ($emails === []) {
            return 0;
        }

        $broker = config('auth.defaults.passwords', 'users');
        $table = config('auth.passwords.'.$broker.'.table', 'password_reset_tokens');

        if (! is_string($table) || $table === '' || ! Schema::hasTable($table)) {
            return 0;
        }

        return DB::table($table)->whereIn('email', $emails)->delete();
    }

    /**
     * Session invalidation, with the stated compensation (rework Fix 3 —
     * surfaced, never silent): same-connection database stores delete
     * inside this transaction and the step is COMPLETE. A database store
     * on another connection cannot join the transaction: its delete is
     * deferred to after commit, a deferral failure is logged (exception
     * class only), and the step is reported INCOMPLETE either way —
     * deferred is not done. Any other driver's storage cannot be
     * enumerated per user at all and is reported incomplete outright. In
     * every incomplete case the registry row commits WITH the
     * revocations, so the guards reject the principal whatever survives
     * in session storage — containment holds; the REPORT stays honest.
     *
     * @param  list<string>  $userIds
     * @return array{int, string|null} [deleted rows, incomplete-step slug or null]
     */
    private function invalidateSessions(array $userIds): array
    {
        if ($userIds === []) {
            return [0, null];
        }

        if (config('session.driver') !== 'database') {
            // Nothing to enumerate: cookie/file/cache-backed stores keep
            // no per-user index the package can sweep. The registry +
            // bfc.auth/bfc.admin rejection (and the app's own documented
            // check on its plain `auth` routes) is the containment.
            return [0, 'sessions:driver-not-enumerable'];
        }

        $table = (string) config('session.table', 'sessions');
        $connection = config('session.connection');

        if ($connection === null || $connection === config('database.default')) {
            if (! Schema::hasTable($table)) {
                return [0, 'sessions:table-missing'];
            }

            return [DB::table($table)->whereIn('user_id', $userIds)->delete(), null];
        }

        // Deferred, not done: the delete runs after commit, its failure is
        // logged, and the step is flagged incomplete regardless — the
        // caller re-runs the idempotent offboard to verify.
        DB::afterCommit(static function () use ($connection, $table, $userIds): void {
            try {
                DB::connection(is_string($connection) ? $connection : null)
                    ->table($table)
                    ->whereIn('user_id', $userIds)
                    ->delete();
            } catch (Throwable $exception) {
                try {
                    Log::warning('Built for Cloud offboard could not delete sessions on the configured session connection after commit; the registry rejection stands.', [
                        'exception' => $exception::class,
                    ]);
                } catch (Throwable) {
                    // Failing to log must not surface past the commit.
                }
            }
        });

        return [0, 'sessions:deferred-other-connection'];
    }

    /**
     * @param  list<string>  $userIds
     */
    private function writeRegistry(Subject $subject, array $userIds, bool $alreadyContained): int
    {
        if (! $alreadyContained) {
            // The (subject_type, subject_ref, user_id) unique key is what
            // makes a concurrent first offboard safe (rework Fix 6): the
            // loser's insert violates, the whole attempt rolls back, and
            // the bounded retry re-reads the winner's committed row as
            // alreadyContained — the idempotent no-op.
            OffboardedSubject::query()->create([
                'id' => (string) Str::uuid(),
                'subject_type' => $subject->type->value,
                'subject_ref' => $subject->ref,
                'user_id' => OffboardedSubject::SUBJECT_ROW,
                'offboarded_at' => now(),
            ]);
        }

        $deactivated = 0;

        foreach ($userIds as $userId) {
            $exists = OffboardedSubject::query()
                ->forSubject($subject)
                ->where('user_id', $userId)
                ->exists();

            if ($exists) {
                continue;
            }

            OffboardedSubject::query()->create([
                'id' => (string) Str::uuid(),
                'subject_type' => $subject->type->value,
                'subject_ref' => $subject->ref,
                'user_id' => $userId,
                'offboarded_at' => now(),
            ]);

            $deactivated++;
        }

        return $deactivated;
    }

    private function auditRevocation(string $credentialId, ?AuditActor $actor): void
    {
        $this->recorder->record(
            event: LifecycleEventType::Revoked,
            credentialId: $credentialId,
            actor: $actor,
            reason: AuditReason::Offboarding,
        );
    }
}
