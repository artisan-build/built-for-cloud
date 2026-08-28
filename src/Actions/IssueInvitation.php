<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Actions;

use ArtisanBuild\BuiltForCloud\Actions\Concerns\ConsultsDeclaration;
use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\CredentialVerb;
use ArtisanBuild\BuiltForCloud\Exceptions\CredentialVerbRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\IntegrationEventContention;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use ArtisanBuild\BuiltForCloud\IntegrationEntitlement;
use ArtisanBuild\BuiltForCloud\IntegrationEvent;
use ArtisanBuild\BuiltForCloud\Invitation;
use ArtisanBuild\BuiltForCloud\InvitationIssueResult;
use ArtisanBuild\BuiltForCloud\InvitationOptions;
use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\MintedSecret;
use ArtisanBuild\BuiltForCloud\Notifications\InvitationDeliveryNotification;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Str;
use Throwable;

/**
 * The machine-callable invite verb (PRD 1.13, D1e constraint 1,
 * SEC-V3-05): ONE implementation consumed by BOTH transports
 * (`bfc:invitation:issue --local` and `POST /bfc/invitations`). An
 * integration triggers the INVITATION, never a key mint — the invitation
 * is the primitive whose interception fails loud.
 *
 * What it refuses, identically on both transports:
 * - a missing or out-of-bounds ttl (the invitation is a claim code; its
 *   lifetime is always the caller's explicit choice, 60s–7d);
 * - a PARTIAL integration-event group (namespace, event id, entitlement
 *   version and external subject travel together or not at all);
 * - an entitlement version outside [1, 2^53] — a version that saturates
 *   integer parsing would otherwise permanently poison its subject;
 * - a declaration whose verb matrix denies `issue` for the subject.
 *
 * The version gate: an event's version must be NEWER than the latest
 * accepted for its (namespace, external subject) or the event is
 * transactionally acknowledged-and-ignored; a replayed event id answers
 * idempotently. Concurrent deliveries racing a gate-row create are
 * re-decided in fresh transactions against the winner's committed row —
 * up to {@see GATE_ATTEMPTS} whole attempts, because one request can
 * lose the entitlement race and then the event-id race; past the bound a
 * clean {@see IntegrationEventContention} escapes (safe to retry, no
 * partial state), never a naked unique-violation 500.
 *
 * Supersession (mirroring the onboarding primitive), scoped precisely:
 * an APPLYING integration event consumes every prior pending invitation
 * of its OWN (namespace, subject) history and nothing else — never
 * another namespace's invitation, never a human one sharing the email;
 * an addressed HUMAN invite consumes every prior pending invitation of
 * its email. Both are conditional updates in the issue's own
 * transaction. Open, non-integration codes supersede nothing (there is
 * no subject to match).
 *
 * The integration path returns ONE uniform acknowledgement whatever
 * happened (applied/ignored/replayed) and reveals nothing to the caller:
 * delivery to an ADDRESSED invitee is the {@see InvitationDeliveryNotification}
 * sent after commit (D1e — the integration triggers, the instance
 * delivers). The human path keeps the transport reveal.
 *
 * The `issued` audit event rides the issue's own transaction (SEC-V3-09).
 */
final class IssueInvitation
{
    use ConsultsDeclaration;

    /**
     * The event kind this verb writes into the gate tables. The
     * offboarding verb (a later PR) plugs its own kind into the SAME
     * tables — the gate is kind-generic by construction.
     */
    public const string EVENT_KIND = 'invite';

    /**
     * The entitlement-version ceiling: 2^53, the largest integer every
     * JSON producer represents exactly. Anything above it — including a
     * digit string that saturated PHP's integer parse — is rejected,
     * never accepted, because a saturated version stored as the latest
     * accepted would leave its subject permanently unable to see a newer
     * event.
     */
    public const int MAX_ENTITLEMENT_VERSION = 9007199254740992;

    /**
     * The gate's contention bound: how many whole transactional attempts
     * one request makes before giving up. Three, because one request can
     * genuinely lose two distinct races back to back (the entitlement
     * row's create, then the event id's) and still deserves the decided
     * answer on a clean third pass.
     */
    public const int GATE_ATTEMPTS = 3;

    public function __construct(private readonly LifecycleEventRecorder $recorder) {}

    public function __invoke(InvitationOptions $options, ?AuditActor $actor = null): InvitationIssueResult
    {
        $ttlSeconds = $options->ttlSeconds;

        if ($ttlSeconds === null || $ttlSeconds < Invitation::TTL_MIN_SECONDS || $ttlSeconds > Invitation::TTL_MAX_SECONDS) {
            throw InvalidCredentialInput::invitationTtlOutOfBounds();
        }

        if ($options->carriesIntegrationEvent() && ! $options->integrationEventComplete()) {
            throw InvalidCredentialInput::partialIntegrationEvent();
        }

        if ($options->entitlementVersion !== null
            && ($options->entitlementVersion < 1 || $options->entitlementVersion > self::MAX_ENTITLEMENT_VERSION)) {
            throw InvalidCredentialInput::entitlementVersionOutOfBounds();
        }

        if (! $this->verbAllowed(CredentialVerb::Issue, $this->subjectFor($options))) {
            throw CredentialVerbRefused::byMatrix(CredentialVerb::Issue);
        }

        if (! $options->integrationEventComplete()) {
            /** @var InvitationIssueResult */
            return DB::transaction(fn (): InvitationIssueResult => $this->issue($options, $ttlSeconds, $actor));
        }

        // The concurrent-winner rescue: another delivery committing a gate
        // row (the entitlement, or this very event id) between our check
        // and our create rolls our transaction back whole; each retry
        // re-enters a FRESH transaction and re-applies the ordinary
        // replay/ignore-older logic against what now stands. Bounded at
        // GATE_ATTEMPTS because losing BOTH races in one request is real
        // (entitlement first, then the event id): past the bound a clean,
        // secret-free contention error escapes — safe to retry, and no
        // attempt leaves partial state (each rolled back whole).
        for ($attempt = 1; $attempt <= self::GATE_ATTEMPTS; $attempt++) {
            try {
                /** @var InvitationIssueResult */
                return DB::transaction(fn (): InvitationIssueResult => $this->decideIntegrationEvent($options, $ttlSeconds, $actor));
            } catch (UniqueConstraintViolationException) {
                // Loop; the next attempt re-decides from scratch.
            }
        }

        throw IntegrationEventContention::afterAttempts(self::GATE_ATTEMPTS);
    }

    /**
     * The subject the verb matrix is asked about: the external subject for
     * an integration event, the addressed human for a plain invite, or
     * null for an open code (the gates in front — admin token on HTTP,
     * machine access on the CLI — remain the authority).
     */
    private function subjectFor(InvitationOptions $options): ?Subject
    {
        if ($options->externalSubject !== null) {
            return new Subject(SubjectType::ExternalConsumer, $options->externalSubject);
        }

        return $options->email !== null
            ? new Subject(SubjectType::UserPrincipal, $options->email)
            : null;
    }

    /**
     * The SEC-V3-05 gate, inside the caller's transaction. Order matters:
     * a replayed event id answers FIRST — idempotently, whatever its
     * original outcome — so a re-delivered applied event is never
     * re-judged against the version it itself advanced. Every branch
     * returns the SAME uniform acknowledgement: the caller learns that
     * the event was decided, never what the decision was.
     */
    private function decideIntegrationEvent(InvitationOptions $options, int $ttlSeconds, ?AuditActor $actor): InvitationIssueResult
    {
        $replayed = IntegrationEvent::query()
            ->where('integration_namespace', $options->integrationNamespace)
            ->where('event_id', $options->eventId)
            ->lockForUpdate()
            ->exists();

        if ($replayed) {
            return InvitationIssueResult::acknowledged();
        }

        /** @var IntegrationEntitlement|null $entitlement */
        $entitlement = IntegrationEntitlement::query()
            ->where('integration_namespace', $options->integrationNamespace)
            ->where('external_subject', $options->externalSubject)
            ->lockForUpdate()
            ->first();

        // Not newer = acknowledged-and-ignored, but still RECORDED: the
        // ignored event's own id must replay idempotently too.
        if ($entitlement !== null && $options->entitlementVersion <= $entitlement->entitlement_version) {
            $this->recordEvent($options, applied: false, invitationId: null);

            return InvitationIssueResult::acknowledged();
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

        // The applying event supersedes every prior pending invitation of
        // its (namespace, subject) — a stolen older code must not survive
        // the newer event. Conditional update: a row a concurrent accept
        // just consumed is simply not matched.
        $this->supersedePending(
            Invitation::query()->whereIn('id', IntegrationEvent::query()
                ->where('integration_namespace', $options->integrationNamespace)
                ->where('external_subject', $options->externalSubject)
                ->where('applied', true)
                ->whereNotNull('invitation_id')
                ->pluck('invitation_id')
                ->all()),
        );

        $result = $this->issue($options, $ttlSeconds, $actor);

        $this->recordEvent($options, applied: true, invitationId: $result->invitationId);

        if ($options->email !== null && $result->invitationId !== null && $result->code instanceof MintedSecret) {
            $this->deliverAfterCommit($options->email, $result->invitationId, $result->code);
        }

        return InvitationIssueResult::acknowledged();
    }

    private function recordEvent(InvitationOptions $options, bool $applied, ?string $invitationId): void
    {
        IntegrationEvent::query()->create([
            'integration_namespace' => $options->integrationNamespace,
            'event_id' => $options->eventId,
            'external_subject' => $options->externalSubject,
            'event_kind' => self::EVENT_KIND,
            'entitlement_version' => $options->entitlementVersion,
            'applied' => $applied,
            'invitation_id' => $invitationId,
        ]);
    }

    /**
     * Consume every still-pending (unaccepted, unexpired) invitation the
     * given query selects — the invitation-side mirror of the onboarding
     * primitive's supersession, as a CONDITIONAL update so it composes
     * with the accept path's affected-rows gate: whichever of accept and
     * supersede runs second matches zero rows and both outcomes stay
     * coherent. A superseded code refuses acceptance as already claimed
     * (`used_by` stays null, distinguishing it from a real acceptance).
     *
     * @param  Builder<Invitation>  $pending
     */
    private function supersedePending(Builder $pending): void
    {
        $pending
            ->whereNull('accepted_at')
            ->where(function (Builder $query): void {
                $query->whereNull('expires_at')
                    ->orWhere('expires_at', '>', now());
            })
            ->update(['accepted_at' => now()]);
    }

    /**
     * The integration path's delivery (D1e: the integration triggers, the
     * INSTANCE delivers): the addressed invitee is mailed the code after
     * the transaction commits — a rolled-back issue delivers nothing, and
     * the caller never sees a plaintext to mis-deliver. A failed send is
     * logged by exception class only; the invitation stands and a human
     * re-invite supersedes it with a fresh deliverable code.
     */
    private function deliverAfterCommit(string $email, string $invitationId, MintedSecret $code): void
    {
        DB::afterCommit(static function () use ($email, $invitationId, $code): void {
            try {
                Notification::route('mail', $email)
                    ->notify(new InvitationDeliveryNotification($invitationId, $code->reveal()));
            } catch (Throwable $exception) {
                try {
                    Log::warning('Built for Cloud could not deliver an invitation code; re-invite to supersede it.', [
                        'exception' => $exception::class,
                    ]);
                } catch (Throwable) {
                    // Failing to log must not resurrect the failure.
                }
            }
        });
    }

    /**
     * Mint the invitation: the code is born inside a sealed
     * {@see MintedSecret}, only its hash reaches storage, and expiry is
     * exactly issue time + ttl — no hidden defaults. An ADDRESSED invite
     * first supersedes every prior pending invitation of the same email —
     * an issuer replaces a code by issuing again; open codes supersede
     * nothing.
     */
    private function issue(InvitationOptions $options, int $ttlSeconds, ?AuditActor $actor): InvitationIssueResult
    {
        // Email-wide supersession is the HUMAN path's semantic only: an
        // issuer replaces the code they addressed. An integration event
        // supersedes nothing here — its scope is exactly its own
        // (namespace, subject) history, consumed by the caller — so an
        // applied event for one namespace can never consume another
        // namespace's invitation, or a human one, that happens to share
        // the recipient address.
        if ($options->email !== null && ! $options->integrationEventComplete()) {
            $this->supersedePending(Invitation::query()->where('email', $options->email));
        }

        do {
            $code = new MintedSecret(bin2hex(random_bytes(32)));
        } while (Invitation::query()->where('token', $code->hash())->exists());

        /** @var Invitation $invitation */
        $invitation = Invitation::query()->create([
            'id' => (string) Str::uuid(),
            'email' => $options->email,
            'token' => $code->hash(),
            'invited_by' => $options->invitedBy,
            'role' => $options->role,
            'expires_at' => now()->addSeconds($ttlSeconds),
        ]);

        $this->recorder->record(
            event: LifecycleEventType::Issued,
            codeId: $invitation->id,
            actor: $actor,
            recipient: $options->email,
            codeTtlSeconds: $ttlSeconds,
        );

        return new InvitationIssueResult($invitation->id, $code, $options->email);
    }
}
