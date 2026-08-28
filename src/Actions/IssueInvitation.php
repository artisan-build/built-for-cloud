<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Actions;

use ArtisanBuild\BuiltForCloud\Actions\Concerns\ConsultsDeclaration;
use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\CredentialVerb;
use ArtisanBuild\BuiltForCloud\Exceptions\CredentialVerbRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use ArtisanBuild\BuiltForCloud\IntegrationEntitlement;
use ArtisanBuild\BuiltForCloud\IntegrationEvent;
use ArtisanBuild\BuiltForCloud\Invitation;
use ArtisanBuild\BuiltForCloud\InvitationIssueResult;
use ArtisanBuild\BuiltForCloud\InvitationOptions;
use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\MintedSecret;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

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
 * - a declaration whose verb matrix denies `issue` for the subject.
 *
 * The version gate: an event's version must be NEWER than the latest
 * accepted for its (namespace, external subject) or the event is
 * transactionally acknowledged-and-ignored; a replayed event id answers
 * idempotently with no second invitation. The response is ONE
 * non-enumerating shape whatever the prior state.
 *
 * The `issued` audit event rides the issue's own transaction (SEC-V3-09);
 * the addressed recipient is notified through the lifecycle policy where
 * the app declares an `issued` row, and an unaddressed invitation notifies
 * nobody.
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

        if ($options->entitlementVersion !== null && $options->entitlementVersion < 0) {
            throw InvalidCredentialInput::entitlementVersionOutOfBounds();
        }

        if (! $this->verbAllowed(CredentialVerb::Issue, $this->subjectFor($options))) {
            throw CredentialVerbRefused::byMatrix(CredentialVerb::Issue);
        }

        /** @var InvitationIssueResult */
        return DB::transaction(function () use ($options, $ttlSeconds, $actor): InvitationIssueResult {
            if ($options->integrationEventComplete()) {
                return $this->decideIntegrationEvent($options, $ttlSeconds, $actor);
            }

            return $this->issue($options, $ttlSeconds, $actor);
        });
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
     * re-judged against the version it itself advanced.
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
        // ignored event's own id must replay idempotently too. Two firsts
        // racing on the same (namespace, subject) fall to the entitlement
        // unique index — one transaction fails whole and its retry lands
        // here as an ordinary ordering decision.
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

        $result = $this->issue($options, $ttlSeconds, $actor);

        $this->recordEvent($options, applied: true, invitationId: $result->invitationId);

        return $result;
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
     * Mint the invitation: the code is born inside a sealed
     * {@see MintedSecret}, only its hash reaches storage, and expiry is
     * exactly issue time + ttl — no hidden defaults.
     */
    private function issue(InvitationOptions $options, int $ttlSeconds, ?AuditActor $actor): InvitationIssueResult
    {
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
