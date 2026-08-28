<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Actions\Concerns;

use ArtisanBuild\BuiltForCloud\Contracts\AuthorizesCredentialVerbs;
use ArtisanBuild\BuiltForCloud\Contracts\ConstrainsMintedCredentials;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresPresentationCadence;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresUnsupportedSummaryFields;
use ArtisanBuild\BuiltForCloud\CredentialSummary;
use ArtisanBuild\BuiltForCloud\CredentialVerb;
use ArtisanBuild\BuiltForCloud\Exceptions\CredentialVerbRefused;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageTokens;
use ArtisanBuild\BuiltForCloud\Subject;
use Carbon\CarbonInterface;
use Illuminate\Http\Request;

/**
 * How an action class consults the app's declaration. The declaration is
 * resolved per call, never via the constructor — actions are the shared
 * core of BOTH transports, and a long-lived worker (or a test rebinding
 * the declaration) must always see the current binding (the same stance as
 * {@see ManageTokens}).
 */
trait ConsultsDeclaration
{
    private function declaration(): CredentialDeclaration
    {
        return app(CredentialDeclaration::class);
    }

    /**
     * The verb matrix (PRD 1.4), consulted INSIDE the action so both
     * transports get the identical answer. A declaration that does not
     * implement the opt-in contract allows every verb — the gates in
     * front (admin token on HTTP, machine access on the CLI) remain the
     * authority — and implementing it can only narrow.
     *
     * The request handed to the hook is the transport's own: the real
     * HTTP request, or the console process's bound request (which carries
     * no client input — exactly the point: nothing a caller supplies can
     * substitute for what the row or the action's own arguments declare).
     */
    private function verbAllowed(CredentialVerb $verb, ?Subject $subject): bool
    {
        $declaration = $this->declaration();

        if (! $declaration instanceof AuthorizesCredentialVerbs) {
            return true;
        }

        return $declaration->authorizeVerb($verb, $subject, $this->currentRequest());
    }

    /**
     * The declared mint ceilings ({@see ConstrainsMintedCredentials}),
     * applied to a RESULT shape — the abilities and expiry a credential
     * row would carry. One implementation for every verb that creates a
     * row: the mint verb checks the requested shape, and a rotation
     * OVERRIDE checks the replacement's effective shape, because an
     * override may never produce a credential a mint of that shape could
     * not have been authorized for. Refusal, never substitution: the
     * package does not quietly narrow abilities or stamp a shorter expiry
     * — TTL defaults on durables are a DO-NOT-BUILD.
     *
     * @param  list<string>|null  $abilities
     */
    private function refuseWideningPastCeilings(Subject $subject, ?array $abilities, ?CarbonInterface $expiresAt): void
    {
        $declaration = $this->declaration();

        if (! $declaration instanceof ConstrainsMintedCredentials) {
            return;
        }

        $grantable = $declaration->grantableAbilities($subject);

        if ($grantable !== null) {
            foreach ($abilities ?? [] as $ability) {
                if (! in_array($ability, $grantable, true)) {
                    throw CredentialVerbRefused::abilityWidening($ability);
                }
            }
        }

        $maxLifetimeSeconds = $declaration->maxCredentialLifetimeSeconds($subject);

        if ($maxLifetimeSeconds === null) {
            return;
        }

        // No expiry at all outlives any ceiling; a later expiry widens past
        // it. Both are the caller's to fix by choosing.
        if ($expiresAt === null || $expiresAt->isAfter(now()->addSeconds($maxLifetimeSeconds))) {
            throw CredentialVerbRefused::lifetimeWidening();
        }
    }

    private function declaredCadence(): ?int
    {
        $declaration = $this->declaration();

        if (! $declaration instanceof DeclaresPresentationCadence) {
            return null;
        }

        return $declaration->presentationCadenceSeconds();
    }

    /**
     * @return list<string>
     */
    private function declaredUnsupportedFields(): array
    {
        $declaration = $this->declaration();

        if (! $declaration instanceof DeclaresUnsupportedSummaryFields) {
            return [];
        }

        return array_values(array_intersect(
            $declaration->unsupportedSummaryFields(),
            CredentialSummary::DECLARABLE_FIELDS,
        ));
    }

    private function currentRequest(): Request
    {
        /** @var Request */
        return app('request');
    }
}
