<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Actions\Concerns;

use ArtisanBuild\BuiltForCloud\Contracts\AuthorizesCredentialVerbs;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresPresentationCadence;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresUnsupportedSummaryFields;
use ArtisanBuild\BuiltForCloud\CredentialSummary;
use ArtisanBuild\BuiltForCloud\CredentialVerb;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageTokens;
use ArtisanBuild\BuiltForCloud\Subject;
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
