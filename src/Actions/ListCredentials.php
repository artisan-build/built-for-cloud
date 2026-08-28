<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Actions;

use ArtisanBuild\BuiltForCloud\Actions\Concerns\ConsultsDeclaration;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialSummary;
use ArtisanBuild\BuiltForCloud\CredentialVerb;
use ArtisanBuild\BuiltForCloud\PersonalCredentialSurface;
use ArtisanBuild\BuiltForCloud\Subject;

/**
 * The list verb over the unified store (PRD 1.0 + 1.6), consumed by both
 * `bfc:credential:list --local` and `GET /bfc/credentials`. The legacy
 * `api_tokens` listing (`GET /api/credentials`) is a separate, unchanged
 * surface.
 *
 * `list_metadata` granularity is PER ROW: each row the declaration's verb
 * matrix denies drops out of the listing — a blanket deny yields an empty
 * listing, not a refusal, because a partial answer is still an honest one.
 * Declared-unsupported summary fields are nulled AND named per row, so a
 * consumer can tell "absent" from "unknowable" on either transport.
 *
 * The optional `$subject` narrows the listing to ONE subject's rows. It is
 * how {@see PersonalCredentialSurface} answers "list MINE" without a second
 * list verb: the operator transport passes nothing and sees the instance,
 * the self-service transport passes the SERVER-DERIVED subject and sees
 * only that subject's rows (SEC-V3-07). The scope is an argument, never
 * anything read off the request here.
 */
final class ListCredentials
{
    use ConsultsDeclaration;

    /**
     * @return list<CredentialSummary>
     */
    public function __invoke(?Subject $subject = null): array
    {
        $cadence = $this->declaredCadence();
        $unsupported = $this->declaredUnsupportedFields();

        $query = Credential::query();

        if ($subject !== null) {
            $query->where('subject_type', $subject->type->value)
                ->where('subject_ref', $subject->ref);
        }

        return $query
            ->orderBy('created_at')
            ->orderBy('id')
            ->get()
            ->filter(fn (Credential $credential): bool => $this->verbAllowed(CredentialVerb::ListMetadata, $credential->subject()))
            ->map(static fn (Credential $credential): CredentialSummary => CredentialSummary::fromCredential($credential, $cadence, $unsupported))
            ->values()
            ->all();
    }
}
