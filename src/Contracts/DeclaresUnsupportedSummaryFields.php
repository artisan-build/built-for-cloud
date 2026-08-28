<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Contracts;

use ArtisanBuild\BuiltForCloud\CredentialSummary;

/**
 * Opt-in extension of {@see CredentialDeclaration} — which summary fields
 * this app's store structurally CANNOT express (PRD 1.6, D3): reel's rows
 * carry no name, no abilities, no last_used_at and no credential expiry,
 * and a summary that renders those as bare nulls leaves the consumer
 * guessing between "absent" and "unknowable".
 *
 * A declared field is serialized null AND named in every summary's
 * `unsupported` list, on BOTH transports. The mint verb also refuses
 * options that set a declared-unsupported field — storing what the
 * declaration says is inexpressible would make the declaration a lie.
 *
 * Only {@see CredentialSummary::DECLARABLE_FIELDS} may be declared; names
 * outside that list are ignored (structural fields are always supported).
 */
interface DeclaresUnsupportedSummaryFields
{
    /**
     * @return list<string>
     */
    public function unsupportedSummaryFields(): array;
}
