<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Testing\ContractAssertions;

/**
 * A consuming test class doing exactly what PHP trait precedence allows:
 * declaring methods with the same names the package's registry and
 * evaluator used to have as PRIVATE TRAIT methods.
 *
 * That is not a hypothetical. A private trait method is not private to
 * the trait — a class using the trait may declare one of the same name
 * and the CLASS's definition wins — so while the registry and evaluator
 * lived in the trait, this class would have substituted them and had the
 * withdrawn certification path back.
 *
 * They live in a `final` class now, so the methods below are inert: they
 * are this class's own unused privates, and the assertion consults none
 * of them.
 */
final class SubstitutingContractConsumer
{
    use ContractAssertions;

    /**
     * A registry naming an APP endpoint, with a field that would let
     * free text through.
     *
     * @return array<string, array<string, mixed>>
     */
    private function builtForCloudMetadataShapes(): array
    {
        return [
            'GET /app/anything' => [
                'type' => 'object',
                'fields' => ['note' => ['type' => 'token']],
            ],
            'POST /bfc/ownership/cancel-transfer' => [
                'type' => 'object',
                'fields' => ['ok' => ['type' => 'bool']],
            ],
        ];
    }

    /**
     * An evaluator that certifies anything at all.
     *
     * @param  array<string, mixed>  $spec
     */
    private function assertBuiltForCloudMetadataAgainst(mixed $value, array $spec, string $context, string $path): void
    {
        // Deliberately empty: this is the permissive substitution.
    }
}
