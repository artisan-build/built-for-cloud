<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\Contracts\AuthorizesCredentialVerbs;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialVerb;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Testing\DetectsSecretLeaks;
use ArtisanBuild\BuiltForCloud\TokenRegistry;
use Closure;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Orchestra\Testbench\Attributes\WithConfig;

/**
 * The per-verb authority matrix, executable (PRD 1.4, D2, SEC-V3-07): the
 * declaration's verb-aware hook is the ONLY authority answer on the
 * credential API, it can only narrow what the admin gate allows, and no
 * permission is ever inferred from a subject_type, a subject_ref, or
 * possession of a name — in any request input.
 */
#[WithConfig('built-for-cloud.credential_api.enabled', true, false)]
final class SubjectsAuthorityTest extends TestCase
{
    use DetectsSecretLeaks;
    use RefreshDatabase;

    // Locked AC4 — a declaration denying `revoke` produces 403 on revoke-by-id DESPITE a valid
    // admin token; allowing produces 204. The row stays alive through the denial.
    public function test_a_declaration_denying_revoke_produces_403_despite_a_valid_admin_token(): void
    {
        $headers = $this->adminHeaders();

        $token = ApiToken::factory()->create([
            'name' => 'guarded',
            'token_hash' => hash('sha256', 'guarded-secret'),
        ]);

        $this->bindMatrix(static fn (CredentialVerb $verb): bool => $verb !== CredentialVerb::Revoke);

        $this->assertNoSecretLeakage('guarded-secret', function () use ($token, $headers): void {
            $this->deleteJson('/api/credentials/id/'.$token->id, [], $headers)->assertForbidden();
        });

        $this->assertSame('guarded', (new TokenRegistry)->resolve('guarded-secret'));

        $this->bindMatrix(static fn (): bool => true);

        $this->deleteJson('/api/credentials/id/'.$token->id, [], $headers)->assertNoContent();

        $this->assertNull((new TokenRegistry)->resolve('guarded-secret'));
    }

    // SEC-V3-07 — a declaration denying `revoke` for a FOREIGN subject_ref blocks revoke-by-id
    // on that row while allowing its own. The subject the matrix sees is what the ROW declares.
    public function test_a_declaration_scoped_to_its_own_subject_ref_blocks_the_foreign_row_only(): void
    {
        $headers = $this->adminHeaders();

        $own = ApiToken::factory()->create([
            'name' => 'client-key',
            'token_hash' => hash('sha256', 'own-secret'),
            'subject_type' => SubjectType::ExternalConsumer->value,
            'subject_ref' => 'tenant-a',
        ]);
        $foreign = ApiToken::factory()->create([
            'name' => 'client-key',
            'token_hash' => hash('sha256', 'foreign-secret'),
            'subject_type' => SubjectType::ExternalConsumer->value,
            'subject_ref' => 'tenant-b',
        ]);

        $this->bindMatrix(static fn (CredentialVerb $verb, ?Subject $subject): bool => $verb !== CredentialVerb::Revoke || $subject?->ref === 'tenant-a');

        $this->assertNoSecretLeakage('foreign-secret', function () use ($own, $foreign, $headers): void {
            $this->deleteJson('/api/credentials/id/'.$foreign->id, [], $headers)->assertForbidden();
            $this->deleteJson('/api/credentials/id/'.$own->id, [], $headers)->assertNoContent();
        });

        $this->assertNull((new TokenRegistry)->resolve('own-secret'));
        $this->assertSame('client-key', (new TokenRegistry)->resolve('foreign-secret'));
    }

    // Locked AC5 — no authority from possession: a crafted subject_ref (or name) supplied in the
    // request body and query never widens what the declaration allows, because the matrix is fed
    // the ROW's subject, never the caller's claim.
    public function test_a_crafted_subject_ref_in_request_input_never_widens_authority(): void
    {
        $headers = $this->adminHeaders();

        $foreign = ApiToken::factory()->create([
            'name' => 'client-key',
            'token_hash' => hash('sha256', 'crafted-target-secret'),
            'subject_type' => SubjectType::ExternalConsumer->value,
            'subject_ref' => 'tenant-b',
        ]);

        $this->bindMatrix(static fn (CredentialVerb $verb, ?Subject $subject): bool => $verb !== CredentialVerb::Revoke || $subject?->ref === 'tenant-a');

        $this->deleteJson(
            '/api/credentials/id/'.$foreign->id.'?subject_ref=tenant-a&subject_type=external_consumer',
            ['subject_ref' => 'tenant-a', 'subject_type' => 'external_consumer', 'name' => 'tenant-a'],
            $headers,
        )->assertForbidden();

        // The name path refuses on the same crafted claim.
        $this->deleteJson(
            '/api/credentials/client-key?subject_ref=tenant-a',
            ['subject_ref' => 'tenant-a'],
            $headers,
        )->assertForbidden();

        $this->assertSame('client-key', (new TokenRegistry)->resolve('crafted-target-secret'));
    }

    // Revoke-by-name consults the same matrix, FAIL CLOSED: if ANY resolvable row of the name is
    // denied, the whole request 403s and NOTHING is revoked — a name is not a licence to kill
    // whichever subset happens to be permitted.
    public function test_revoke_by_name_fails_closed_when_any_row_of_the_name_is_denied(): void
    {
        $headers = $this->adminHeaders();

        ApiToken::factory()->create([
            'name' => 'mixed',
            'token_hash' => hash('sha256', 'mixed-allowed-secret'),
            'subject_type' => SubjectType::ExternalConsumer->value,
            'subject_ref' => 'tenant-a',
        ]);
        ApiToken::factory()->create([
            'name' => 'mixed',
            'token_hash' => hash('sha256', 'mixed-denied-secret'),
            'subject_type' => SubjectType::ExternalConsumer->value,
            'subject_ref' => 'tenant-b',
        ]);

        $this->bindMatrix(static fn (CredentialVerb $verb, ?Subject $subject): bool => $verb !== CredentialVerb::Revoke || $subject?->ref === 'tenant-a');

        $this->deleteJson('/api/credentials/mixed', [], $headers)->assertForbidden();

        $this->assertSame('mixed', (new TokenRegistry)->resolve('mixed-allowed-secret'));
        $this->assertSame('mixed', (new TokenRegistry)->resolve('mixed-denied-secret'));

        // With every row permitted, the name verb keeps its existing semantics: EVERY resolvable
        // row of the name dies in one request.
        $this->bindMatrix(static fn (): bool => true);

        $this->deleteJson('/api/credentials/mixed', [], $headers)->assertNoContent();

        $this->assertNull((new TokenRegistry)->resolve('mixed-allowed-secret'));
        $this->assertNull((new TokenRegistry)->resolve('mixed-denied-secret'));
    }

    // Locked AC4 — list_metadata granularity is PER-ROW FILTERING: denied rows drop out of the
    // listing; a blanket deny yields an empty 200, not a 403.
    public function test_a_declaration_denying_list_metadata_filters_rows_per_subject(): void
    {
        $headers = $this->adminHeaders();

        ApiToken::factory()->create([
            'name' => 'visible',
            'subject_type' => SubjectType::ExternalConsumer->value,
            'subject_ref' => 'tenant-a',
        ]);
        ApiToken::factory()->create([
            'name' => 'hidden',
            'subject_type' => SubjectType::ExternalConsumer->value,
            'subject_ref' => 'tenant-b',
        ]);

        $this->bindMatrix(static fn (CredentialVerb $verb, ?Subject $subject): bool => $verb !== CredentialVerb::ListMetadata || $subject?->ref === 'tenant-a');

        // The admin row itself has no subject, so a tenant-scoped matrix hides it too — the
        // null subject reaches the declaration honestly and the declaration decides.
        $this->assertSame(
            ['visible'],
            array_column($this->getJson('/api/credentials', $headers)->assertOk()->json(), 'name'),
        );

        $this->bindMatrix(static fn (CredentialVerb $verb): bool => $verb !== CredentialVerb::ListMetadata);

        $this->getJson('/api/credentials', $headers)
            ->assertOk()
            ->assertExactJson([]);
    }

    // The issue verb runs through the matrix too: denying `issue` blocks the POST despite the
    // valid admin token, and nothing is minted.
    public function test_a_declaration_denying_issue_blocks_the_store_route(): void
    {
        $headers = $this->adminHeaders();

        $this->bindMatrix(static fn (CredentialVerb $verb): bool => $verb !== CredentialVerb::Issue);

        $this->postJson('/api/credentials', ['name' => 'refused'], $headers)->assertForbidden();

        $this->assertFalse(ApiToken::query()->where('name', 'refused')->exists());
    }

    // The hook receives real verb context: the verb enum and the TARGET row's subject.
    public function test_the_hook_receives_the_verb_and_the_target_rows_subject(): void
    {
        $headers = $this->adminHeaders();

        $seen = [];

        $this->bindMatrix(static function (CredentialVerb $verb, ?Subject $subject) use (&$seen): bool {
            $seen[] = [$verb, $subject?->type, $subject?->ref];

            return true;
        });

        $token = ApiToken::factory()->create([
            'name' => 'observed',
            'subject_type' => SubjectType::Installation->value,
            'subject_ref' => 'install-9',
        ]);

        $this->deleteJson('/api/credentials/id/'.$token->id, [], $headers)->assertNoContent();

        $this->assertContains([CredentialVerb::Revoke, SubjectType::Installation, 'install-9'], $seen);
    }

    /**
     * Bind a declaration whose verb matrix is the given closure — the
     * package's opt-in AuthorizesCredentialVerbs contract, minus boilerplate.
     *
     * @param  Closure(CredentialVerb, ?Subject, Request): bool|Closure(CredentialVerb, ?Subject): bool|Closure(CredentialVerb): bool|Closure(): bool  $matrix
     */
    private function bindMatrix(Closure $matrix): void
    {
        $this->app->bind(CredentialDeclaration::class, static fn (): CredentialDeclaration => new class($matrix) implements AuthorizesCredentialVerbs, CredentialDeclaration
        {
            public function __construct(private readonly Closure $matrix) {}

            public function resolveSubject(Request $request): ?Subject
            {
                return null;
            }

            public function authorize(Credential $credential, ?string $ability, Request $request): bool
            {
                return true;
            }

            public function authorizeVerb(CredentialVerb $verb, ?Subject $subject, Request $request): bool
            {
                return (bool) ($this->matrix)($verb, $subject, $request);
            }
        });
    }

    /**
     * @return array{Authorization: string}
     */
    private function adminHeaders(string $plaintext = 'authority-admin-secret'): array
    {
        ApiToken::factory()->create([
            'name' => 'admin',
            'token_hash' => hash('sha256', $plaintext),
            'abilities' => [Scope::Admin->value],
        ]);

        return ['Authorization' => 'Bearer '.$plaintext];
    }
}
