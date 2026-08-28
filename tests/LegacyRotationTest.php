<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\AuditReason;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\Exceptions\RotationCutoverIncomplete;
use ArtisanBuild\BuiltForCloud\Exceptions\RotationRefused;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Testing\DetectsSecretLeaks;
use ArtisanBuild\BuiltForCloud\TokenRegistry;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Orchestra\Testbench\Attributes\WithConfig;

/**
 * The legacy `api_tokens` rotation, corrected per D6 (PRD 1.7): the two
 * verified defects fixed — the replacement inherits the exact ability set
 * and remaining expiry of the row it replaces (locked AC 1), and name-based
 * rotation refuses whenever more than one resolvable row shares the name
 * (locked AC 2) — plus the by-id primary verb, its HTTP entry point, and
 * the failure-path contract on this store.
 */
#[WithConfig('built-for-cloud.credential_api.enabled', true, false)]
final class LegacyRotationTest extends TestCase
{
    use DetectsSecretLeaks;
    use RefreshDatabase;

    /**
     * Locked AC 1 — the D6 regression: a token with abilities [consume]
     * and 30 days remaining rotates into a replacement with exactly
     * [consume] and the SAME remaining expiry, and ability checks pass on
     * the replacement. Before the fix the replacement was unscoped and
     * non-expiring, and hasAbility() fails closed — rotation was unusable
     * for any scoped caller.
     */
    public function test_a_scoped_expiring_token_rotates_into_a_scoped_expiring_replacement_that_passes_its_ability_checks(): void
    {
        $registry = new TokenRegistry;
        $expiry = now()->addDays(30);

        $source = $registry->store('scoped-ci', hash('sha256', 'old-scoped-secret'), $expiry, [Scope::Consume->value]);

        ApiToken::query()->whereKey($source->getKey())->update([
            'subject_type' => SubjectType::Application->value,
            'subject_ref' => 'app-1',
        ]);

        $replacement = $registry->rotate('scoped-ci', hash('sha256', 'new-scoped-secret'));

        $this->assertSame([Scope::Consume->value], $replacement->abilities);
        $this->assertTrue($replacement->hasAbility(Scope::Consume->value));
        $this->assertNotNull($replacement->expires_at);
        $this->assertSame($expiry->timestamp, $replacement->expires_at->timestamp);
        $this->assertTrue($replacement->expires_at->lessThanOrEqualTo(now()->addDays(30)));

        // The subject binding rides along (PRD 1.7 point 3).
        $replacement->refresh();
        $this->assertSame(SubjectType::Application, $replacement->subject_type);
        $this->assertSame('app-1', $replacement->subject_ref);

        // And the replacement authenticates as far as the original did.
        $model = $registry->resolveModel('new-scoped-secret');
        $this->assertNotNull($model);
        $this->assertTrue($model->hasAbility(Scope::Consume->value));
    }

    /**
     * Locked AC 2: two resolvable rows of one name refuse the name verb —
     * naming the count, never picking one — while by-id rotates exactly
     * the named row and leaves the same-named sibling untouched.
     */
    public function test_name_based_rotation_refuses_on_two_resolvable_rows_while_by_id_succeeds(): void
    {
        $registry = new TokenRegistry;

        $first = $registry->store('dup', hash('sha256', 'dup-secret-one'), null, [Scope::Consume->value]);
        $second = $registry->store('dup', hash('sha256', 'dup-secret-two'));

        try {
            $registry->rotate('dup', hash('sha256', 'dup-replacement'));
            $this->fail('An ambiguous name-based rotation was performed.');
        } catch (RotationRefused $refused) {
            $this->assertStringContainsString('2 resolvable credentials share the name "dup"', $refused->getMessage());
        }

        $this->assertNull($first->refresh()->rotated_at);
        $this->assertNull($second->refresh()->rotated_at);
        $this->assertSame(2, ApiToken::query()->where('name', 'dup')->count());

        $replacement = $registry->rotateById($first->id, hash('sha256', 'dup-replacement'));

        $this->assertSame([Scope::Consume->value], $replacement->abilities);
        $this->assertNotNull($first->refresh()->rotated_at);
        $this->assertNull($second->refresh()->rotated_at);
        $this->assertNull($second->expires_at);
    }

    public function test_rotating_an_unknown_name_refuses_rather_than_minting(): void
    {
        $this->expectException(RotationRefused::class);
        $this->expectExceptionMessage('No resolvable credential is named "ghost"');

        (new TokenRegistry)->rotate('ghost', hash('sha256', 'ghost-secret'));
    }

    public function test_rotating_a_dead_row_by_id_refuses(): void
    {
        $registry = new TokenRegistry;

        $dead = $registry->store('dead', hash('sha256', 'dead-secret'));
        $registry->revokeById($dead->id);

        $this->expectException(RotationRefused::class);
        $this->expectExceptionMessage('no longer resolves');

        $registry->rotateById($dead->id, hash('sha256', 'dead-replacement'));
    }

    public function test_the_cli_name_verb_reports_ambiguity_as_a_clean_failure(): void
    {
        $registry = new TokenRegistry;
        $registry->store('dup', hash('sha256', 'cli-dup-one'));
        $registry->store('dup', hash('sha256', 'cli-dup-two'));

        $this->assertSame(1, Artisan::call('token:rotate', ['name' => 'dup', '--local' => true]));

        $output = Artisan::output();

        $this->assertStringContainsString('2 resolvable credentials share the name "dup"', $output);
        $this->assertStringNotContainsString('shown once', $output);
        $this->assertSame(2, ApiToken::query()->where('name', 'dup')->count());
    }

    public function test_rotate_by_id_stamps_the_old_row_and_records_lineage(): void
    {
        $registry = new TokenRegistry;

        $source = $registry->store('lineage', hash('sha256', 'lineage-old'));
        $replacement = $registry->rotateById($source->id, hash('sha256', 'lineage-new'));

        $this->assertNotNull($source->refresh()->rotated_at);

        $rotated = CredentialAuditEvent::query()
            ->where('credential_id', $source->id)
            ->where('event', LifecycleEventType::Rotated->value)
            ->sole();

        $this->assertSame((string) $replacement->getKey(), $rotated->superseded_by_credential_id);
        $this->assertSame(AuditReason::Rotation, $rotated->reason_code);
    }

    /**
     * The by-id HTTP entry point on the PR5 route pattern: the replacement
     * inherits scope and expiry, the plaintext appears exactly once in the
     * response, and nothing leaks into any side-effect channel.
     */
    public function test_the_http_by_id_route_rotates_and_reveals_the_plaintext_exactly_once(): void
    {
        $registry = new TokenRegistry;
        $expiry = now()->addDays(7);

        $source = $registry->store('http-rotate', hash('sha256', 'http-rotate-old'), $expiry, [Scope::Consume->value]);

        $response = $this->assertNoSecretLeakageOfMinted(
            fn () => $this->postJson(
                '/api/credentials/id/'.$source->id.'/rotate',
                [],
                $this->legacyAdminHeaders(),
            ),
            fn ($response): ?string => $response->json('plaintext'),
        );

        $response->assertCreated()
            ->assertJsonPath('name', 'http-rotate')
            ->assertJsonPath('abilities', [Scope::Consume->value])
            ->assertJsonPath('superseded_id', $source->id);

        $plaintext = (string) $response->json('plaintext');

        $this->assertRevealsSecretExactlyOnce((string) $response->getContent(), $plaintext);

        $replacement = ApiToken::query()->where('token_hash', hash('sha256', $plaintext))->sole();

        $this->assertSame([Scope::Consume->value], $replacement->abilities);
        $this->assertNotNull($replacement->expires_at);
        $this->assertSame($expiry->timestamp, $replacement->expires_at->timestamp);
        $this->assertNotNull($source->refresh()->rotated_at);
        $this->assertNotNull($source->expires_at);
        $this->assertTrue($source->expires_at->lessThanOrEqualTo(now()->addHour()));
    }

    public function test_the_http_by_id_route_handles_missing_and_dead_rows(): void
    {
        $registry = new TokenRegistry;

        $this->postJson('/api/credentials/id/no-such-id/rotate', [], $this->legacyAdminHeaders())
            ->assertNotFound();

        $dead = $registry->store('http-dead', hash('sha256', 'http-dead-secret'));
        $registry->revokeById($dead->id);

        $refusal = $this->postJson('/api/credentials/id/'.$dead->id.'/rotate', [], $this->legacyAdminHeaders())
            ->assertStatus(409);

        $this->assertStringContainsString('no longer resolves', (string) $refusal->json('message'));
    }

    public function test_the_http_by_id_route_honors_emergency(): void
    {
        $registry = new TokenRegistry;

        $source = $registry->store('http-emergency', hash('sha256', 'http-emergency-old'));

        $this->postJson(
            '/api/credentials/id/'.$source->id.'/rotate',
            ['emergency' => true],
            $this->legacyAdminHeaders(),
        )->assertCreated();

        $source->refresh();

        $this->assertNotNull($source->rotated_at);
        $this->assertNotNull($source->expires_at);
        $this->assertTrue($source->expires_at->lessThanOrEqualTo(now()));
        $this->assertNull((new TokenRegistry)->resolve('http-emergency-old'));
    }

    /**
     * Failure path B on this store (locked AC 8): the cutover write fails,
     * the committed replacement stands, the old row stays visible with its
     * stamp, the error names the leftover id — and revoke-by-id can always
     * kill it.
     */
    public function test_a_failed_cutover_leaves_the_replacement_standing_and_the_old_row_killable_by_id(): void
    {
        $registry = new TokenRegistry;

        $source = $registry->store('cutover', hash('sha256', 'cutover-old'), null, [Scope::Consume->value]);

        DB::statement("CREATE TRIGGER bfc_fail_legacy_cutover BEFORE UPDATE OF expires_at ON api_tokens WHEN NEW.rotated_at IS NOT NULL BEGIN SELECT RAISE(ABORT, 'forced cutover failure'); END");

        $incomplete = null;

        try {
            $registry->rotateById($source->id, hash('sha256', 'cutover-new'));
        } catch (RotationCutoverIncomplete $caught) {
            $incomplete = $caught;
        }

        $this->assertNotNull($incomplete, 'The forced cutover failure did not surface.');
        $this->assertStringContainsString($source->id, $incomplete->getMessage());
        $this->assertSame($source->id, $incomplete->supersededId);

        // The replacement stands, correctly scoped; the old row is still
        // resolvable, stamped, and untouched at its original expiry.
        $replacement = ApiToken::query()->where('token_hash', hash('sha256', 'cutover-new'))->sole();
        $this->assertSame([Scope::Consume->value], $replacement->abilities);
        $this->assertSame($replacement->id, $incomplete->replacementId);

        $source->refresh();
        $this->assertNotNull($source->rotated_at);
        $this->assertNull($source->expires_at);
        $this->assertSame('cutover', (new TokenRegistry)->resolve('cutover-old'));

        DB::statement('DROP TRIGGER bfc_fail_legacy_cutover');

        // The stated cleanup: the precise verb kills exactly the leftover.
        $this->assertTrue($registry->revokeById($source->id));
        $this->assertNull((new TokenRegistry)->resolve('cutover-old'));
        $this->assertSame('cutover', (new TokenRegistry)->resolve('cutover-new'));
    }

    /**
     * The never-extend rule at cutover: an old row already dying sooner
     * than grace end keeps its earlier death.
     */
    public function test_the_grace_window_never_extends_an_earlier_expiry(): void
    {
        $registry = new TokenRegistry;
        $expiry = now()->addMinutes(10);

        $source = $registry->store('short-lived', hash('sha256', 'short-old'), $expiry);
        $replacement = $registry->rotate('short-lived', hash('sha256', 'short-new'));

        $source->refresh();

        $this->assertNotNull($source->expires_at);
        $this->assertSame($expiry->timestamp, $source->expires_at->timestamp);
        $this->assertNotNull($replacement->expires_at);
        $this->assertSame($expiry->timestamp, $replacement->expires_at->timestamp);
    }

    /**
     * @return array{Authorization: string}
     */
    private function legacyAdminHeaders(): array
    {
        $plaintext = 'legacy-rotation-admin-'.bin2hex(random_bytes(8));

        ApiToken::query()->create([
            'name' => 'legacy-rotation-admin',
            'token_hash' => hash('sha256', $plaintext),
            'abilities' => [Scope::Admin->value],
        ]);

        return ['Authorization' => 'Bearer '.$plaintext];
    }
}
