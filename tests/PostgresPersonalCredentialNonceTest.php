<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Audit\AppActionEvent;
use ArtisanBuild\BuiltForCloud\Audit\AppActionOutboxEntry;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialOutboxEntry;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\OnboardingToken;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\UiPersonalCredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Tests\Support\PostgresLane;
use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Symfony\Component\Process\Process;

uses(PostgresLane::class)->group('pgsql');

it('lets exactly one concurrent personal issue POST consume a submission nonce', function (): void {
    UiPersonalCredentialDeclaration::$kinds = [CredentialKind::Bearer];
    UiPersonalCredentialDeclaration::$abilities = [OperatorAbility::McpRead->value];
    UiPersonalCredentialDeclaration::$deniedVerbs = [];
    UiPersonalCredentialDeclaration::$resolvesSubject = true;
    UiPersonalCredentialDeclaration::$subjectRef = null;
    config([
        'auth.guards.bfc' => ['driver' => 'bfc', 'provider' => 'users'],
        'built-for-cloud.credentials.declaration' => UiPersonalCredentialDeclaration::class,
        'built-for-cloud.credentials.app_purposes' => [
            'test.consume' => CredentialPurpose::Consumption->value,
        ],
        'built-for-cloud.ui.credential_purposes' => ['test.consume'],
        'built-for-cloud.ui.personal_credentials' => true,
    ]);

    $user = User::query()->create([
        'name' => 'Concurrent personal credential user',
        'email' => 'concurrent-personal-credential@example.test',
        'password' => bcrypt('test-created-password'),
    ]);
    $user->forceFill([
        'role' => UserRole::Member->value,
        'status' => 'active',
        'email_verified_at' => now(),
    ])->save();

    $action = route('bfc.ui.personal-credentials.store');
    $page = $this->actingAsVersioned($user, 'web')->get(route('bfc.ui.personal-credentials.index'));
    $page->assertOk();
    $matched = preg_match(
        '/<form[^>]+action="'.preg_quote($action, '/').'".*?name="submission_nonce" value="([a-f0-9]{64})"/s',
        (string) $page->getContent(),
        $matches,
    );
    expect($matched)->toBe(1);
    $nonce = $matches[1];
    $sessionToken = session()->token();
    $before = [
        'credentials' => Credential::query()->count(),
        'audits' => CredentialAuditEvent::query()->count(),
        'outbox' => CredentialOutboxEntry::query()->count(),
        'onboarding' => OnboardingToken::query()->count(),
        'app_actions' => AppActionEvent::query()->count(),
        'app_action_outbox' => AppActionOutboxEntry::query()->count(),
    ];

    $main = $this->postgresLaneConnection();
    $main->beginTransaction();
    $locked = $main->table('bfc_submission_nonces')
        ->where('nonce_hash', hash('sha256', $nonce))
        ->lockForUpdate()
        ->first();
    expect($locked)->not->toBeNull();
    $workers = [];

    try {
        foreach ([1, 2] as $worker) {
            $process = new Process([PHP_BINARY, __DIR__.'/Fixtures/personal-submission-nonce-worker.php']);
            $process->setInput(json_encode([
                'worker' => $worker,
                'user_id' => (string) $user->getKey(),
                'session_token' => $sessionToken,
                'submission_nonce' => $nonce,
            ], JSON_THROW_ON_ERROR));
            $process->start();
            $workers[] = $process;
        }

        $bothBlocked = false;

        foreach (range(1, 5000) as $ignored) {
            foreach ($workers as $worker) {
                if (! $worker->isRunning()) {
                    throw new RuntimeException(
                        'A personal issue worker exited before the nonce row was released: '
                        .$worker->getOutput().$worker->getErrorOutput(),
                    );
                }
            }

            $blocked = (int) $this->postgresLaneProbe()->scalar(<<<'SQL'
                select count(*)
                from pg_stat_activity
                where datname = current_database()
                  and application_name like 'bfc-p5-ui-d-nonce-worker-%'
                  and state = 'active'
                  and wait_event_type = 'Lock'
                  and query like '%bfc_submission_nonces%'
                SQL);

            if ($blocked === count($workers)) {
                $bothBlocked = true;
                break;
            }
        }

        expect($bothBlocked)->toBeTrue();
        $main->commit();
        $results = [];

        foreach ($workers as $worker) {
            $worker->wait();
            expect($worker->isSuccessful())->toBeTrue($worker->getErrorOutput());
            $results[] = json_decode($worker->getOutput(), true, flags: JSON_THROW_ON_ERROR);
        }

        $statuses = array_column($results, 'status');
        sort($statuses);
        $after = [
            'credentials' => Credential::query()->count(),
            'audits' => CredentialAuditEvent::query()->count(),
            'outbox' => CredentialOutboxEntry::query()->count(),
            'onboarding' => OnboardingToken::query()->count(),
            'app_actions' => AppActionEvent::query()->count(),
            'app_action_outbox' => AppActionOutboxEntry::query()->count(),
        ];

        expect($statuses)->toBe([201, 409])
            ->and(array_filter($results, static fn (array $result): bool => $result['has_delivery']))->toHaveCount(1)
            ->and($after)->toBe([
                'credentials' => $before['credentials'] + 1,
                'audits' => $before['audits'] + 1,
                'outbox' => $before['outbox'] + 1,
                'onboarding' => $before['onboarding'],
                'app_actions' => $before['app_actions'],
                'app_action_outbox' => $before['app_action_outbox'],
            ]);
    } finally {
        foreach ($workers as $worker) {
            if ($worker->isRunning()) {
                $worker->stop();
            }
        }

        if ($main->transactionLevel() > 0) {
            $main->rollBack();
        }
    }
});
