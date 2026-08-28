<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\Database\MintInitialOwnershipClaim;
use ArtisanBuild\BuiltForCloud\OwnershipClaim;
use ArtisanBuild\BuiltForCloud\Scope;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Log\Events\MessageLogged;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;

uses(RefreshDatabase::class);

/**
 * The D7 bug fix (PRD 1.14, BUG-FIX class, floors mutation-verified): the
 * install migration's initial ownership-claim mint used to write the
 * PLAINTEXT admin-yielding claim token into the application log. The mint
 * now logs the claim row id and timestamp only, and it is flag-gated
 * behind the `data_migrations` surface family.
 *
 * The killing assertions are SEMANTIC, not cosmetic: every string the
 * mint logs — messages, context keys and values, and every 64-hex
 * substring inside them — is hashed and compared against the stored
 * claim's token_hash, so re-introducing the plaintext log line (the
 * named mutation) turns this suite red no matter what key it hides
 * under; the exact-context-shape assertion catches it a second way.
 */

/**
 * Run the mint while capturing every log record emitted.
 *
 * @return list<array{message: string, context: array<array-key, mixed>}>
 */
function captureMintLogs(): array
{
    $records = [];

    Event::listen(MessageLogged::class, function (MessageLogged $event) use (&$records): void {
        $records[] = ['message' => $event->message, 'context' => $event->context];
    });

    app(MintInitialOwnershipClaim::class)();

    return $records;
}

/**
 * Every string the captured records carry, flattened: messages, context
 * keys, context values (stringified).
 *
 * @param  list<array{message: string, context: array<array-key, mixed>}>  $records
 * @return list<string>
 */
function flattenLoggedStrings(array $records): array
{
    $strings = [];

    foreach ($records as $record) {
        $strings[] = $record['message'];

        foreach ($record['context'] as $key => $value) {
            $strings[] = (string) $key;
            $strings[] = is_string($value) ? $value : (string) json_encode($value);
        }
    }

    return $strings;
}

it('mints the pending claim and logs NO plaintext token — ids and timestamps only', function (): void {
    $records = captureMintLogs();

    /** @var OwnershipClaim $claim */
    $claim = OwnershipClaim::query()->sole();

    // The mint happened, only the hash reached storage, and the row is
    // pending (an operator claims it after re-minting a deliverable code).
    expect($claim->consumed_at)->toBeNull()
        ->and($claim->token_hash)->toMatch('/^[0-9a-f]{64}$/');

    // The semantic no-plaintext assertion: nothing logged — no message,
    // no context key, no context value, no 64-hex substring within any of
    // them — hashes to the stored token_hash. The plaintext is the ONLY
    // string in the world with that property.
    foreach (flattenLoggedStrings($records) as $logged) {
        expect(hash('sha256', $logged))->not->toBe($claim->token_hash);

        preg_match_all('/[0-9a-f]{64}/', $logged, $matches);

        foreach ($matches[0] as $hexRun) {
            expect(hash('sha256', $hexRun))->not->toBe($claim->token_hash);
        }
    }

    // And the log line's exact bounded shape: one record, id + timestamp
    // context and nothing else — a smuggled claim_token key cannot hide.
    expect($records)->toHaveCount(1)
        ->and(array_keys($records[0]['context']))->toBe(['claim_id', 'minted_at'])
        ->and($records[0]['context']['claim_id'])->toBe($claim->id)
        ->and($records[0]['message'])->toContain('bfc:ownership:mint-claim');
});

it('is flag-gated behind the data_migrations surface family', function (): void {
    config(['built-for-cloud.surfaces.data_migrations' => false]);

    $records = captureMintLogs();

    expect(OwnershipClaim::query()->count())->toBe(0)
        ->and($records)->toBe([]);
});

it('mints nothing when a pending claim already exists', function (): void {
    OwnershipClaim::query()->create([
        'id' => (string) Str::uuid(),
        'token_hash' => hash('sha256', 'already-pending'),
    ]);

    $records = captureMintLogs();

    expect(OwnershipClaim::query()->count())->toBe(1)
        ->and($records)->toBe([]);
});

it('mints nothing on a claimed instance', function (): void {
    $ownerToken = ApiToken::query()->create([
        'name' => 'owner',
        'token_hash' => hash('sha256', 'owner-secret'),
        'abilities' => [Scope::Admin->value],
    ]);

    DB::table('ownership')->insert([
        'id' => (string) Str::uuid(),
        'owner_token_id' => $ownerToken->getKey(),
        'created_at' => now(),
        'updated_at' => now(),
    ]);

    $records = captureMintLogs();

    expect(OwnershipClaim::query()->count())->toBe(0)
        ->and($records)->toBe([]);
});
