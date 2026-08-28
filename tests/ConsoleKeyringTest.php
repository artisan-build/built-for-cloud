<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Console\ConsoleKey;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyring;
use Carbon\CarbonImmutable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use ParagonIE\Paseto\Keys\Version4\AsymmetricSecretKey;
use ParagonIE\Paseto\Protocol\Version4;

uses(RefreshDatabase::class);

/**
 * The app's copy of the vendor's PUBLIC console keys (Console PRD D12):
 * what it will store, what it structurally CANNOT store, and the
 * two-step make-before-break lifecycle that lets a live deployment be
 * re-keyed without an outage.
 */

// ------------------------------------------------ public material only

it('refuses to store anything that is not a 32-byte ed25519 public key (locked AC 10)', function (): void {
    $keyring = new ConsoleKeyring;

    $rejected = [
        '',
        'not-a-key',
        bin2hex(random_bytes(16)),   // 16 bytes
        bin2hex(random_bytes(31)),   // one byte short
        bin2hex(random_bytes(33)),   // one byte long
        str_repeat('z', 64),         // right length, not hex or base64url
        '-----BEGIN PUBLIC KEY-----',
    ];

    foreach ($rejected as $material) {
        expect(fn (): ConsoleKey => $keyring->add('k-'.bin2hex(random_bytes(4)), $material))
            ->toThrow(InvalidArgumentException::class);
    }

    expect(ConsoleKey::query()->count())->toBe(0);
});

it('refuses the private half of a keypair outright (locked AC 10)', function (): void {
    $secret = AsymmetricSecretKey::generate(new Version4);

    // A v4 Ed25519 SECRET key is 64 bytes; the ring takes 32-byte public
    // keys and nothing else, so the one delivery that would give this
    // app signing authority it must never hold cannot be filed at all.
    expect(fn (): ConsoleKey => (new ConsoleKeyring)->add('k1', $secret->encode()))
        ->toThrow(InvalidArgumentException::class)
        ->and(fn (): ConsoleKey => (new ConsoleKeyring)->add('k1', bin2hex($secret->raw())))
        ->toThrow(InvalidArgumentException::class);

    expect(ConsoleKey::query()->count())->toBe(0);
});

it('has no column capable of holding private key material (locked AC 10)', function (): void {
    $columns = Schema::getColumnListing('bfc_console_keys');

    sort($columns);

    // The whole schema, enumerated: a private-key column could only
    // arrive by editing this list, which is exactly the review moment
    // this assertion exists to force.
    expect($columns)->toBe([
        'activated_at',
        'created_at',
        'id',
        'key_id',
        'public_key',
        'retired_at',
        'updated_at',
    ]);

    foreach ($columns as $column) {
        expect($column)->not->toMatch('/secret|private|seed|signing|cipher/i');
    }

    // And the model itself will not mass-assign one into existence.
    expect((new ConsoleKey)->getFillable())
        ->toBe(['id', 'key_id', 'public_key', 'activated_at', 'retired_at']);
});

it('stores the delivered public key as hex whichever encoding it arrived in', function (): void {
    $secret = AsymmetricSecretKey::generate(new Version4);
    $public = $secret->getPublicKey();

    $keyring = new ConsoleKeyring;
    $keyring->add('k-hex', $public->toHexString());
    $keyring->add('k-base64url', $public->encode());

    /** @var stdClass $hexRow */
    $hexRow = DB::table('bfc_console_keys')->where('key_id', 'k-hex')->first();
    /** @var stdClass $base64Row */
    $base64Row = DB::table('bfc_console_keys')->where('key_id', 'k-base64url')->first();

    // One key delivered two ways is one key, not two: the stored form is
    // identical, so no transport can smuggle in a second identity for
    // material the app already trusts.
    expect($hexRow->public_key)->toBe($public->toHexString())
        ->and($base64Row->public_key)->toBe($public->toHexString())
        ->and(strlen((string) $hexRow->public_key))->toBe(64);
});

it('refuses a key id outside the bounded charset', function (): void {
    $keyring = new ConsoleKeyring;
    $public = AsymmetricSecretKey::generate(new Version4)->getPublicKey()->toHexString();

    foreach (['', "k1\n", 'k 1', 'k/1', str_repeat('k', 65), '{"kid":"k1"}'] as $keyId) {
        expect(fn (): ConsoleKey => $keyring->add($keyId, $public))
            ->toThrow(InvalidArgumentException::class);
    }
});

it('refuses to overwrite the material behind a key id already on file', function (): void {
    $keyring = new ConsoleKeyring;
    $original = AsymmetricSecretKey::generate(new Version4)->getPublicKey()->toHexString();
    $replacement = AsymmetricSecretKey::generate(new Version4)->getPublicKey()->toHexString();

    $keyring->add('k1', $original);

    // Substituting the key behind a trusted `kid` is the one write that
    // would let mis-delivered material inherit an existing trust.
    expect(fn (): ConsoleKey => $keyring->add('k1', $replacement))
        ->toThrow(InvalidArgumentException::class);

    expect($keyring->find('k1')?->public_key)->toBe($original);
});

// --------------------------------------------------- the key lifecycle

it('files a key as pending and starts trusting it only when it is activated', function (): void {
    $keyring = new ConsoleKeyring;
    $public = AsymmetricSecretKey::generate(new Version4)->getPublicKey()->toHexString();

    $key = $keyring->add('k1', $public);

    expect($key->activated_at)->toBeNull()
        ->and($keyring->active())->toBe([]);

    $keyring->activate('k1');

    expect($keyring->active())->toHaveCount(1)
        ->and($keyring->find('k1')?->activated_at)->not->toBeNull();
});

it('activates without retiring anything and retires as a separate later step', function (): void {
    $keyring = new ConsoleKeyring;

    foreach (['k1', 'k2'] as $keyId) {
        $keyring->add($keyId, AsymmetricSecretKey::generate(new Version4)->getPublicKey()->toHexString());
        $keyring->activate($keyId);
    }

    // Two keys active at once IS make-before-break; activation is not a
    // cutover and never touches the outgoing key.
    expect(array_map(static fn (ConsoleKey $key): string => $key->key_id, $keyring->active()))
        ->toBe(['k1', 'k2']);

    $keyring->retire('k1');

    expect(array_map(static fn (ConsoleKey $key): string => $key->key_id, $keyring->active()))
        ->toBe(['k2'])
        ->and($keyring->find('k1')?->retired_at)->not->toBeNull()
        ->and($keyring->find('k1')?->activated_at)->not->toBeNull();
});

it('does not reset an already activated or already retired key', function (): void {
    $keyring = new ConsoleKeyring;
    $keyring->add('k1', AsymmetricSecretKey::generate(new Version4)->getPublicKey()->toHexString());

    $this->travelTo(CarbonImmutable::parse('2026-08-28T12:00:00+00:00'));
    $keyring->activate('k1');
    $activatedAt = $keyring->find('k1')?->activated_at;

    $this->travelTo(CarbonImmutable::parse('2026-08-28T13:00:00+00:00'));
    $keyring->activate('k1');
    $keyring->retire('k1');
    $retiredAt = $keyring->find('k1')?->retired_at;

    $this->travelTo(CarbonImmutable::parse('2026-08-28T14:00:00+00:00'));
    $keyring->retire('k1');

    expect($keyring->find('k1')?->activated_at?->toAtomString())->toBe($activatedAt?->toAtomString())
        ->and($keyring->find('k1')?->retired_at?->toAtomString())->toBe($retiredAt?->toAtomString());
});

it('refuses to activate or retire a key id nobody filed', function (): void {
    $keyring = new ConsoleKeyring;

    expect(fn (): ConsoleKey => $keyring->activate('k-nobody'))->toThrow(InvalidArgumentException::class)
        ->and(fn (): ConsoleKey => $keyring->retire('k-nobody'))->toThrow(InvalidArgumentException::class)
        ->and($keyring->find('k-nobody'))->toBeNull();
});
