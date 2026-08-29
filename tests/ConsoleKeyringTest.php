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
        // Unparseable encodings: neither hex nor base64url, so nothing
        // is decoded and no length is guessed at. (`z` is IN the
        // base64url alphabet — a string of them decodes fine and is
        // refused on length instead, which is a different branch, so
        // these cases use characters that appear in neither encoding.)
        '',
        'not-a-key',
        str_repeat('*', 64),
        'AAAA+AAAA/AAAA==',
        '-----BEGIN PUBLIC KEY-----',
        // Right encoding, wrong length.
        bin2hex(random_bytes(16)),   // 16 bytes
        bin2hex(random_bytes(31)),   // one byte short
        bin2hex(random_bytes(33)),   // one byte long
        str_repeat('z', 64),         // decodes as base64url to 48 bytes
    ];

    foreach ($rejected as $material) {
        expect(fn (): ConsoleKey => $keyring->add('k-'.bin2hex(random_bytes(4)), $material))
            ->toThrow(InvalidArgumentException::class);
    }

    expect(ConsoleKey::query()->count())->toBe(0);
});

it('refuses 32 bytes that are not a usable ed25519 point (locked AC 10)', function (): void {
    $keyring = new ConsoleKeyring;

    // Fixed values, not random ones, deliberately: roughly one random
    // 32-byte string in twenty IS a valid point, so a random fixture
    // would make this test flake. Each of these was checked to fail
    // libsodium's point test — all-zero and all-ones are small-order /
    // non-canonical, the third is a value that simply does not decode
    // to a curve point.
    $notPoints = [
        str_repeat('00', 32),
        str_repeat('ff', 32),
        '4eee3cfe6c43f0deb6c655ebd4a89800cd292dfbaf811fe548261ff0b1e7d6e2',
    ];

    foreach ($notPoints as $material) {
        expect(strlen((string) hex2bin($material)))->toBe(32)
            ->and(fn (): ConsoleKey => $keyring->add('k-'.bin2hex(random_bytes(4)), $material))
            ->toThrow(InvalidArgumentException::class);
    }

    // Every real public key passes, which is the half that matters:
    // the check must never refuse a key the vendor actually delivered.
    foreach (range(1, 25) as $ignored) {
        $public = AsymmetricSecretKey::generate(new Version4)->getPublicKey()->toHexString();

        expect($keyring->add('k-'.bin2hex(random_bytes(4)), $public)->public_key)->toBe($public);
    }
});

it('refuses the 64-byte expanded secret key on length (locked AC 10)', function (): void {
    $secret = AsymmetricSecretKey::generate(new Version4);

    // A v4 Ed25519 SECRET key is 64 bytes and the ring takes 32, so the
    // delivery that would hand this app signing authority it must never
    // hold cannot be filed — in either encoding.
    expect(fn (): ConsoleKey => (new ConsoleKeyring)->add('k1', $secret->encode()))
        ->toThrow(InvalidArgumentException::class)
        ->and(fn (): ConsoleKey => (new ConsoleKeyring)->add('k1', bin2hex($secret->raw())))
        ->toThrow(InvalidArgumentException::class);

    expect(ConsoleKey::query()->count())->toBe(0);
});

it('cannot tell a 32-byte seed from a public key, so custody is the protocol\'s job not the ring\'s', function (): void {
    // The uncomfortable truth this test pins, so no docblock can drift
    // away from it: an Ed25519 SEED is the private half in compact form
    // and is 32 bytes, exactly like a public key. This one — a fixed
    // fixture, chosen because it also happens to encode a valid curve
    // point, as roughly one in twenty random values does — files
    // happily. Nothing about the bytes gives it away.
    $seed = hex2bin('d1908fa3b5e26f4b0c4367bf676107ec45fb0e4305c68b8fea0fdb99dfb27cb2');
    $keypair = sodium_crypto_sign_seed_keypair((string) $seed);

    // It is genuinely private material: it derives a real signing key.
    expect(strlen(sodium_crypto_sign_secretkey($keypair)))->toBe(64);

    $filed = (new ConsoleKeyring)->add('k-seed', bin2hex((string) $seed));

    expect($filed->public_key)->toBe(bin2hex((string) $seed));

    // Which is why the custody guarantee lives elsewhere: the vendor
    // hands over public halves only, nothing in this package asks for or
    // transports a private one, and — decisively — there is no code path
    // here that signs anything, so a seed filed by mistake is inert. It
    // is not a key the ring could ever use to mint an assertion.
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

    // Delivered as unpadded base64url — what PASETO's own encode() emits.
    $keyring->add('k-base64url', $public->encode());

    /** @var stdClass $base64Row */
    $base64Row = DB::table('bfc_console_keys')->where('key_id', 'k-base64url')->first();

    expect($base64Row->public_key)->toBe($public->toHexString())
        ->and(strlen((string) $base64Row->public_key))->toBe(64);

    // One key delivered two ways is ONE key: normalizing to a single
    // stored form is exactly what lets the material-uniqueness rule see
    // the hex delivery as the same key, rather than as new bytes that
    // could file a second identity for material the app already trusts.
    // (Rework B4 — before the rule, this second add() succeeded.)
    expect(fn (): ConsoleKey => $keyring->add('k-hex', $public->toHexString()))
        ->toThrow(InvalidArgumentException::class);

    expect(ConsoleKey::query()->count())->toBe(1);
});

it('refuses material already on file, in every lifecycle state including retired (rework B4)', function (): void {
    $keyring = new ConsoleKeyring;
    $public = AsymmetricSecretKey::generate(new Version4)->getPublicKey()->toHexString();

    // Pending.
    $keyring->add('k1', $public);
    expect(fn (): ConsoleKey => $keyring->add('k1-again', $public))->toThrow(InvalidArgumentException::class);

    // Active.
    $keyring->activate('k1');
    expect(fn (): ConsoleKey => $keyring->add('k1-again', $public))->toThrow(InvalidArgumentException::class);

    // RETIRED — the state that matters. Retirement is the only
    // revocation this design has, so material that could be re-filed
    // under a fresh key id after retirement was never revoked.
    $keyring->retire('k1');
    expect(fn (): ConsoleKey => $keyring->add('k1-again', $public))->toThrow(InvalidArgumentException::class);

    expect(ConsoleKey::query()->count())->toBe(1)
        ->and($keyring->active())->toBe([]);
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
