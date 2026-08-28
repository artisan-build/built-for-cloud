<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Console\AssertionRefusalReason;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyring;
use ArtisanBuild\BuiltForCloud\Console\ConsoleRole;
use ArtisanBuild\BuiltForCloud\Exceptions\AssertionRefused;
use Carbon\CarbonImmutable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use ParagonIE\Paseto\Builder;
use ParagonIE\Paseto\Keys\SymmetricKey;
use ParagonIE\Paseto\Keys\Version3\AsymmetricSecretKey as Version3SecretKey;
use ParagonIE\Paseto\Protocol\Version3;
use ParagonIE\Paseto\Protocol\Version4;
use ParagonIE\Paseto\Purpose;

uses(RefreshDatabase::class);

/**
 * The console assertion's verification core (Console PRD D12/D8/D4/D18,
 * PR1). Every test here drives the ONE choke point — nothing in the
 * package reads a console claim without having verified the whole token.
 */
beforeEach(function (): void {
    config([
        'built-for-cloud.console.issuer' => 'https://scalpels.test',
        'built-for-cloud.console.audience' => 'https://sink.test',
    ]);
});

// ------------------------------------------------------- the happy path

it('verifies an assertion signed by an active key and yields every minted claim (locked AC 1)', function (): void {
    $mintedAt = CarbonImmutable::parse('2026-08-28T12:00:00+00:00');
    $this->travelTo($mintedAt);

    $secret = consoleKeypair();
    consoleFileKey('k1', $secret);

    $token = consoleMint($secret, consoleClaims([
        'sub' => 'operator_7',
        'display_name' => 'Jane Operator',
        'on_behalf_of' => 'Acme Agency',
        'role' => 'member',
        'jti' => 'mint_0001',
    ]));

    $assertion = consoleVerify($token);

    expect($assertion->issuer)->toBe('https://scalpels.test')
        ->and($assertion->subject)->toBe('operator_7')
        ->and($assertion->displayName)->toBe('Jane Operator')
        ->and($assertion->role)->toBe(ConsoleRole::Member)
        ->and($assertion->onBehalfOf)->toBe('Acme Agency')
        ->and($assertion->audience)->toBe('https://sink.test')
        ->and($assertion->issuedAt->toAtomString())->toBe($mintedAt->toAtomString())
        ->and($assertion->expiresAt->toAtomString())->toBe($mintedAt->addSeconds(90)->toAtomString())
        ->and($assertion->keyId)->toBe('k1')
        ->and($assertion->id)->toBe('mint_0001')
        ->and($assertion->isAdmin())->toBeFalse()
        ->and($assertion->attribution())->toBe('Jane Operator (Acme Agency)');
});

it('carries a direct operator with no agency as a null on_behalf_of', function (): void {
    $secret = consoleKeypair();
    consoleFileKey('k1', $secret);

    $assertion = consoleVerify(consoleMint($secret, consoleClaims(['on_behalf_of' => null])));

    expect($assertion->onBehalfOf)->toBeNull()
        ->and($assertion->attribution())->toBe('Jane Operator')
        ->and($assertion->isAdmin())->toBeTrue();
});

// ------------------------------------------------------------- the clock

it('refuses an assertion exactly at exp and accepts one a second earlier (locked AC 2)', function (): void {
    $mintedAt = CarbonImmutable::parse('2026-08-28T12:00:00+00:00');
    $this->travelTo($mintedAt);

    $secret = consoleKeypair();
    consoleFileKey('k1', $secret);

    $token = consoleMint($secret, consoleClaims());
    $expiresAt = $mintedAt->addSeconds(90);

    // One second inside the window — and inside the clock skew, which
    // deliberately buys nothing on this side of the boundary.
    $this->travelTo($expiresAt->subSecond());
    expect(consoleVerify($token)->id)->not->toBeEmpty();

    // Exactly at exp the assertion is dead. Skew never extends it.
    $this->travelTo($expiresAt);
    expect(consoleRefusal($token)->reason)->toBe(AssertionRefusalReason::Expired);

    $this->travelTo($expiresAt->addMinute());
    expect(consoleRefusal($token)->reason)->toBe(AssertionRefusalReason::Expired);
});

it('accepts an assertion minted slightly ahead of this clock and refuses one beyond the skew', function (): void {
    $now = CarbonImmutable::parse('2026-08-28T12:00:00+00:00');
    $this->travelTo($now);

    $secret = consoleKeypair();
    consoleFileKey('k1', $secret);

    // The issuer's clock runs 4 seconds ahead of ours; the configured
    // 5-second skew is spent exactly here.
    $withinSkew = consoleMint($secret, consoleClaims([
        'iat' => $now->addSeconds(4)->toAtomString(),
        'nbf' => $now->addSeconds(4)->toAtomString(),
        'exp' => $now->addSeconds(94)->toAtomString(),
    ]));

    expect(consoleVerify($withinSkew)->subject)->toBe('operator_42');

    $beyondSkew = consoleMint($secret, consoleClaims([
        'iat' => $now->addSeconds(30)->toAtomString(),
        'nbf' => $now->addSeconds(30)->toAtomString(),
        'exp' => $now->addSeconds(120)->toAtomString(),
    ]));

    expect(consoleRefusal($beyondSkew)->reason)->toBe(AssertionRefusalReason::NotYetValid);
});

it('refuses an assertion whose own ttl exceeds this deployment bound even though it has not expired (locked AC 7)', function (): void {
    $now = CarbonImmutable::parse('2026-08-28T12:00:00+00:00');
    $this->travelTo($now);

    $secret = consoleKeypair();
    consoleFileKey('k1', $secret);

    // A full day of life, minted one second ago: perfectly unexpired,
    // and refused anyway. The app enforces D12's upper bound itself
    // rather than trusting the issuer to have been honest about it.
    $token = consoleMint($secret, consoleClaims([
        'iat' => $now->toAtomString(),
        'nbf' => $now->toAtomString(),
        'exp' => $now->addDay()->toAtomString(),
    ]));

    expect(consoleRefusal($token)->reason)->toBe(AssertionRefusalReason::TtlTooLong);

    // The bound is the configured one, not a hard-coded 120.
    config(['built-for-cloud.console.assertion_max_ttl_seconds' => 86400]);

    expect(consoleVerify($token)->subject)->toBe('operator_42');
});

// -------------------------------------------------------- deployment scope

it('refuses an assertion minted for another deployment (locked AC 3)', function (): void {
    $secret = consoleKeypair();
    consoleFileKey('k1', $secret);

    // Deployment A's assertion, presented at deployment B.
    $token = consoleMint($secret, consoleClaims(['aud' => 'https://other-customer.test']));

    expect(consoleRefusal($token)->reason)->toBe(AssertionRefusalReason::AudienceMismatch);

    // The same token verifies at the deployment it names — nothing else
    // about it is wrong.
    config(['built-for-cloud.console.audience' => 'https://other-customer.test']);

    expect(consoleVerify($token)->audience)->toBe('https://other-customer.test');
});

it('falls back to app.url when no console audience is configured', function (): void {
    $secret = consoleKeypair();
    consoleFileKey('k1', $secret);

    config([
        'built-for-cloud.console.audience' => null,
        'app.url' => 'https://configured-by-app-url.test',
    ]);

    $token = consoleMint($secret, consoleClaims(['aud' => 'https://configured-by-app-url.test']));

    expect(consoleVerify($token)->audience)->toBe('https://configured-by-app-url.test');
});

it('refuses an assertion from an issuer other than the configured one (locked AC 8)', function (): void {
    $secret = consoleKeypair();
    consoleFileKey('k1', $secret);

    $token = consoleMint($secret, consoleClaims(['iss' => 'https://impostor.test']));

    expect(consoleRefusal($token)->reason)->toBe(AssertionRefusalReason::IssuerMismatch);
});

// ------------------------------------------------------------ the crypto

it('refuses a token whose payload was tampered with (locked AC 4)', function (): void {
    $secret = consoleKeypair();
    consoleFileKey('k1', $secret);

    $token = consoleMint($secret, consoleClaims());

    // A byte inside the claims segment.
    $tampered = consoleFlipCharacter($token, strlen('v4.public.') + 12);

    expect($tampered)->not->toBe($token)
        ->and(consoleRefusal($tampered)->reason)->toBe(AssertionRefusalReason::SignatureInvalid);
});

it('refuses a token whose signature was tampered with (locked AC 4)', function (): void {
    $secret = consoleKeypair();
    consoleFileKey('k1', $secret);

    $token = consoleMint($secret, consoleClaims());

    // The trailing bytes of the payload segment ARE the signature.
    $signatureByte = strrpos($token, '.') - 3;
    $tampered = consoleFlipCharacter($token, $signatureByte);

    expect($tampered)->not->toBe($token)
        ->and(consoleRefusal($tampered)->reason)->toBe(AssertionRefusalReason::SignatureInvalid);
});

it('refuses a token signed by the wrong key under a filed key id', function (): void {
    $filed = consoleKeypair();
    $impostor = consoleKeypair();
    consoleFileKey('k1', $filed);

    // The `kid` names a key the ring trusts; the signature was made by
    // another one. PASETO binds the footer, so this cannot survive.
    $token = consoleMint($impostor, consoleClaims(), 'k1');

    expect(consoleRefusal($token)->reason)->toBe(AssertionRefusalReason::SignatureInvalid);
});

// ------------------------------------------------------------- the keyring

it('refuses a token signed by a keypair the ring never heard of (locked AC 5)', function (): void {
    consoleFileKey('k1', consoleKeypair());

    $stranger = consoleKeypair();
    $token = consoleMint($stranger, consoleClaims(), 'k-stranger');

    expect(consoleRefusal($token)->reason)->toBe(AssertionRefusalReason::UnknownKey);
});

it('refuses a token naming a key id no row carries (locked AC 5)', function (): void {
    $secret = consoleKeypair();
    consoleFileKey('k1', $secret);

    $token = consoleMint($secret, consoleClaims(), 'k-nobody-filed');

    expect(consoleRefusal($token)->reason)->toBe(AssertionRefusalReason::UnknownKey);
});

it('refuses a token whose footer names no key at all', function (): void {
    $secret = consoleKeypair();
    consoleFileKey('k1', $secret);

    $token = (new Builder)
        ->setVersion(new Version4)
        ->setPurpose(Purpose::public())
        ->setKey($secret)
        ->setClaims(consoleClaims())
        ->toString();

    expect(consoleRefusal($token)->reason)->toBe(AssertionRefusalReason::UnknownKey);
});

it('refuses a token signed by a filed but never activated key', function (): void {
    $secret = consoleKeypair();
    consoleFileKey('k-pending', $secret, activate: false);

    $token = consoleMint($secret, consoleClaims(), 'k-pending');

    expect(consoleRefusal($token)->reason)->toBe(AssertionRefusalReason::KeyNotActive);
});

it('verifies under either of two simultaneously active keys and stops only the retired one (locked AC 6)', function (): void {
    $first = consoleKeypair();
    $second = consoleKeypair();

    $keyring = new ConsoleKeyring;

    consoleFileKey('k1', $first);

    // Make-before-break: the replacement is activated while the
    // outgoing key is still trusted, and NOTHING is retired by that act.
    consoleFileKey('k2', $second);

    expect($keyring->active())->toHaveCount(2);

    expect(consoleVerify(consoleMint($first, consoleClaims(), 'k1'))->keyId)->toBe('k1')
        ->and(consoleVerify(consoleMint($second, consoleClaims(), 'k2'))->keyId)->toBe('k2');

    // Retiring is the separate, later step.
    $keyring->retire('k1');

    expect($keyring->active())->toHaveCount(1)
        ->and(consoleRefusal(consoleMint($first, consoleClaims(), 'k1'))->reason)->toBe(AssertionRefusalReason::RetiredKey)
        ->and(consoleVerify(consoleMint($second, consoleClaims(), 'k2'))->keyId)->toBe('k2');
});

// ------------------------------------------------------ format pinning

it('refuses a v4.local token (locked AC 9)', function (): void {
    consoleFileKey('k1', consoleKeypair());

    $token = (new Builder)
        ->setVersion(new Version4)
        ->setPurpose(Purpose::local())
        ->setKey(SymmetricKey::generate(new Version4))
        ->setClaims(consoleClaims())
        ->setFooterArray(['kid' => 'k1'])
        ->toString();

    expect($token)->toStartWith('v4.local.')
        ->and(consoleRefusal($token)->reason)->toBe(AssertionRefusalReason::UnsupportedVersion);
});

it('refuses a v3.public token and older version headers (locked AC 9)', function (): void {
    consoleFileKey('k1', consoleKeypair());

    $version3 = (new Builder)
        ->setVersion(new Version3)
        ->setPurpose(Purpose::public())
        ->setKey(Version3SecretKey::generate(new Version3))
        ->setClaims(consoleClaims())
        ->setFooterArray(['kid' => 'k1'])
        ->toString();

    expect($version3)->toStartWith('v3.public.')
        ->and(consoleRefusal($version3)->reason)->toBe(AssertionRefusalReason::UnsupportedVersion);

    foreach (['v1.public.abcdef', 'v2.public.abcdef', 'v1.local.abcdef', 'v2.local.abcdef', 'v3.local.abcdef'] as $legacy) {
        expect(consoleRefusal($legacy)->reason)->toBe(AssertionRefusalReason::UnsupportedVersion);
    }
});

it('refuses anything that is not a token at all', function (): void {
    consoleFileKey('k1', consoleKeypair());

    foreach (['', 'not-a-token', 'v4.public', str_repeat('v4.public.a', 1000)] as $garbage) {
        expect(consoleRefusal($garbage)->reason)->toBe(AssertionRefusalReason::MalformedToken);
    }
});

// -------------------------------------------------------------- the claims

it('refuses a role outside the two-value contract vocabulary (locked AC 11)', function (): void {
    $secret = consoleKeypair();
    consoleFileKey('k1', $secret);

    foreach ([consoleAbsent(), '', 'owner', 'Admin', 'superuser', 'admin,member'] as $role) {
        $token = consoleMint($secret, consoleClaims(['role' => $role]));

        expect(consoleRefusal($token)->reason)->toBe(AssertionRefusalReason::InvalidRole);
    }

    // A non-string role is refused on the same reason — nothing coerces.
    $token = consoleMint($secret, consoleClaims(['role' => ['admin']]));

    expect(consoleRefusal($token)->reason)->toBe(AssertionRefusalReason::InvalidRole);
});

it('bounds the display claims at the door (locked AC 13)', function (): void {
    $secret = consoleKeypair();
    consoleFileKey('k1', $secret);

    $hostile = [
        str_repeat('a', 121),
        "Jane\nOperator",
        "Jane\r\nSet-Cookie: x",
        "Jane\tOperator",
        "Jane\x00Operator",
        "Jane\u{2028}Operator",
        "Jane\u{202E}Operator",
    ];

    foreach ($hostile as $value) {
        expect(consoleRefusal(consoleMint($secret, consoleClaims(['display_name' => $value])))->reason)
            ->toBe(AssertionRefusalReason::InvalidClaims)
            ->and(consoleRefusal(consoleMint($secret, consoleClaims(['on_behalf_of' => $value])))->reason)
            ->toBe(AssertionRefusalReason::InvalidClaims);
    }

    // The bound is a bound, not a truncation: the longest legal name
    // still verifies unchanged.
    $longest = str_repeat('a', 120);

    expect(consoleVerify(consoleMint($secret, consoleClaims(['display_name' => $longest])))->displayName)
        ->toBe($longest);
});

it('refuses claims that are absent, mistyped, or unparseable', function (): void {
    $secret = consoleKeypair();
    consoleFileKey('k1', $secret);

    $broken = [
        ['sub' => consoleAbsent()],
        ['sub' => ''],
        ['sub' => 42],
        ['display_name' => consoleAbsent()],
        ['jti' => consoleAbsent()],
        ['jti' => str_repeat('j', 65)],
        ['iss' => consoleAbsent()],
        ['aud' => consoleAbsent()],
        ['iat' => consoleAbsent()],
        ['exp' => consoleAbsent()],
        ['iat' => 'yesterday'],
        ['exp' => 'tomorrow'],
        ['exp' => 1786608000],
        ['nbf' => 'whenever'],
        // exp at or before iat: a token with no life at all.
        ['exp' => CarbonImmutable::now()->subMinute()->toAtomString(), 'iat' => CarbonImmutable::now()->toAtomString()],
    ];

    foreach ($broken as $overrides) {
        expect(consoleRefusal(consoleMint($secret, consoleClaims($overrides)))->reason)
            ->toBe(AssertionRefusalReason::InvalidClaims);
    }
});

// ------------------------------------------------------- the anti-oracle

it('answers every refusal with the same class and the same reason-free message (locked AC 12)', function (): void {
    $now = CarbonImmutable::parse('2026-08-28T12:00:00+00:00');
    $this->travelTo($now);

    $filed = consoleKeypair();
    $pending = consoleKeypair();
    $retired = consoleKeypair();
    $stranger = consoleKeypair();

    consoleFileKey('k1', $filed);
    consoleFileKey('k-pending', $pending, activate: false);
    consoleFileKey('k-retired', $retired);
    (new ConsoleKeyring)->retire('k-retired');

    $tokens = [
        AssertionRefusalReason::UnsupportedVersion->value => 'v2.public.abcdef',
        AssertionRefusalReason::MalformedToken->value => 'not-a-token',
        AssertionRefusalReason::UnknownKey->value => consoleMint($stranger, consoleClaims(), 'k-stranger'),
        AssertionRefusalReason::KeyNotActive->value => consoleMint($pending, consoleClaims(), 'k-pending'),
        AssertionRefusalReason::RetiredKey->value => consoleMint($retired, consoleClaims(), 'k-retired'),
        AssertionRefusalReason::SignatureInvalid->value => consoleMint($stranger, consoleClaims(), 'k1'),
        AssertionRefusalReason::IssuerMismatch->value => consoleMint($filed, consoleClaims(['iss' => 'https://impostor.test'])),
        AssertionRefusalReason::AudienceMismatch->value => consoleMint($filed, consoleClaims(['aud' => 'https://elsewhere.test'])),
        AssertionRefusalReason::Expired->value => consoleMint($filed, consoleClaims([
            'iat' => $now->subMinutes(10)->toAtomString(),
            'nbf' => $now->subMinutes(10)->toAtomString(),
            'exp' => $now->subMinutes(9)->toAtomString(),
        ])),
        AssertionRefusalReason::NotYetValid->value => consoleMint($filed, consoleClaims([
            'iat' => $now->addMinutes(10)->toAtomString(),
            'nbf' => $now->addMinutes(10)->toAtomString(),
            'exp' => $now->addMinutes(11)->toAtomString(),
        ])),
        AssertionRefusalReason::TtlTooLong->value => consoleMint($filed, consoleClaims(['exp' => $now->addDay()->toAtomString()])),
        AssertionRefusalReason::InvalidRole->value => consoleMint($filed, consoleClaims(['role' => 'owner'])),
        AssertionRefusalReason::InvalidClaims->value => consoleMint($filed, consoleClaims(['display_name' => "Jane\nOperator"])),
    ];

    // Every reason in the vocabulary is exercised here — a new reason
    // added without a scenario fails this test rather than shipping
    // unproven.
    expect(array_keys($tokens))->toEqualCanonicalizing(AssertionRefusalReason::values());

    $messages = [];

    foreach ($tokens as $expected => $token) {
        $refusal = consoleRefusal($token);

        expect($refusal)->toBeInstanceOf(AssertionRefused::class)
            ->and($refusal->reason->value)->toBe($expected);

        $messages[] = $refusal->getMessage();
    }

    expect(array_unique($messages))->toBe([AssertionRefused::MESSAGE])
        ->and(AssertionRefused::MESSAGE)->not->toContain('key')
        ->and(AssertionRefused::MESSAGE)->not->toContain('expired');
});

it('fails loudly rather than trusting any issuer when none is configured', function (): void {
    $secret = consoleKeypair();
    consoleFileKey('k1', $secret);

    config(['built-for-cloud.console.issuer' => null]);

    expect(fn (): mixed => consoleVerify(consoleMint($secret, consoleClaims())))
        ->toThrow(RuntimeException::class);
});

it('refuses to verify at all when neither a console audience nor app.url is configured', function (): void {
    $secret = consoleKeypair();
    consoleFileKey('k1', $secret);

    config(['built-for-cloud.console.audience' => null, 'app.url' => null]);

    expect(fn (): mixed => consoleVerify(consoleMint($secret, consoleClaims())))
        ->toThrow(RuntimeException::class);
});
