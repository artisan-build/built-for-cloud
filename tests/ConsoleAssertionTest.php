<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Console\Assertion;
use ArtisanBuild\BuiltForCloud\Console\AssertionRefusalReason;
use ArtisanBuild\BuiltForCloud\Console\AssertionVerifier;
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

    // Driven at the boundary: the configured skew is 5 seconds, so an
    // issuer clock 4 or exactly 5 seconds ahead is tolerated and 6 is
    // not. `exp` stays inside the wall-clock TTL ceiling in every case,
    // so nothing here is answered by the TTL rule instead.
    $mint = static fn (int $ahead): string => consoleMint($secret, consoleClaims([
        'iat' => $now->addSeconds($ahead)->toAtomString(),
        'nbf' => $now->addSeconds($ahead)->toAtomString(),
        'exp' => $now->addSeconds($ahead + 60)->toAtomString(),
    ]));

    expect(consoleVerify($mint(4))->subject)->toBe('operator_42')
        ->and(consoleVerify($mint(5))->subject)->toBe('operator_42')
        ->and(consoleRefusal($mint(6))->reason)->toBe(AssertionRefusalReason::NotYetValid)
        ->and(consoleRefusal($mint(30))->reason)->toBe(AssertionRefusalReason::NotYetValid);
});

it('caps the window on this server clock, so an early iat cannot buy extra life (locked AC 7)', function (): void {
    $now = CarbonImmutable::parse('2026-08-28T12:00:00+00:00');
    $this->travelTo($now);

    $secret = consoleKeypair();
    consoleFileKey('k1', $secret);

    // `iat` five seconds ahead — inside the skew, so the not-yet-valid
    // rule lets it through — with a span of exactly the configured 120
    // second bound. The token's OWN arithmetic is legal; accepting it
    // would leave this app honouring the assertion until now + 125,
    // past the bound it just enforced. The wall-clock half refuses it.
    $token = consoleMint($secret, consoleClaims([
        'iat' => $now->addSeconds(5)->toAtomString(),
        'nbf' => $now->addSeconds(5)->toAtomString(),
        'exp' => $now->addSeconds(125)->toAtomString(),
    ]));

    expect(consoleRefusal($token)->reason)->toBe(AssertionRefusalReason::TtlTooLong);

    // One second inside the ceiling and the same shape verifies, so the
    // refusal above is the ceiling talking and not the early `iat`.
    $atCeiling = consoleMint($secret, consoleClaims([
        'iat' => $now->addSeconds(5)->toAtomString(),
        'nbf' => $now->addSeconds(5)->toAtomString(),
        'exp' => $now->addSeconds(120)->toAtomString(),
    ]));

    expect(consoleVerify($atCeiling)->subject)->toBe('operator_42');
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

it('refuses to verify against app.url when no console audience is configured', function (): void {
    $secret = consoleKeypair();
    consoleFileKey('k1', $secret);

    // Two deployments can easily share an APP_URL — localhost, a cloned
    // .env, a shared load-balancer hostname — and an audience two
    // deployments share stops a stolen assertion at neither. So there is
    // no fallback: an unset audience fails closed and loudly.
    config([
        'built-for-cloud.console.audience' => null,
        'app.url' => 'https://configured-by-app-url.test',
    ]);

    $token = consoleMint($secret, consoleClaims(['aud' => 'https://configured-by-app-url.test']));

    expect(fn (): mixed => consoleVerify($token))->toThrow(RuntimeException::class);
});

it('refuses an assertion from an issuer other than the configured one (locked AC 8)', function (): void {
    $secret = consoleKeypair();
    consoleFileKey('k1', $secret);

    $token = consoleMint($secret, consoleClaims(['iss' => 'https://impostor.test']));

    expect(consoleRefusal($token)->reason)->toBe(AssertionRefusalReason::IssuerMismatch);
});

// ------------------------------------------------------------ the crypto

it('refuses a token whose claims were tampered with (locked AC 4)', function (): void {
    $secret = consoleKeypair();
    consoleFileKey('k1', $secret);

    $token = consoleMint($secret, consoleClaims(['role' => 'member']));

    // The privilege escalation this check exists for: `member` rewritten
    // to `admin` in the signed claims. The helper asserts the result is
    // still decodable base64 carrying valid JSON, so the refusal below
    // can only be the signature — not a broken encoding the verifier
    // would have reported under the same reason.
    $tampered = consoleTamperClaims($token, '"role":"member"', '"role":"admin"');

    expect(consoleRefusal($tampered)->reason)->toBe(AssertionRefusalReason::SignatureInvalid);
});

it('refuses a token whose signature was tampered with (locked AC 4)', function (): void {
    $secret = consoleKeypair();
    consoleFileKey('k1', $secret);

    $token = consoleMint($secret, consoleClaims());

    // One bit of the signature, claims left byte-for-byte intact.
    $tampered = consoleTamperSignature($token);

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

it('refuses a stranger keypair token at keyring lookup, before any signature work (locked AC 5)', function (): void {
    consoleFileKey('k1', consoleKeypair());

    // A whole foreign keypair, presenting its own key id. It never
    // reaches signature verification — no row answers for the `kid`, so
    // the ring refuses first. (The signature path against a FILED key id
    // is driven by the wrong-key test above; these are the two ways a
    // stranger's token dies, and this is the earlier one.)
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

it('refuses input that never reaches the parser at all', function (): void {
    consoleFileKey('k1', consoleKeypair());

    // These two are stopped by the size guards before any parsing: an
    // empty string, and a token past MAX_TOKEN_LENGTH — an endpoint that
    // will base64-parse a megabyte has been handed cheap CPU to spend.
    $oversize = 'v4.public.'.str_repeat('a', AssertionVerifier::MAX_TOKEN_LENGTH);

    expect(strlen($oversize))->toBeGreaterThan(AssertionVerifier::MAX_TOKEN_LENGTH)
        ->and(consoleRefusal('')->reason)->toBe(AssertionRefusalReason::MalformedToken)
        ->and(consoleRefusal($oversize)->reason)->toBe(AssertionRefusalReason::MalformedToken);
});

it('refuses strings that reach the parser and are not tokens', function (): void {
    consoleFileKey('k1', consoleKeypair());

    // Right size, wrong everything else: no PASETO header at all, a
    // header with no payload separator, and a well-headed token whose
    // body is garbage — the last one gets all the way to PASETO's own
    // message parsing before it dies.
    foreach (['not-a-token', 'v4.public', 'v4.public.@@@@@@', 'v4.public.abc.def.ghi'] as $garbage) {
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

it('carries html metacharacters through verbatim — escaping is the rendering sink\'s job (locked AC 13)', function (): void {
    $secret = consoleKeypair();
    consoleFileKey('k1', $secret);

    // A display name is issuer-supplied free text: apostrophes, accents,
    // ampersands and angle brackets are all legitimate in a human name,
    // and the mint-side charset limits are Scalpels' business. This
    // verifier bounds LENGTH and rejects CONTROL characters, and that is
    // all it claims — so a payload-shaped name arrives intact.
    //
    // This test exists to tell PR5's implementer, who builds the
    // privileged chrome that renders this string, that escaping is
    // theirs to do. If it ever fails because the verifier started
    // stripping or encoding, the chrome's contract changed and every
    // rendering sink needs re-reading.
    $hostile = '<img src=x onerror=alert(1)>';
    $agency = 'Ben & Jerry\'s "Agency" <b>';

    $assertion = consoleVerify(consoleMint($secret, consoleClaims([
        'display_name' => $hostile,
        'on_behalf_of' => $agency,
    ])));

    expect($assertion->displayName)->toBe($hostile)
        ->and($assertion->onBehalfOf)->toBe($agency)
        ->and($assertion->attribution())->toBe($hostile.' ('.$agency.')');
});

it('cannot be constructed without going through a verifier by accident (locked AC 1)', function (): void {
    // PHP cannot restrict a static factory to one caller, so the
    // protection is: no public constructor, and a factory whose name
    // states what the caller is asserting. PR3 opens a delegated session
    // from this object and PR4 grants admin standing from it — an
    // instance conjured with no token is an unauthenticated admin, so
    // `new Assertion(role: Admin)` must not be something a hurried
    // implementer can reach for.
    $constructor = (new ReflectionClass(Assertion::class))->getConstructor();

    expect($constructor?->isPrivate())->toBeTrue()
        ->and(method_exists(Assertion::class, 'fromVerifiedClaims'))->toBeTrue();
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

it('refuses to verify at all when no audience is configured anywhere', function (): void {
    $secret = consoleKeypair();
    consoleFileKey('k1', $secret);

    config(['built-for-cloud.console.audience' => null, 'app.url' => null]);

    expect(fn (): mixed => consoleVerify(consoleMint($secret, consoleClaims())))
        ->toThrow(RuntimeException::class);
});
