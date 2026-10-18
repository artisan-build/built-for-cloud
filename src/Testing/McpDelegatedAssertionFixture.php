<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use ArtisanBuild\BuiltForCloud\Console\Assertion;
use ArtisanBuild\BuiltForCloud\Console\AssertionVerifier;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKey;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyring;
use ArtisanBuild\BuiltForCloud\Console\ConsoleRole;
use Carbon\CarbonImmutable;
use Illuminate\Database\UniqueConstraintViolationException;
use InvalidArgumentException;

/**
 * Fixed, signed assertions for the delegated conformance harness. The
 * signing key is not shipped. The verifier receives only this fixture's
 * public key, and time is frozen only for the verification call.
 *
 * @internal
 */
final class McpDelegatedAssertionFixture
{
    private const string ISSUER = 'https://bfc-enforcement.test';

    private const string AUDIENCE = 'https://bfc-enforcement-consumer.test';

    private const string KEY_ID = 'bfc-enforcement-v1';

    private const string PUBLIC_KEY = 'tny8aEEkRf3Qyqp2T0P4mWD81Eroo1Wu_Im-KVtZFGw';

    /** @var array<string, string> */
    private const array TOKENS = [
        'member:primary' => 'v4.public.eyJpc3MiOiJodHRwczpcL1wvYmZjLWVuZm9yY2VtZW50LnRlc3QiLCJzdWIiOiJiZmMtZW5mb3JjZW1lbnQtcHJpbWFyeSIsImF1ZCI6Imh0dHBzOlwvXC9iZmMtZW5mb3JjZW1lbnQtY29uc3VtZXIudGVzdCIsImlhdCI6IjIwMjYtMDEtMDFUMDA6MDA6MDArMDA6MDAiLCJuYmYiOiIyMDI2LTAxLTAxVDAwOjAwOjAwKzAwOjAwIiwiZXhwIjoiMjAyNi0wMS0wMVQwMDowMTozMCswMDowMCIsImp0aSI6ImJmYy1lbmZvcmNlbWVudC1tZW1iZXItcHJpbWFyeSIsImRpc3BsYXlfbmFtZSI6IkJmQyBFbmZvcmNlbWVudCBNZW1iZXIgUHJpbWFyeSIsInJvbGUiOiJtZW1iZXIiLCJwdXJwb3NlIjoibWNwIn15XvWr3U_fBpqSWCnBJf8IVRwQIChc85FWEwc9ruuTMg_rwLVK2y8cHEv34eN8wjbfFMeHFCpNO5hcpCQqbFcG.eyJraWQiOiJiZmMtZW5mb3JjZW1lbnQtdjEifQ',
        'member:secondary' => 'v4.public.eyJpc3MiOiJodHRwczpcL1wvYmZjLWVuZm9yY2VtZW50LnRlc3QiLCJzdWIiOiJiZmMtZW5mb3JjZW1lbnQtc2Vjb25kYXJ5IiwiYXVkIjoiaHR0cHM6XC9cL2JmYy1lbmZvcmNlbWVudC1jb25zdW1lci50ZXN0IiwiaWF0IjoiMjAyNi0wMS0wMVQwMDowMDowMCswMDowMCIsIm5iZiI6IjIwMjYtMDEtMDFUMDA6MDA6MDArMDA6MDAiLCJleHAiOiIyMDI2LTAxLTAxVDAwOjAxOjMwKzAwOjAwIiwianRpIjoiYmZjLWVuZm9yY2VtZW50LW1lbWJlci1zZWNvbmRhcnkiLCJkaXNwbGF5X25hbWUiOiJCZkMgRW5mb3JjZW1lbnQgTWVtYmVyIFNlY29uZGFyeSIsInJvbGUiOiJtZW1iZXIiLCJwdXJwb3NlIjoibWNwIn19LkAS1q-HRx6HZnYFHxsWm1mndse95R0p2ZTfe1ZQwKYyTs4lyfkJtmwhvQItc392HWa83-vDbjO-0IJqDFgD.eyJraWQiOiJiZmMtZW5mb3JjZW1lbnQtdjEifQ',
        'admin:primary' => 'v4.public.eyJpc3MiOiJodHRwczpcL1wvYmZjLWVuZm9yY2VtZW50LnRlc3QiLCJzdWIiOiJiZmMtZW5mb3JjZW1lbnQtcHJpbWFyeSIsImF1ZCI6Imh0dHBzOlwvXC9iZmMtZW5mb3JjZW1lbnQtY29uc3VtZXIudGVzdCIsImlhdCI6IjIwMjYtMDEtMDFUMDA6MDA6MDArMDA6MDAiLCJuYmYiOiIyMDI2LTAxLTAxVDAwOjAwOjAwKzAwOjAwIiwiZXhwIjoiMjAyNi0wMS0wMVQwMDowMTozMCswMDowMCIsImp0aSI6ImJmYy1lbmZvcmNlbWVudC1hZG1pbi1wcmltYXJ5IiwiZGlzcGxheV9uYW1lIjoiQmZDIEVuZm9yY2VtZW50IEFkbWluIFByaW1hcnkiLCJyb2xlIjoiYWRtaW4iLCJwdXJwb3NlIjoibWNwIn23v3oD6kWL72GelSvGSzcq76VYk4XMJlrjalCMld58mvELTw9FRYnZNJJAnTHGUVcGdg0j1WMrJEDY0jEC4a0J.eyJraWQiOiJiZmMtZW5mb3JjZW1lbnQtdjEifQ',
        'admin:secondary' => 'v4.public.eyJpc3MiOiJodHRwczpcL1wvYmZjLWVuZm9yY2VtZW50LnRlc3QiLCJzdWIiOiJiZmMtZW5mb3JjZW1lbnQtc2Vjb25kYXJ5IiwiYXVkIjoiaHR0cHM6XC9cL2JmYy1lbmZvcmNlbWVudC1jb25zdW1lci50ZXN0IiwiaWF0IjoiMjAyNi0wMS0wMVQwMDowMDowMCswMDowMCIsIm5iZiI6IjIwMjYtMDEtMDFUMDA6MDA6MDArMDA6MDAiLCJleHAiOiIyMDI2LTAxLTAxVDAwOjAxOjMwKzAwOjAwIiwianRpIjoiYmZjLWVuZm9yY2VtZW50LWFkbWluLXNlY29uZGFyeSIsImRpc3BsYXlfbmFtZSI6IkJmQyBFbmZvcmNlbWVudCBBZG1pbiBTZWNvbmRhcnkiLCJyb2xlIjoiYWRtaW4iLCJwdXJwb3NlIjoibWNwIn0TkHs4bEy1gqGSULbV-lTrBZqu677WK3iubQzI2OSTtmajTp3aLiPiPMqUAplJccNUVz_YKuJxeonTvQVNtpsN.eyJraWQiOiJiZmMtZW5mb3JjZW1lbnQtdjEifQ',
    ];

    public static function verified(ConsoleRole $role, bool $secondary = false): Assertion
    {
        $issuer = config('built-for-cloud.console.issuer');
        $audience = config('built-for-cloud.console.audience');
        $testNow = CarbonImmutable::getTestNow();
        $fixtureKey = null;
        $created = false;

        config([
            'built-for-cloud.console.issuer' => self::ISSUER,
            'built-for-cloud.console.audience' => self::AUDIENCE,
        ]);
        CarbonImmutable::setTestNow(CarbonImmutable::parse('2026-01-01T00:00:30+00:00'));

        try {
            $keyring = app(ConsoleKeyring::class);
            $fixtureKey = $keyring->find(self::KEY_ID);
            $normalized = ConsoleKeyring::normalizePublicKey(self::PUBLIC_KEY);

            if ($fixtureKey !== null) {
                throw new McpDelegatedFixtureCollision('console-key-id');
            }

            if (ConsoleKey::query()->where('public_key', $normalized)->exists()) {
                throw new McpDelegatedFixtureCollision('console-key-material');
            }

            try {
                $fixtureKey = $keyring->add(self::KEY_ID, self::PUBLIC_KEY);
            } catch (InvalidArgumentException|UniqueConstraintViolationException $collision) {
                throw new McpDelegatedFixtureCollision('console-key-race');
            }
            $created = true;
            $keyring->activate(self::KEY_ID);
            $token = $role->value.':'.($secondary ? 'secondary' : 'primary');

            return app(AssertionVerifier::class)->verify(self::TOKENS[$token]);
        } finally {
            if ($created && $fixtureKey !== null) {
                $fixtureKey->delete();
            }

            config([
                'built-for-cloud.console.issuer' => $issuer,
                'built-for-cloud.console.audience' => $audience,
            ]);
            CarbonImmutable::setTestNow($testNow);
        }
    }
}
