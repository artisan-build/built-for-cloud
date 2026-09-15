<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\Http\Middleware\AuthenticateMcp;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\SystemAuthorityContext;
use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Assert;
use RuntimeException;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\StreamedResponse;

/**
 * Consumer-side proof of the MCP product-admission branches. The helper owns
 * its test users and credential rows so a consuming test imports no concrete
 * package model, credential enum, role enum, or system-context class.
 *
 * Run it in a database-refreshing Laravel feature test. It mounts random,
 * test-only probes through the router's real `bfc.mcp` alias and asserts
 * recognized account roles, unknown and unresolved accounts, installation
 * system attribution (including deferred streaming work), the `product`
 * compound exclusion, usage ordering, and context cleanup.
 *
 * Pinned by `tests/McpProductAdmissionTest.php` — "proves MCP product
 * admission through the reusable consumer helper".
 */
final class McpProductAdmission
{
    public static function assert(): void
    {
        $context = app(SystemAuthorityContext::class);
        $prefix = '/_bfc/testing/mcp-product-admission-'.bin2hex(random_bytes(8));

        Route::post($prefix.'/plain', static fn (): array => [
            'system_authority' => app(SystemAuthorityContext::class)->active(),
        ])->middleware('bfc.mcp');
        Route::post($prefix.'/product', static fn (): array => [
            'system_authority' => app(SystemAuthorityContext::class)->active(),
        ])->middleware('bfc.mcp:product');
        Route::post($prefix.'/stream', static fn (): StreamedResponse => response()->stream(
            static function (): void {
                echo app(SystemAuthorityContext::class)->active() ? 'active' : 'inactive';
            },
        ))->middleware('bfc.mcp:product');
        Route::post($prefix.'/stream-throw', static fn (): StreamedResponse => response()->stream(
            static function (): never {
                throw new RuntimeException('installation stream probe');
            },
        ))->middleware('bfc.mcp:product');

        foreach (UserRole::cases() as $role) {
            $account = self::accountCredential($role->value);

            self::assertResponse(
                self::request($prefix.'/product', $account['plaintext']),
                Response::HTTP_OK,
                ['system_authority' => false],
            );

            Assert::assertNotNull($account['credential']->refresh()->last_used_at);
            Assert::assertFalse($context->active(), 'System authority leaked after an account-bound MCP request.');
        }

        foreach ([
            'unknown' => self::accountCredential('unknown'),
            'unresolved' => self::unresolvedAccountCredential(),
            'malformed' => self::malformedAccountCredential(),
        ] as $case => $account) {
            self::assertResponse(
                self::request($prefix.'/product', $account['plaintext']),
                Response::HTTP_UNAUTHORIZED,
                ['message' => 'Unauthenticated.'],
            );

            Assert::assertNull(
                $account['credential']->refresh()->last_used_at,
                "The {$case} account credential recorded usage before refusal.",
            );
            Assert::assertSame(
                0,
                CredentialAuditEvent::query()->where('credential_id', $account['credential']->id)->count(),
                "The {$case} account credential wrote a usage event before refusal.",
            );
            Assert::assertFalse($context->active(), "System authority became active for the {$case} account request.");
        }

        $installation = self::credential(
            name: 'installation',
            subjectType: SubjectType::Installation,
            purpose: CredentialPurpose::Mcp,
        );
        self::assertResponse(
            self::request($prefix.'/product', $installation['plaintext']),
            Response::HTTP_OK,
            ['system_authority' => true],
        );
        Assert::assertNotNull($installation['credential']->refresh()->last_used_at);
        Assert::assertFalse($context->active(), 'System authority leaked after the installation MCP request.');

        $stream = self::request($prefix.'/stream', $installation['plaintext']);
        Assert::assertInstanceOf(StreamedResponse::class, $stream);
        Assert::assertFalse($context->active(), 'System authority leaked before the installation stream callback.');

        ob_start();
        try {
            $stream->sendContent();
            $streamOutput = ob_get_contents();
        } finally {
            ob_end_clean();
        }

        Assert::assertSame('active', $streamOutput);
        Assert::assertFalse($context->active(), 'System authority leaked after the installation stream callback.');

        $immediateException = null;
        try {
            app(AuthenticateMcp::class)->handle(
                self::bearerRequest($prefix.'/throw', $installation['plaintext']),
                static function (): never {
                    Assert::assertTrue(
                        app(SystemAuthorityContext::class)->active(),
                        'System authority was inactive while immediate installation downstream ran.',
                    );

                    throw new RuntimeException('installation downstream probe');
                },
                'product',
            );
        } catch (RuntimeException $exception) {
            $immediateException = $exception;
        }
        Assert::assertInstanceOf(RuntimeException::class, $immediateException);
        Assert::assertSame('installation downstream probe', $immediateException->getMessage());
        Assert::assertFalse($context->active(), 'System authority leaked after immediate downstream threw.');

        $throwingStream = self::request($prefix.'/stream-throw', $installation['plaintext']);
        Assert::assertInstanceOf(StreamedResponse::class, $throwingStream);
        $streamException = null;
        try {
            $throwingStream->sendContent();
        } catch (RuntimeException $exception) {
            $streamException = $exception;
        }
        Assert::assertInstanceOf(RuntimeException::class, $streamException);
        Assert::assertSame('installation stream probe', $streamException->getMessage());
        Assert::assertFalse($context->active(), 'System authority leaked after the installation stream callback threw.');

        $compound = self::credential(
            name: 'compound-admin',
            subjectType: SubjectType::Operator,
            purpose: CredentialPurpose::OperatorManagement,
            abilities: [OperatorAbility::Admin->value],
        );
        self::assertResponse(
            self::request($prefix.'/product', $compound['plaintext']),
            Response::HTTP_UNAUTHORIZED,
            ['message' => 'Unauthenticated.'],
        );
        Assert::assertNull($compound['credential']->refresh()->last_used_at);
        Assert::assertSame(
            0,
            CredentialAuditEvent::query()->where('credential_id', $compound['credential']->id)->count(),
            'The product-refused compound credential wrote a usage event.',
        );

        self::assertResponse(
            self::request($prefix.'/plain', $compound['plaintext']),
            Response::HTTP_OK,
            ['system_authority' => false],
        );
        Assert::assertNotNull($compound['credential']->refresh()->last_used_at);
        Assert::assertFalse($context->active(), 'System authority became active for the operator compound request.');
    }

    /**
     * @return array{credential: Credential, plaintext: string}
     */
    private static function accountCredential(string $role): array
    {
        $suffix = bin2hex(random_bytes(8));
        $user = User::query()->create([
            'name' => 'MCP '.$role,
            'email' => "mcp-{$role}-{$suffix}@example.test",
        ]);
        $user->forceFill(['role' => $role])->save();

        return self::credential(
            name: 'account-'.$role,
            subjectType: SubjectType::UserPrincipal,
            purpose: CredentialPurpose::Mcp,
            userId: (string) $user->getKey(),
        );
    }

    /**
     * @return array{credential: Credential, plaintext: string}
     */
    private static function unresolvedAccountCredential(): array
    {
        return self::credential(
            name: 'unresolved-account',
            subjectType: SubjectType::UserPrincipal,
            purpose: CredentialPurpose::Mcp,
            userId: (string) PHP_INT_MAX,
        );
    }

    /**
     * @return array{credential: Credential, plaintext: string}
     */
    private static function malformedAccountCredential(): array
    {
        return self::credential(
            name: 'malformed-account',
            subjectType: SubjectType::UserPrincipal,
            purpose: CredentialPurpose::Mcp,
            userId: 'missing-'.bin2hex(random_bytes(8)),
        );
    }

    /**
     * @param  list<string>|null  $abilities
     * @return array{credential: Credential, plaintext: string}
     */
    private static function credential(
        string $name,
        SubjectType $subjectType,
        CredentialPurpose $purpose,
        ?string $userId = null,
        ?array $abilities = null,
    ): array {
        $suffix = bin2hex(random_bytes(16));
        $plaintext = 'mcp-product-'.$suffix;
        $credential = Credential::query()->create([
            'kind' => CredentialKind::Bearer,
            'purpose' => $purpose,
            'subject_type' => $subjectType,
            'subject_ref' => $name.'-'.$suffix,
            'name' => $name,
            'user_id' => $userId,
            'abilities' => $abilities,
            'secret_hash' => hash('sha256', $plaintext),
            'status' => CredentialStatus::Active,
        ]);

        return ['credential' => $credential, 'plaintext' => $plaintext];
    }

    private static function request(string $uri, string $plaintext): Response
    {
        return app('router')->dispatch(self::bearerRequest($uri, $plaintext));
    }

    private static function bearerRequest(string $uri, string $plaintext): Request
    {
        return Request::create($uri, 'POST', server: [
            'HTTP_AUTHORIZATION' => 'Bearer '.$plaintext,
            'CONTENT_TYPE' => 'application/json',
            'HTTP_ACCEPT' => 'application/json',
        ]);
    }

    /** @param array<string, bool|string> $body */
    private static function assertResponse(Response $response, int $status, array $body): void
    {
        Assert::assertSame($status, $response->getStatusCode());
        Assert::assertSame($body, json_decode((string) $response->getContent(), true));
    }
}
