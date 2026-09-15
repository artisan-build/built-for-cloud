<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\SystemAuthorityContext;
use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Assert;
use Symfony\Component\HttpFoundation\Response;

/**
 * Consumer-side proof of the MCP product-admission branches. The helper owns
 * its test users and credential rows so a consuming test imports no concrete
 * package model, credential enum, role enum, or system-context class.
 *
 * Run it in a database-refreshing Laravel feature test. It mounts two random,
 * test-only probes through the application's real `bfc.mcp` alias and asserts
 * recognized account roles, unknown and unresolved accounts, installation
 * system attribution, the `product` compound exclusion, usage ordering, and
 * context cleanup.
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

        foreach (['unknown' => self::accountCredential('unknown'), 'unresolved' => self::unresolvedAccountCredential()] as $case => $account) {
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
        $request = Request::create($uri, 'POST', server: [
            'HTTP_AUTHORIZATION' => 'Bearer '.$plaintext,
            'CONTENT_TYPE' => 'application/json',
            'HTTP_ACCEPT' => 'application/json',
        ]);

        return app('router')->dispatch($request);
    }

    /** @param array<string, bool|string> $body */
    private static function assertResponse(Response $response, int $status, array $body): void
    {
        Assert::assertSame($status, $response->getStatusCode());
        Assert::assertSame($body, json_decode((string) $response->getContent(), true));
    }
}
