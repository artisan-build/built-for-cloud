<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\CredentialKind;
use PHPUnit\Framework\Attributes\DataProvider;

final class StyledControlViewTest extends TestCase
{
    /** @return iterable<string, array{string, string, string}> */
    public static function controlPageProvider(): iterable
    {
        yield 'personal credentials' => [
            'bfc::credentials.personal',
            'personal-credentials',
            'personal-credentials-panel',
        ];
        yield 'device authorization' => [
            'bfc::authorizations.device',
            'device-authorization-page',
            'device-authorization-panel',
        ];
        yield 'loopback authorization' => [
            'bfc::authorizations.loopback',
            'device-authorization-loopback',
            'device-authorization-loopback-panel',
        ];
    }

    #[DataProvider('controlPageProvider')]
    public function test_every_package_page_with_unclassed_controls_renders_in_the_styled_panel(
        string $view,
        string $rootTestId,
        string $panelTestId,
    ): void {
        $html = view($view, $this->viewData($view))->render();

        $this->assertMatchesRegularExpression(
            '/<section(?=[^>]*data-testid="'.preg_quote($rootTestId, '/').'")(?=[^>]*class="[^"]*\\bbfc-auth\\b[^"]*")[^>]*>/',
            $html,
        );
        $this->assertMatchesRegularExpression(
            '/<div(?=[^>]*data-testid="'.preg_quote($panelTestId, '/').'")(?=[^>]*class="[^"]*\\bbfc-panel\\b[^"]*")[^>]*>/',
            $html,
        );
        $this->assertGreaterThan(0, substr_count($html, '<button type="submit">'));

        $css = (string) file_get_contents(__DIR__.'/../resources/dist/bfc.css');
        $this->assertStringContainsString('.bfc-auth button', $css);
    }

    /** @return array<string, mixed> */
    private function viewData(string $view): array
    {
        if ($view === 'bfc::credentials.personal') {
            return [
                'choices' => [[
                    'submissionNonce' => 'personal-issue-nonce',
                    'appPurpose' => 'test.mcp',
                    'kind' => CredentialKind::Bearer,
                ]],
                'credentials' => [],
                'delivery' => null,
                'fields' => [],
                'rotationNonces' => [],
            ];
        }

        $authorization = [
            'appPurpose' => 'test.mcp',
            'audience' => 'https://api.example.test',
            'installation' => 'test-installation',
            'application' => 'test-application',
            'ownership' => 'personal',
            'label' => 'Test client',
            'approveNonce' => 'approve-nonce',
            'denyNonce' => 'deny-nonce',
        ];

        if ($view === 'bfc::authorizations.device') {
            return [
                'authorizations' => [[...$authorization, 'userCode' => 'ABCD-EFGH']],
                'outcome' => null,
            ];
        }

        return [
            'authorization' => [...$authorization, 'callbackAuthority' => '127.0.0.1:49152'],
            'outcome' => null,
        ];
    }
}
