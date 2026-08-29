<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\BuiltForCloud;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Route;
use Orchestra\Testbench\Attributes\WithConfig;

/**
 * Locked AC 9: the HTTP surface is a versioned public contract, and the
 * contract doc is verified MECHANICALLY, not trusted as prose — every
 * registered package route appears in docs/http-contract.md, and every
 * route the doc names is real. The credential API is enabled here so its
 * flag-gated routes register and get checked too.
 *
 * RECOGNITION CAVEAT: package routes are recognized by their action's
 * class name (the ArtisanBuild\BuiltForCloud namespace prefix). A package
 * route registered with a CLOSURE has the action name "Closure" and would
 * escape this net — every package route today uses a controller class,
 * and any future closure route must either become one or be added to the
 * exclusion list with a reason.
 */
#[WithConfig('built-for-cloud.credential_api.enabled', true, false)]
final class HttpContractDocTest extends TestCase
{
    use RefreshDatabase;

    /**
     * Routes that are genuinely internal and deliberately excluded from
     * the public contract. EMPTY on purpose: every surface the package
     * mounts today is public contract. Add here only with a reason.
     *
     * @var list<string>
     */
    private const array EXCLUDED_ROUTES = [];

    public function test_api_version_two_is_reported_and_documented(): void
    {
        $this->assertSame(2, BuiltForCloud::API_VERSION);

        $this->getJson('/bfc/meta')->assertOk()->assertJsonPath('api_version', 2);

        $this->assertStringContainsString('"api_version": 2', $this->contractDoc());
    }

    /**
     * Spelled counts, so the doc's own "exactly the N operator
     * abilities" is checked rather than trusted. Small on purpose: if
     * the vocabulary ever grows past this, the miss is a red test
     * telling someone to extend the map, not a silent pass.
     *
     * @var array<string, int>
     */
    private const array SPELLED_COUNTS = [
        'four' => 4, 'five' => 5, 'six' => 6, 'seven' => 7, 'eight' => 8,
        'nine' => 9, 'ten' => 10, 'eleven' => 11, 'twelve' => 12,
    ];

    /**
     * The document is the contract (GATE-3), and its statement about
     * which abilities `credential:admin` expands to is a statement about
     * **who can take over a deployment** — one of which the code is the
     * only witness. This is exactly the drift that shipped in the
     * previous round: the mapping said "the six operator abilities"
     * while {@see OperatorAbility::adminEquivalent()} had grown to
     * seven, `console:key:write` among them, so an operator could read
     * the contract's explicitly EXACT mapping and conclude a break-glass
     * credential could not install a delegated-admin trust root. It
     * could.
     *
     * The route-completeness checks above cannot catch that: they read
     * headings, not prose. This is the smallest extension of the same
     * idea that would have caught it — pin the prose to the enum, in
     * both directions and including the count word.
     */
    public function test_the_documented_admin_equivalent_mapping_matches_the_code(): void
    {
        $matched = preg_match(
            '/expanding\s+to\s+exactly\s+the\s+(\w+)\s+operator\s+abilities\s+(.+?)\(never the MCP pair\)/s',
            $this->contractDoc(),
            $matches,
        );

        $this->assertSame(
            1,
            $matched,
            'docs/http-contract.md no longer states the credential:admin expansion in the form this test pins. '
            .'Restore the sentence, or update this test deliberately — do not delete the check.',
        );

        [, $spelledCount, $listed] = $matches;

        $expected = array_map(
            static fn (OperatorAbility $ability): string => $ability->value,
            OperatorAbility::adminEquivalent(),
        );

        // Every ability name the sentence spells out, in order.
        preg_match_all('/`([a-z]+:[a-z:]+)`/', $listed, $found);

        $this->assertSame(
            $expected,
            $found[1],
            'The abilities docs/http-contract.md lists for credential:admin do not match '
            .'OperatorAbility::adminEquivalent(). The document is the contract: a mismatch here is a '
            .'false statement about who can take over a deployment.',
        );

        $this->assertArrayHasKey(
            $spelledCount,
            self::SPELLED_COUNTS,
            "The contract spells the admin-equivalent count as \"{$spelledCount}\", which this test cannot read. Extend SPELLED_COUNTS.",
        );

        $this->assertSame(
            count($expected),
            self::SPELLED_COUNTS[$spelledCount],
            'docs/http-contract.md says credential:admin expands to "'.$spelledCount.'" abilities; '
            .'OperatorAbility::adminEquivalent() returns '.count($expected).'.',
        );

        // The MCP pair is never admin-equivalent, and the sentence that
        // says so must keep saying so about the real enum values.
        foreach ([OperatorAbility::McpRead, OperatorAbility::McpAdmin] as $mcp) {
            $this->assertNotContains(
                $mcp->value,
                $found[1],
                'The MCP abilities are deliberately not admin-equivalent.',
            );
            $this->assertNotContains($mcp, OperatorAbility::adminEquivalent());
        }
    }

    /**
     * Every ability the vocabulary defines is named somewhere in the
     * contract. A name the code enforces and the document never mentions
     * is a gate nobody can discover from the contract.
     */
    public function test_every_operator_ability_appears_in_the_contract(): void
    {
        $doc = $this->contractDoc();

        foreach (OperatorAbility::cases() as $ability) {
            $this->assertStringContainsString(
                '`'.$ability->value.'`',
                $doc,
                "The operator ability {$ability->value} is enforced by the package but never named in docs/http-contract.md.",
            );
        }

        foreach ([OperatorAbility::ADMIN, OperatorAbility::RESERVED_METADATA_READ] as $name) {
            $this->assertStringContainsString('`'.$name.'`', $doc);
        }
    }

    public function test_every_registered_package_route_is_documented(): void
    {
        $missing = array_diff($this->registeredPackageRoutes(), $this->documentedRoutes(), self::EXCLUDED_ROUTES);

        $this->assertSame(
            [],
            array_values($missing),
            'Registered package routes missing from docs/http-contract.md: '.implode(', ', $missing),
        );
    }

    public function test_every_documented_route_is_registered(): void
    {
        $phantom = array_diff($this->documentedRoutes(), $this->registeredPackageRoutes());

        $this->assertSame(
            [],
            array_values($phantom),
            'docs/http-contract.md documents routes that do not exist: '.implode(', ', $phantom),
        );
    }

    private function contractDoc(): string
    {
        return (string) file_get_contents(__DIR__.'/../docs/http-contract.md');
    }

    /**
     * @return list<string>
     */
    private function registeredPackageRoutes(): array
    {
        $routes = [];

        foreach (Route::getRoutes()->getRoutes() as $route) {
            if (! str_starts_with($route->getActionName(), 'ArtisanBuild\\BuiltForCloud\\')) {
                continue;
            }

            foreach ($route->methods() as $method) {
                if (in_array($method, ['HEAD', 'OPTIONS'], true)) {
                    continue;
                }

                $routes[] = $method.' /'.$route->uri();
            }
        }

        sort($routes);

        return array_values(array_unique($routes));
    }

    /**
     * Every `### METHOD /path` heading in the doc — the machine-checkable
     * convention the document commits to.
     *
     * @return list<string>
     */
    private function documentedRoutes(): array
    {
        preg_match_all('/^### (GET|POST|PUT|PATCH|DELETE) (\/\S+)$/m', $this->contractDoc(), $matches, PREG_SET_ORDER);

        $routes = array_map(
            static fn (array $match): string => $match[1].' '.$match[2],
            $matches,
        );

        sort($routes);

        return array_values(array_unique($routes));
    }
}
