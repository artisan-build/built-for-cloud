<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\BuiltForCloud;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAdmin;
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
     * idea that would have caught it.
     *
     * WHAT IT PINS, exactly: the ability names the contract's
     * admin-equivalent sentence lists, their ORDER, the spelled count
     * word beside them, and the absence of the MCP pair from both the
     * sentence and the method. That is all.
     *
     * WHAT IT DOES NOT PIN — named because an unlisted gap reads as a
     * covered one, which is the failure this whole check exists to
     * answer:
     *
     * 1. **That `adminEquivalent()` is what the gate enforces. It is
     *    not.** {@see EnsureCredentialAdmin}
     *    grants a `credential:admin` credential whatever ability the
     *    route names, without consulting this method — which appears
     *    nowhere in `src/` outside docblocks. So a future ability
     *    deliberately left OFF the list would still be satisfied by
     *    break-glass at runtime, and this test would stay green while
     *    the contract's "exactly" quietly stopped being true. Closing
     *    it means either having the gate consult the method or adding a
     *    behavioural test per ability; neither is done.
     * 2. **The ability a ROUTE requires.**
     *    {@see self::test_every_registered_package_route_is_documented}
     *    compares `METHOD /uri` and nothing else, so swapping a route's
     *    middleware — `console:key:write` back to `credential:rotate`,
     *    say — leaves every check in this class green. Today that swap
     *    is caught, but by ConsoleKeyCustodyTest's behavioural
     *    assertions, not here; nothing mechanically ties the doc's
     *    stated ability for a route to that route's middleware.
     * 3. **WHERE in the document an ability appears.**
     *    {@see self::test_every_operator_ability_appears_in_the_contract}
     *    searches the whole file, and `console:key:write` occurs a dozen
     *    times across the changelog, the authority table and the route
     *    section — so deleting it from the vocabulary paragraph, the one
     *    place an operator looks up what abilities exist, still passes.
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
     * Every ability the vocabulary defines is named SOMEWHERE in the
     * contract. A name the code enforces and the document never mentions
     * is a gate nobody can discover from the contract.
     *
     * Somewhere is the whole of the claim: this is an occurrence check
     * over the entire file, not a check that the ability is documented
     * in the vocabulary list, or on the route that requires it, or with
     * any description at all. An ability mentioned only in a changelog
     * line passes.
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

        $this->assertStringContainsString('`'.OperatorAbility::ADMIN.'`', $doc);
    }

    /**
     * The classification column is the durable privacy boundary the
     * Console reads (Console PRD D15), so the vitals row is pinned
     * mechanically rather than trusted: the route is in the table, and
     * it is in it as `metadata`.
     *
     * This pins ONE row. Nothing here checks that every documented route
     * has a classification row, nor that a row's stated classification
     * matches what the endpoint actually returns — the second is what
     * `ContractAssertions::assertBuiltForCloudMetadataShape()` checks,
     * against real responses, in MetadataShapeTest.
     */
    public function test_the_vitals_route_is_documented_as_metadata_classified(): void
    {
        $this->assertMatchesRegularExpression(
            '/^\| `GET \/bfc\/console\/vitals` \| `metadata` \|/m',
            $this->contractDoc(),
            'docs/http-contract.md no longer classifies GET /bfc/console/vitals as metadata.',
        );
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
