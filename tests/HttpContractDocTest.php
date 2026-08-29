<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\Audit\AppActionReason;
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
     * The app-action stream's REASON vocabulary is closed, and the
     * document is the only place a consumer can read what is in it — so
     * the document is checked against the enum rather than trusted.
     *
     * This is the same mechanism as the admin-equivalent check above,
     * and it exists for the same reason: this build shipped false
     * contract sentences in two consecutive rounds, and prose review is
     * not a mechanism. A reason added to the enum and not to the
     * document, or listed in the document and never in the code, reds
     * this test.
     *
     * WHAT IT PINS, exactly: the reason values the contract's "exactly
     * the N app-action reasons" sentence lists, their ORDER, and the
     * spelled count word beside them. That is all.
     *
     * WHAT IT DOES NOT PIN, named because an unlisted gap reads as a
     * covered one:
     *
     * 1. **That the reasons mean what the document says they mean.** The
     *    per-case descriptions live on the enum and are not compared to
     *    anything; a value whose meaning drifted while its name stayed
     *    would pass.
     * 2. **That an emitter picks the right one.** Nothing here ties a
     *    reason to the action that carries it. `console-entered` is
     *    driven as `console_entry` behaviourally, in
     *    `tests/ConsoleEnterAuditTest.php`, and no other emitter exists
     *    to check.
     */
    public function test_the_documented_app_action_reason_vocabulary_matches_the_code(): void
    {
        $matched = preg_match(
            '/exactly\s+the\s+(\w+)\s+app-action\s+reasons\*{0,2}\s*(.+?)\(closed set\)/s',
            $this->contractDoc(),
            $matches,
        );

        $this->assertSame(
            1,
            $matched,
            'docs/http-contract.md no longer states the app-action reason vocabulary in the form this test pins. '
            .'Restore the sentence, or update this test deliberately — do not delete the check.',
        );

        [, $spelledCount, $listed] = $matches;

        $expected = array_map(
            static fn (AppActionReason $reason): string => $reason->value,
            AppActionReason::cases(),
        );

        preg_match_all('/`([a-z][a-z0-9_]*)`/', $listed, $found);

        $this->assertSame(
            $expected,
            $found[1],
            'The reasons docs/http-contract.md lists for the app-action stream do not match AppActionReason. '
            .'The document is the contract, and this vocabulary is closed: a mismatch here is a false statement '
            .'about what an app may record.',
        );

        $this->assertArrayHasKey(
            $spelledCount,
            self::SPELLED_COUNTS,
            "The contract spells the app-action reason count as \"{$spelledCount}\", which this test cannot read. Extend SPELLED_COUNTS.",
        );

        $this->assertSame(
            count($expected),
            self::SPELLED_COUNTS[$spelledCount],
            'docs/http-contract.md says the app-action reason vocabulary has "'.$spelledCount.'" members; '
            .'AppActionReason has '.count($expected).'.',
        );
    }

    /**
     * The stream is described in detail and has NO read transport, so
     * the document has to say so — a description without that sentence
     * reads as one you can query.
     *
     * An occurrence check over the whole file, deliberately: what is
     * pinned is that the sentence EXISTS, not where it sits. The
     * absence of a route is pinned separately and behaviourally, by
     * `tests/AppActionAuditTest.php`.
     */
    public function test_the_contract_states_the_app_action_stream_has_no_read_transport(): void
    {
        $doc = $this->contractDoc();

        $this->assertStringContainsString('## The app-action audit stream', $doc);
        $this->assertStringContainsString(
            '**This release provides no way to read the app-action stream over HTTP.**',
            $doc,
        );
        $this->assertStringContainsString('`app-action-audit-emit`', $doc);
        $this->assertStringContainsString('`bfc_app_action_events`', $doc);
        $this->assertStringContainsString('**App-action events are never pruned by this package.**', $doc);
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
     * This pins ONE row, deliberately — it is the row a vendor-side read
     * depends on. What it CANNOT see is a route with no row at all, and
     * that is the check below.
     */
    public function test_the_vitals_route_is_documented_as_metadata_classified(): void
    {
        $this->assertMatchesRegularExpression(
            '/^\| `GET \/bfc\/console\/vitals` \| `metadata` \|/m',
            $this->contractDoc(),
            'docs/http-contract.md no longer classifies GET /bfc/console/vitals as metadata.',
        );
    }

    /**
     * **EVERY documented route is classified, and every classification
     * row names a real documented route.**
     *
     * This is the standing lesson of this build applied to the
     * classification column: *a check that selects before it compares
     * cannot see a MISSING thing.* The row check above reads the vitals
     * row by name, so it is blind to a route that carries no row — and a
     * route with no row is exactly the way a surface escapes the privacy
     * boundary the column exists to be. Classification was one of the
     * five reservations this release converts from reserved to
     * implemented, and "every endpoint carries one" is the sentence that
     * conversion rests on, so it is enumerated rather than asserted.
     *
     * Both directions, because a removal is drift too: a row naming a
     * route that no longer exists tells a vendor-side reader a surface
     * is safe to read when there is no surface.
     *
     * **This test asserts four things about the routes and rows the scan
     * RECOGNISES**, and that qualifier is the whole of the claim: a
     * recognised heading has a classification row, a recognised row has
     * a heading, no route has two rows, and no route has two headings.
     *
     * It is worded that way after two rounds of it being worded
     * otherwise. The first version said {@see ContractScan} "states its
     * own blind spots in full" — it did not, and duplicate rows were
     * invisible because the scan keyed a value by route. The second said
     * each heading is "required to carry exactly one classification row"
     * — also false, because `GET /a` and `get  /a` counted as two
     * routes, so a contradictory pair passed. Normalization closed that
     * variant. It did not close the CLASS: these are regexes over
     * Markdown, and "the document contains no second row for this route"
     * is not a property a regex can own.
     *
     * So the residue is named instead of a third completeness sentence
     * being written: **a row or heading this parse does not recognise is
     * not counted and cannot be seen here.** {@see ContractScan} carries
     * the boundary of each scan on the method that performs it. Whether
     * a classification is RIGHT is a different question again, answered
     * for this package's own metadata endpoints only by
     * `ContractAssertions::assertBuiltForCloudMetadataEndpoint()` in
     * `tests/MetadataShapeTest.php`.
     */
    public function test_every_documented_route_carries_a_classification(): void
    {
        $doc = $this->contractDoc();

        $this->assertSame(
            [],
            ContractScan::unclassifiedRoutes($doc),
            'docs/http-contract.md documents routes that carry no classification row. The column is the '
            .'durable privacy boundary vendor-side reads are decided by, so an endpoint missing from it is '
            .'an endpoint no consumer can tell is safe to read: '
            .implode(', ', ContractScan::unclassifiedRoutes($doc)),
        );

        $this->assertSame(
            [],
            ContractScan::phantomClassifications($doc),
            'The classification table names routes the document does not document: '
            .implode(', ', ContractScan::phantomClassifications($doc)),
        );

        $this->assertSame(
            [],
            ContractScan::conflictingClassifications($doc),
            'The classification table gives one route more than one row, so the contract states two '
            .'answers to "is this safe for a vendor-side read": '
            .implode('; ', ContractScan::conflictingClassifications($doc)),
        );

        $this->assertSame(
            [],
            ContractScan::duplicateRouteHeadings($doc),
            'docs/http-contract.md declares the same route under more than one heading: '
            .implode(', ', ContractScan::duplicateRouteHeadings($doc)),
        );

        // The scan is not merely green: it is green on a document where
        // it CAN be red. Every direction is driven over a fixture
        // carrying the offence, because an instrument nobody has watched
        // fail is a claim rather than a check.
        $missingRow = <<<'MD'
            ### GET /a
            ### POST /b

            | endpoint | classification | basis |
            |---|---|---|
            | `GET /a` | `metadata` | bounded |
            MD;

        $this->assertSame(['POST /b'], ContractScan::unclassifiedRoutes($missingRow));
        $this->assertSame([], ContractScan::phantomClassifications($missingRow));
        $this->assertSame([], ContractScan::conflictingClassifications($missingRow));

        $phantomRow = <<<'MD'
            ### GET /a

            | endpoint | classification | basis |
            |---|---|---|
            | `GET /a` | `metadata` | bounded |
            | `DELETE /gone` | `metadata` | bounded |
            MD;

        $this->assertSame([], ContractScan::unclassifiedRoutes($phantomRow));
        $this->assertSame(['DELETE /gone'], ContractScan::phantomClassifications($phantomRow));

        // The case that was invisible: two rows, two answers, and both
        // of the older scans clean. Asserting they ARE clean here is the
        // point — it records why disclosure would not have been enough.
        $contradiction = <<<'MD'
            ### GET /a

            | endpoint | classification | basis |
            |---|---|---|
            | `GET /a` | `metadata` | bounded |
            | `GET /a` | `content` | free text |
            MD;

        $this->assertSame([], ContractScan::unclassifiedRoutes($contradiction));
        $this->assertSame([], ContractScan::phantomClassifications($contradiction));
        $this->assertSame(['GET /a: metadata, content'], ContractScan::conflictingClassifications($contradiction));

        $repeatedHeading = <<<'MD'
            ### GET /a
            ### GET /a

            | endpoint | classification | basis |
            |---|---|---|
            | `GET /a` | `metadata` | bounded |
            MD;

        $this->assertSame(['GET /a'], ContractScan::duplicateRouteHeadings($repeatedHeading));
        $this->assertSame([], ContractScan::duplicateRouteHeadings($missingRow));

        // The two variants that slipped past the first version of the
        // conflict check, both driven: the contradiction is only visible
        // once "the same route" survives a difference in method case and
        // in spacing. A document renders `get /a` and `GET  /a` as the
        // same endpoint, so the scan has to count them as one.
        $caseVariant = <<<'MD'
            ### GET /a

            | endpoint | classification | basis |
            |---|---|---|
            | `GET /a` | `metadata` | bounded |
            | `get /a` | `content` | free text |
            MD;

        $this->assertSame(['GET /a: metadata, content'], ContractScan::conflictingClassifications($caseVariant));
        $this->assertSame([], ContractScan::unclassifiedRoutes($caseVariant));
        $this->assertSame([], ContractScan::phantomClassifications($caseVariant));

        $spacingVariant = <<<'MD'
            ###  get   /a

            | endpoint | classification | basis |
            |---|---|---|
            | `GET /a` | `metadata` | bounded |
            |  `GET  /a`  |  `content`  | free text |
            MD;

        $this->assertSame(['GET /a: metadata, content'], ContractScan::conflictingClassifications($spacingVariant));
        $this->assertSame([], ContractScan::unclassifiedRoutes($spacingVariant));
        $this->assertSame([], ContractScan::phantomClassifications($spacingVariant));

        $headingCaseVariant = <<<'MD'
            ### GET /a
            ### get  /a

            | endpoint | classification | basis |
            |---|---|---|
            | `GET /a` | `metadata` | bounded |
            MD;

        $this->assertSame(['GET /a'], ContractScan::duplicateRouteHeadings($headingCaseVariant));
    }

    /**
     * **The document's release-version examples agree with each other.**
     *
     * They did not: `GET /bfc/meta` showed `0.6.0`, the vitals payload
     * showed `0.5.0`, and the vitals section says in prose that it
     * reports the same discriminator `/bfc/meta` does — so a dashboard
     * implementing this specification saw two expected values for one
     * release. A lagging `BuiltForCloud::VERSION` explains a doc/code
     * mismatch; it explains nothing about a doc/doc one.
     *
     * DOC-INTERNAL, and that is the whole of the claim. This compares
     * the examples to each other and to NOTHING else. It does not pin
     * them to `BuiltForCloud::VERSION`, which lags the document until
     * the release is tagged — that window stays open and is the
     * release's to close, not this test's.
     */
    public function test_every_release_version_example_agrees(): void
    {
        $versions = ContractScan::releaseVersionExamplesIn($this->contractDoc());

        $this->assertNotEmpty(
            $versions,
            'docs/http-contract.md spells no bfc_version example at all, so this check would pass vacuously.',
        );

        $this->assertSame(
            [$versions[0]],
            array_values(array_unique($versions)),
            'docs/http-contract.md spells more than one release version in its bfc_version examples ('
            .implode(', ', array_unique($versions)).'). Every example names the same release, and the '
            .'vitals payload reports the same discriminator GET /bfc/meta does.',
        );

        // Proven able to fail, over a fixture.
        $this->assertSame(
            ['0.6.0', '0.5.0'],
            ContractScan::releaseVersionExamplesIn('{"bfc_version": "0.6.0"} and {"bfc_version": "0.5.0"}'),
        );
    }

    /**
     * **THE PAIR, HELD WITHOUT REQUIRING THE TAG TO HAVE HAPPENED.**
     *
     * `bfc_version` in this document and `BuiltForCloud::VERSION` in the
     * code are the same fact written twice, and nothing compared them:
     * every test in this suite compares a response to the CONSTANT and
     * none of them to the DOCUMENT, so the two read 0.6.0 and 0.5.0 for
     * a whole release and the suite stayed green.
     *
     * A plain equality assertion is the wrong instrument. The pair is
     * unequal ON PURPOSE for the length of a release window — the
     * document is written with the release it describes, the constant is
     * bumped when the tag is cut, and the tag follows the merge — so
     * asserting equality would red the suite for the entire window and
     * force the tag to happen before the merge, which is not how this
     * package releases.
     *
     * So what is required is that a difference be DECLARED. While the
     * two differ the document carries a line naming both halves, and it
     * has to name the right two. That leaves silent drift nowhere to
     * happen: change either side alone and the declaration is wrong;
     * remove the declaration and the difference is undeclared; land the
     * tag so the two agree and the declaration is stale. All four are
     * findings, and all four are driven in the test below this one.
     *
     * @see ContractScan::versionPairBreaksIn()
     */
    public function test_the_documented_release_and_the_constant_differ_only_where_the_document_declares_it(): void
    {
        $doc = $this->contractDoc();

        // THE FLOOR FIRST. A parse that recognised no version at all
        // would report no breaks, so the enumeration is asserted before
        // anything is concluded from it — and the foreign bucket with
        // it, because a version EXCLUDED from the comparison is the one
        // way a mention could vanish from it quietly.
        $this->assertNotEmpty(ContractScan::releaseVersionMentionsIn($doc));
        $this->assertSame(['app_version: 1.4.2'], ContractScan::foreignVersionMentionsIn($doc));

        $this->assertSame(
            [],
            ContractScan::versionPairBreaksIn($doc, BuiltForCloud::VERSION),
            'docs/http-contract.md and BuiltForCloud::VERSION disagree in a way nothing declares.',
        );

        // The wider half of the same property: EVERY spelling of the
        // release agrees, in prose as well as in the examples. The
        // examples check above this one could not see the changelog's
        // three prose mentions, and a document contradicting itself
        // about its own release discriminator is the defect PR8 fixed by
        // hand between two examples in this same file.
        $this->assertSame(
            [ContractScan::releaseVersionMentionsIn($doc)[0]],
            array_values(array_unique(ContractScan::releaseVersionMentionsIn($doc))),
            'docs/http-contract.md spells more than one release version: '
            .implode(', ', array_unique(ContractScan::releaseVersionMentionsIn($doc))),
        );
    }

    /**
     * Proven able to fail, over fixture documents carrying each offence
     * — including the one the shipped pair is in today, so the check is
     * demonstrated on a real mismatch rather than only on the clean
     * case.
     */
    public function test_names_a_version_pair_that_drifted_one_that_is_undeclared_and_a_declaration_left_behind(): void
    {
        $declared = <<<'MD'
            **RELEASE WINDOW: this document describes `bfc_version` 0.6.0; `BuiltForCloud::VERSION` is 0.5.0
            until the tag lands.**

            ```json
            {"bfc_version": "0.6.0", "app_version": "1.4.2"}
            ```

            The Console lands in 0.6.0.
            MD;

        // 1. THE SHIPPED SHAPE: a declared window over a real mismatch.
        //    The wrap is deliberate — the declaration is a sentence in a
        //    wrapped document, and a parse that only read it on one line
        //    would be satisfied by a document nobody can write.
        $this->assertSame(['pending' => '0.6.0', 'tagged' => '0.5.0'], ContractScan::releaseWindowIn($declared));
        $this->assertSame([], ContractScan::versionPairBreaksIn($declared, '0.5.0'));

        // 2. THE TAG LANDS. The two now agree and the declaration is
        //    stale, which is its own finding: a window that never closes
        //    is a licence to differ.
        $this->assertSame(
            ['the document and BuiltForCloud::VERSION both read 0.6.0, so the release window is over '
                .'and its declaration must be removed'],
            ContractScan::versionPairBreaksIn($declared, '0.6.0'),
        );

        // 3. SILENT DRIFT, which is what the criterion exists for: the
        //    same document with no declaration at all.
        $undeclared = '```json'.PHP_EOL.'{"bfc_version": "0.6.0"}'.PHP_EOL.'```'.PHP_EOL;

        $this->assertNull(ContractScan::releaseWindowIn($undeclared));
        $this->assertSame(
            ['the document describes 0.6.0 and BuiltForCloud::VERSION reads 0.5.0, and nothing '
                .'declares the difference'],
            ContractScan::versionPairBreaksIn($undeclared, '0.5.0'),
        );

        // 4. A DECLARATION THAT NAMES THE WRONG PAIR — the way a
        //    declaration could otherwise become a rubber stamp. Both
        //    halves are reported, not the first one found.
        $stale = str_replace(
            ['`bfc_version` 0.6.0;', 'is 0.5.0'],
            ['`bfc_version` 0.7.0;', 'is 0.4.0'],
            $declared,
        );

        $this->assertSame(
            [
                'the release-window declaration names 0.7.0 as pending while the document describes 0.6.0',
                'the release-window declaration names 0.4.0 as tagged while BuiltForCloud::VERSION reads 0.5.0',
            ],
            ContractScan::versionPairBreaksIn($stale, '0.5.0'),
        );

        // 5. THE DOCUMENT CONTRADICTING ITSELF, in prose against an
        //    example — the half `releaseVersionExamplesIn()` cannot see,
        //    because it reads `"bfc_version": "…"` and nothing else.
        $contradictory = '```json'.PHP_EOL.'{"bfc_version": "0.6.0"}'.PHP_EOL.'```'
            .PHP_EOL.PHP_EOL.'The Console lands in 0.5.0.'.PHP_EOL;

        $this->assertSame(['0.6.0'], ContractScan::releaseVersionExamplesIn($contradictory));
        $this->assertSame(['0.6.0', '0.5.0'], ContractScan::releaseVersionMentionsIn($contradictory));
        $this->assertSame(
            ['the document spells more than one release version (0.6.0, 0.5.0), so which one the '
                .'constant should be compared to has no answer'],
            ContractScan::versionPairBreaksIn($contradictory, '0.6.0'),
        );

        // 6. THE EXCLUSION IS A LIST, NOT A FILTER. `app_version` is the
        //    consuming application's release and is supposed to differ,
        //    so it is classified out — and returned, so a reader can
        //    see what was left out of the comparison.
        $this->assertSame(['app_version: 1.4.2'], ContractScan::foreignVersionMentionsIn($declared));

        // 7. AND HERE IS WHAT THAT EXCLUSION COSTS, asserted rather
        //    than left as a sentence. A semver under a key that is not
        //    exactly `bfc_version` is compared to nothing, so a
        //    document can describe another package's release and stay
        //    green. That is why the shipped check asserts the foreign
        //    SET rather than trusting the release set alone.
        $foreign = '{"bfc_version": "0.6.0", "scalpels_version": "0.7.0"}';

        $this->assertSame(['0.6.0'], ContractScan::releaseVersionMentionsIn($foreign));
        $this->assertSame([], ContractScan::versionPairBreaksIn($foreign, '0.6.0'));
        $this->assertSame(['scalpels_version: 0.7.0'], ContractScan::foreignVersionMentionsIn($foreign));
    }

    /**
     * D6 and D8: a declaration a reader cannot see, two of them at
     * once, and one that points the wrong way.
     *
     * The first two were accepted by the shipped parse. A declaration
     * inside an HTML comment satisfied it while rendering to nothing —
     * a licence to differ that no consumer of this contract could read
     * — and a second declaration beside the first was ignored, so the
     * document could name the real pair once and any other pair as
     * well, with whichever came first deciding.
     */
    public function test_refuses_a_release_window_a_reader_cannot_see_a_duplicate_one_and_one_that_goes_backwards(): void
    {
        $window = '**RELEASE WINDOW: this document describes `bfc_version` %s; '
            .'`BuiltForCloud::VERSION` is %s until the tag lands.**';

        $body = PHP_EOL.PHP_EOL.'{"bfc_version": "0.6.0"}'.PHP_EOL;

        // Hidden: parsed, and refused as no declaration at all — so the
        // difference below it is undeclared rather than licensed.
        $hidden = '<!-- '.sprintf($window, '0.6.0', '0.5.0').' -->'.$body;

        $this->assertNull(ContractScan::releaseWindowIn($hidden));
        $this->assertSame(
            [['pending' => '0.6.0', 'tagged' => '0.5.0', 'visible' => false]],
            ContractScan::releaseWindowsIn($hidden),
        );
        $this->assertSame(
            ['the release-window declaration is inside an HTML comment, where a reader of this '
                .'document cannot see it'],
            ContractScan::versionPairBreaksIn($hidden, '0.5.0'),
        );

        // Duplicated: the first names the true pair, so a parse that
        // stopped at the first match called this clean.
        $duplicated = sprintf($window, '0.6.0', '0.5.0').PHP_EOL.PHP_EOL
            .sprintf($window, '0.9.9', '0.1.0').$body;

        $this->assertNull(ContractScan::releaseWindowIn($duplicated));
        $this->assertCount(2, ContractScan::releaseWindowsIn($duplicated));
        $this->assertSame(
            ['the document carries 2 release-window declarations, so which pair it declares has no answer'],
            ContractScan::versionPairBreaksIn($duplicated, '0.5.0'),
        );

        // Backwards: internally consistent and honest about both
        // halves, and tagging it would move the package down a version.
        $backwards = sprintf($window, '0.5.0', '0.6.0').PHP_EOL.PHP_EOL.'{"bfc_version": "0.5.0"}'.PHP_EOL;

        $this->assertSame(
            ['the release-window declaration has 0.5.0 pending behind 0.6.0 tagged, so tagging it '
                .'would go backwards'],
            ContractScan::versionPairBreaksIn($backwards, '0.6.0'),
        );

        // A visible, single, forward declaration over the same body is
        // clean, so the three assertions above are read as findings
        // rather than as a check that refuses everything.
        $this->assertSame([], ContractScan::versionPairBreaksIn(sprintf($window, '0.6.0', '0.5.0').$body, '0.5.0'));
    }

    /**
     * **The version signal, checked rather than asserted.**
     *
     * `api_version` stays 2 across this release, so what tells a
     * consumer what a deployment can do is `bfc_version` plus the
     * `capabilities` array — which the changelog now says in those
     * words. That makes "every capability this package reports is named
     * in the contract" a load-bearing sentence rather than a courtesy: a
     * capability the code emits and the document never mentions is a
     * feature no consumer can discover, on the one axis the release
     * deliberately left as the discovery mechanism.
     *
     * Modelled on the operator-ability check above, and with the same
     * two halves: the emitted SET is pinned, so a capability cannot
     * appear or vanish without the diff saying so, and each emitted name
     * must occur in the document.
     *
     * WHAT IT DOES NOT CATCH. `Somewhere` is the whole of the second
     * half — an occurrence check over the file, so a capability named
     * only in a changelog line passes, and nothing here reads what the
     * document SAYS about one. Nor does it check the PREDICATE: that
     * `console-enter` appears under a stricter condition than
     * `console-guard` is driven behaviourally, in
     * `tests/ConsoleEnterForeignGuardTest.php` and
     * `tests/ConsoleDisabledTest.php`. This suite's app is a
     * console-ENABLED deployment whose delegated guard is the package's
     * own, so the response below carries the conditional capabilities
     * too; on a console-disabled app it would carry eight, and the
     * pinned set would red rather than quietly shrink.
     *
     * The same list is pinned a second time, as a response SHAPE, by
     * `tests/OwnershipFoundationTest.php` — "returns unauthenticated bfc
     * meta for unclaimed and claimed environments". Two places to update
     * when a capability lands, deliberately: that one asserts the whole
     * `/bfc/meta` body, this one asserts the release signal and ties it
     * to the document. Whoever adds a capability will meet both.
     */
    public function test_every_capability_this_deployment_reports_is_named_in_the_contract(): void
    {
        $expected = [
            'tokens', 'ownership', 'onboarding', 'webhooks', 'credentials',
            'console-keys', 'console-vitals', 'app-action-audit-emit',
            'console-guard', 'console-enter', 'console-chrome-assets',
        ];

        $reported = (array) $this->getJson('/bfc/meta')->assertOk()->json('capabilities');

        $this->assertSame(
            $expected,
            $reported,
            'The capabilities GET /bfc/meta reports have changed. That is the release signal this '
            .'contract tells consumers to feature-detect on, so extend this set in the same diff — and '
            .'name the new capability in docs/http-contract.md.',
        );

        $doc = $this->contractDoc();

        $this->assertSame(
            [],
            ContractScan::capabilitiesNotNamedIn($doc, $reported),
            'GET /bfc/meta reports capabilities docs/http-contract.md never names: '
            .implode(', ', ContractScan::capabilitiesNotNamedIn($doc, $reported)),
        );

        // Proven able to fail, over a fixture rather than by editing the
        // shipped contract.
        $this->assertSame(
            ['console-enter'],
            ContractScan::capabilitiesNotNamedIn('a doc naming `tokens` and nothing else', ['tokens', 'console-enter']),
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
        // ONE definition of "a documented route", shared with the
        // classification scan. Two copies of this regex would be two
        // definitions that drift, and the drift would be invisible: each
        // check would stay green against its own reading of the file.
        return ContractScan::documentedRoutes($this->contractDoc());
    }
}
