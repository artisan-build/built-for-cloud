<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

/**
 * Pure text scans over `docs/http-contract.md`, so the claims the
 * document makes about ITSELF can be checked the way the claims it makes
 * about the CODE already are.
 *
 * WHY THIS IS A SEPARATE CLASS AND TAKES THE DOCUMENT AS A STRING. Every
 * method here is a pure function of the text, which is what lets
 * {@see HttpContractDocTest} drive each one over a FIXTURE document
 * carrying the offence — the standing rule on this package's scanners:
 * an instrument nobody has watched fail is a claim, not a check. Reading
 * the real file inside these methods would have made that impossible
 * without editing the shipped contract.
 *
 * WHAT EACH SCAN CHECKS, and what it leaves over. **Written as what is
 * checked, never as how complete the set is** — twice now a sentence
 * about this class's own coverage has outrun what the class does, which
 * is exactly the failure the class exists to catch in the document. The
 * first claimed to state its blind spots "in full" and missed duplicate
 * rows; the replacement claimed each heading is required to carry
 * "exactly one" row, and missed case and whitespace variants of the same
 * route. So there is no completeness sentence here any more, and there
 * should not be one added: these are regexes over Markdown, and a claim
 * about what a Markdown document CANNOT contain is not something a regex
 * can own.
 *
 * **THE RESIDUE, which is the honest form of the same information: a
 * heading or a row this parse does not RECOGNISE is not counted, and no
 * scan below can see it.** Recognition is normalized — the method is
 * matched case-insensitively and internal whitespace is collapsed, so
 * `get /a`, `GET  /a` and `GET /a` are one route — but normalization is
 * a list of variants somebody thought of, and the next variant (a
 * unicode lookalike, a trailing character, a differently rendered table)
 * is not on it. What these scans give is that the recognised rows are
 * consistent with the recognised headings; a reader wanting more than
 * that has to read the table.
 *
 *  - {@see unclassifiedRoutes()} — a recognised route heading with no
 *    recognised classification row. Not whether the classification is
 *    CORRECT: a route returning free text under a `metadata` row passes
 *    here, and is caught, for this package's own metadata endpoints
 *    only, by `ContractAssertions::assertBuiltForCloudMetadataEndpoint()`
 *    in `tests/MetadataShapeTest.php`.
 *  - {@see phantomClassifications()} — a recognised row whose route has
 *    no recognised heading.
 *  - {@see conflictingClassifications()} — a route with more than one
 *    recognised row, so the table cannot give two answers to "is this
 *    safe for a vendor-side read".
 *  - {@see duplicateRouteHeadings()} — the same route under more than
 *    one recognised heading.
 *  - {@see documentedRoutes()} sees only headings. A route that exists
 *    and is documented nowhere is caught against the ROUTER, by the
 *    route-completeness checks in `tests/HttpContractDocTest.php`.
 *  - {@see capabilitiesNotNamedIn()} — a capability NAME that does not
 *    occur in the document. Not whether what the document says about it
 *    is true, and not whether the condition the package emits it under
 *    matches the predicate the document states; those are driven
 *    behaviourally, per capability, in the Console suites.
 *  - {@see releaseVersionExamplesIn()} — the `bfc_version` examples,
 *    compared to each other. Deliberately doc-internal.
 *  - {@see releaseVersionMentionsIn()} — a SYNTACTIC set, and worth
 *    reading as one: semver-shaped tokens standing bare in the text,
 *    plus the value of a JSON field spelled exactly `bfc_version`. It
 *    is wider than the examples scan, which reads only the second of
 *    those, and the changelog's three running-text spellings are inside
 *    it for that reason. It is NOT "every mention of a release": a
 *    version under any other key is {@see foreignVersionMentionsIn()}'s,
 *    so a document naming another package's release as
 *    `"scalpels_version": "0.7.0"` says nothing to this comparison.
 *  - {@see foreignVersionMentionsIn()} — semver tokens that are the
 *    JSON value of a field other than `bfc_version`. `app_version` in
 *    the vitals example is the consuming application's release and is
 *    supposed to differ. They are returned rather than dropped, so the
 *    exclusion is a list somebody can read; reading it is the only
 *    thing that catches a release hidden under an unexpected key.
 *  - {@see versionPairBreaksIn()} — the document's release against
 *    `BuiltForCloud::VERSION`. NOT an equality assertion: the two are
 *    deliberately unequal during a release window, because the
 *    orchestrator bumps the constant at tag time and the tag follows
 *    the merge. What it requires is that a difference be DECLARED, in a
 *    line naming both halves, so the only way for them to differ is for
 *    someone to write down that they differ and what the pending
 *    version is. Six things are findings: an undeclared difference, a
 *    declaration naming the wrong pending half, the wrong tagged half,
 *    a pending version behind the tagged one, a declaration still
 *    standing once the two agree, and more than one declaration. A
 *    seventh — a declaration hidden inside an HTML comment — is refused
 *    as no declaration at all.
 *  - Nothing here reads the `basis` column of the classification table.
 */
final class ContractScan
{
    /**
     * The release-window declaration, in the one shape this parse
     * recognises. A fixed sentence rather than a comment, so the reader
     * a release window actually affects — a consumer whose deployment
     * reports a lower `bfc_version` than this document describes — is
     * told, and the machine reads the same words they do.
     *
     * Every space in it is `\s+`, so the sentence may wrap; nothing
     * else about it may vary, and a declaration written any other way
     * is not recognised and therefore not present.
     */
    public const string RELEASE_WINDOW = '/RELEASE\s+WINDOW:\s+this\s+document\s+describes\s+`bfc_version`'
        .'\s+([0-9A-Za-z.\-]+);\s+`BuiltForCloud::VERSION`\s+is\s+([0-9A-Za-z.\-]+)\s+until\s+the\s+tag\s+lands\./';

    /**
     * Every `### METHOD /path` heading — the machine-checkable
     * convention the document commits to in its own opening.
     *
     * @return list<string>
     */
    public static function documentedRoutes(string $doc): array
    {
        $routes = array_map(
            static fn (array $match): string => self::normalize($match[1], $match[2]),
            self::routeHeadingMatches($doc),
        );

        sort($routes);

        return array_values(array_unique($routes));
    }

    /**
     * One route, in the single spelling every scan here counts by:
     * upper-case method, one space, path as written.
     *
     * **Normalization is what makes "the same route" a decidable
     * question at all.** Two rows spelled `GET /a` and `get  /a` render
     * as one endpoint and read as one endpoint, so counting them as two
     * routes let a contradictory pair through every scan below. It is
     * also, unavoidably, a list of the variants someone thought of — the
     * class docblock names that as the residue rather than implying the
     * list is closed.
     */
    private static function normalize(string $method, string $path): string
    {
        return strtoupper(trim($method)).' '.(string) preg_replace('/\s+/', '', $path);
    }

    /**
     * Every `### METHOD /path` heading, matched case-insensitively and
     * tolerating repeated internal whitespace.
     *
     * @return list<array<int, string>>
     */
    private static function routeHeadingMatches(string $doc): array
    {
        preg_match_all('/^###\s+(GET|POST|PUT|PATCH|DELETE)\s+(\/\S+)\s*$/mi', $doc, $matches, PREG_SET_ORDER);

        return $matches;
    }

    /**
     * The classification table, as route => EVERY row found for it, in
     * document order.
     *
     * **A list per route, not one value.** Keying a value by route made
     * a second row overwrite the first, which is how a table stating two
     * classifications for one endpoint read as clean to every scan built
     * on this method. {@see conflictingClassifications()} is what the
     * list is for.
     *
     * @return array<string, list<string>>
     */
    public static function classifiedRoutes(string $doc): array
    {
        preg_match_all(
            '/^\|\s*`(GET|POST|PUT|PATCH|DELETE)\s+(\/[^`]+)`\s*\|\s*`(metadata|content)`\s*\|/mi',
            $doc,
            $matches,
            PREG_SET_ORDER,
        );

        $classified = [];

        foreach ($matches as $match) {
            $classified[self::normalize($match[1], $match[2])][] = strtolower($match[3]);
        }

        ksort($classified);

        return $classified;
    }

    /**
     * Routes the classification table gives more than one row.
     *
     * **This is the contradiction the column exists to make impossible.**
     * The classification is the durable privacy boundary a vendor-side
     * reader decides by, so a route carrying both a `metadata` row and a
     * `content` row does not merely duplicate — it gives two different
     * answers to "is this safe to read", and whichever a reader's eye
     * lands on first is the one they act on.
     *
     * Any repeat is reported, not only a disagreeing one: a table that
     * lists one endpoint twice is a defect whether or not the two rows
     * happen to match, and "the duplicate agreed with itself" is not a
     * property worth carving an exception for.
     *
     * @return list<string> each as `METHOD /path: classification, classification`
     */
    public static function conflictingClassifications(string $doc): array
    {
        $conflicts = [];

        foreach (self::classifiedRoutes($doc) as $route => $classifications) {
            if (count($classifications) > 1) {
                $conflicts[] = $route.': '.implode(', ', $classifications);
            }
        }

        return $conflicts;
    }

    /**
     * Routes the document declares with more than one `### METHOD /path`
     * heading — the same property as
     * {@see conflictingClassifications()}, one level up.
     *
     * {@see documentedRoutes()} de-duplicates, deliberately: the
     * completeness checks compare SETS against the router and a repeat
     * would break them for the wrong reason. That de-duplication is
     * exactly what hides two sections claiming to define one route, so
     * the repeat is reported here instead of being silently absorbed.
     *
     * @return list<string>
     */
    public static function duplicateRouteHeadings(string $doc): array
    {
        $counts = [];

        foreach (self::routeHeadingMatches($doc) as $match) {
            $route = self::normalize($match[1], $match[2]);
            $counts[$route] = ($counts[$route] ?? 0) + 1;
        }

        $duplicates = array_keys(array_filter($counts, static fn (int $n): bool => $n > 1));

        sort($duplicates);

        return $duplicates;
    }

    /**
     * Every release version the document spells in a `bfc_version`
     * example, in document order.
     *
     * **Doc-internal on purpose.** Three examples of one field carried
     * three different versions at once — `GET /bfc/meta` said one thing,
     * the vitals payload another, and the versioning section a third —
     * while the vitals section says in prose that it reports the same
     * discriminator `/bfc/meta` does. A consumer implementing this
     * specification saw two expected values for one release.
     *
     * It compares the examples to EACH OTHER and to nothing else. It
     * does NOT compare them to `BuiltForCloud::VERSION`, which lags the
     * document until the release is tagged; that window is real and is
     * named in the report, not closed here.
     *
     * @return list<string>
     */
    public static function releaseVersionExamplesIn(string $doc): array
    {
        preg_match_all('/"bfc_version":\s*"([^"]+)"/', $doc, $matches);

        return array_values($matches[1]);
    }

    /**
     * Documented routes carrying no classification row.
     *
     * **This is the direction a filtering scan cannot see.** The shipped
     * check before this one asserted that ONE named row said `metadata`
     * — a check that reads a row it selected by name is blind to a route
     * that has no row at all, which is precisely how a new endpoint
     * escapes the privacy boundary the column exists to be. So this
     * enumerates the routes and requires each to be classified.
     *
     * @return list<string>
     */
    public static function unclassifiedRoutes(string $doc): array
    {
        return array_values(array_diff(
            self::documentedRoutes($doc),
            array_keys(self::classifiedRoutes($doc)),
        ));
    }

    /**
     * Classification rows naming no documented route — the other
     * direction, and a real failure rather than tidiness: a row for a
     * route that no longer exists tells a vendor-side reader a surface
     * is safe to read when there is no surface.
     *
     * @return list<string>
     */
    public static function phantomClassifications(string $doc): array
    {
        return array_values(array_diff(
            array_keys(self::classifiedRoutes($doc)),
            self::documentedRoutes($doc),
        ));
    }

    /**
     * The release-window declaration, as `pending` and `tagged`, or
     * null when the document carries none.
     *
     * The declaration is a SENTENCE and not a comment, because a
     * consumer reading this document during a release window needs to
     * know that the deployment they are talking to may report a lower
     * `bfc_version` than the document describes. Making it machine-read
     * as well costs a fixed shape and nothing else.
     *
     * @return array{pending: string, tagged: string}|null
     */
    public static function releaseWindowIn(string $doc): ?array
    {
        $windows = self::releaseWindowsIn($doc);

        return count($windows) === 1 && $windows[0]['visible'] ? [
            'pending' => $windows[0]['pending'],
            'tagged' => $windows[0]['tagged'],
        ] : null;
    }

    /**
     * EVERY occurrence of the declaration sentence, each with whether a
     * reader of the rendered document would see it.
     *
     * **Both halves of this were defects.** A declaration inside an HTML
     * comment satisfied the parse while rendering to nothing, so the
     * document could carry a licence to differ that no consumer could
     * read — and a licence nobody can see is not a declaration. And two
     * declarations satisfied it as well, with the first one found
     * deciding: a document could name the real pair once and any other
     * pair beside it.
     *
     * Visibility is decided by whether the sentence falls inside an
     * `<!-- … -->` span. That is the concealment Markdown offers here
     * and the one that was tried; a sentence hidden some other way — a
     * fenced code block, a `<details>` a reader must open, an HTML
     * attribute — is reported as visible.
     *
     * @return list<array{pending: string, tagged: string, visible: bool}>
     */
    public static function releaseWindowsIn(string $doc): array
    {
        if (preg_match_all(self::RELEASE_WINDOW, $doc, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE) === false) {
            return [];
        }

        $comments = [];

        if (preg_match_all('/<!--.*?-->/s', $doc, $found, PREG_OFFSET_CAPTURE) !== false) {
            foreach ($found[0] as $comment) {
                $comments[] = [$comment[1], $comment[1] + strlen($comment[0])];
            }
        }

        $windows = [];

        foreach ($matches as $match) {
            $offset = $match[0][1];
            $hidden = false;

            foreach ($comments as [$from, $to]) {
                if ($offset >= $from && $offset < $to) {
                    $hidden = true;

                    break;
                }
            }

            $windows[] = [
                'pending' => $match[1][0],
                'tagged' => $match[2][0],
                'visible' => ! $hidden,
            ];
        }

        return $windows;
    }

    /**
     * The semver tokens this parse READS AS THIS DOCUMENT'S OWN
     * RELEASE, in document order: a token standing bare in the text, or
     * the value of a JSON field spelled exactly `bfc_version`.
     *
     * **A syntactic rule, not "every release the document mentions",
     * and the difference is load-bearing.** A version given under any
     * other key — `"scalpels_version": "0.7.0"` — is classified foreign
     * and compared to nothing, so a document can describe another
     * package's release and this says nothing about it. What catches
     * that is reading {@see foreignVersionMentionsIn()}, which is why
     * it is returned.
     *
     * The prose half is the direction `releaseVersionExamplesIn()`
     * cannot see: it reads `"bfc_version": "…"` and nothing else, so
     * the changelog's "bfc **0.6.0**, this release" and "`bfc_version`
     * 0.6.0 plus the `capabilities` entries" were outside every check.
     *
     * The release-window declaration is removed before matching, since
     * it names both halves of a pair that is supposed to differ.
     *
     * @return list<string>
     */
    public static function releaseVersionMentionsIn(string $doc): array
    {
        return self::classifyVersions($doc)['release'];
    }

    /**
     * Semver tokens the document gives as the value of a field other
     * than `bfc_version`, each as `field: version`.
     *
     * They are excluded from the release comparison and RETURNED rather
     * than dropped, so the exclusion is a list somebody can read
     * instead of a filter that swallows things silently. `app_version`
     * in the vitals example is the consuming application's release and
     * has no reason to match anything here.
     *
     * **Reading this list is the only thing that catches a release
     * spelled under a key nobody expected.** Nothing here decides
     * whether a key OUGHT to have been compared:
     * `"scalpels_version": "0.7.0"` lands here exactly as `app_version`
     * does, and the check that the set is what it should be is an
     * assertion in `tests/HttpContractDocTest.php`, not a rule in this
     * method.
     *
     * @return list<string>
     */
    public static function foreignVersionMentionsIn(string $doc): array
    {
        return self::classifyVersions($doc)['foreign'];
    }

    /**
     * How the document's release and `BuiltForCloud::VERSION` disagree,
     * if they do — each as a sentence naming what to do about it.
     *
     * **WHY THIS IS NOT AN EQUALITY ASSERTION.** The pair is unequal on
     * purpose for the length of a release window: the bucket lands, the
     * document describes the release it is part of, and the constant is
     * bumped when the tag is cut. Asserting equality would red the suite
     * for that whole window and force the tag to happen before the
     * merge, which is not how this package releases.
     *
     * So the property is not "they agree" but **"a difference is
     * declared"**: while they differ, the document must carry one
     * VISIBLE line naming both halves, and it must name the right two.
     * Changing either side alone makes the declaration wrong; removing
     * it leaves the difference undeclared; landing the tag so the two
     * agree makes it stale; writing a second one makes the pair
     * ambiguous; hiding it in an HTML comment is not writing one.
     *
     * WHAT IT READS: this document and one string. **Not
     * `composer.json`, not a git tag, not the release notes** — and
     * `release-notes/console-reservations.md` spells a release of its
     * own that nothing compares to anything, which is a real hole
     * rather than a hypothetical one and is carried as a debt row. What
     * is pinned is the pair the report said drifted, and only that
     * pair.
     *
     * @return list<string>
     */
    public static function versionPairBreaksIn(string $doc, string $constant): array
    {
        $mentions = array_values(array_unique(self::releaseVersionMentionsIn($doc)));
        $declared = self::releaseWindowsIn($doc);
        $window = self::releaseWindowIn($doc);
        $breaks = [];

        if (count($declared) > 1) {
            return ['the document carries '.count($declared).' release-window declarations, so which '
                .'pair it declares has no answer'];
        }

        if ($declared !== [] && ! $declared[0]['visible']) {
            return ['the release-window declaration is inside an HTML comment, where a reader of this '
                .'document cannot see it'];
        }

        if ($mentions === []) {
            return ['the document spells no release version at all, so there is no pair to pin'];
        }

        if (count($mentions) > 1) {
            $breaks[] = 'the document spells more than one release version ('.implode(', ', $mentions)
                .'), so which one the constant should be compared to has no answer';

            return $breaks;
        }

        $documented = $mentions[0];

        if ($documented === $constant) {
            if ($window !== null) {
                $breaks[] = 'the document and BuiltForCloud::VERSION both read '.$constant
                    .', so the release window is over and its declaration must be removed';
            }

            return $breaks;
        }

        if ($window === null) {
            return ['the document describes '.$documented.' and BuiltForCloud::VERSION reads '
                .$constant.', and nothing declares the difference'];
        }

        if ($window['pending'] !== $documented) {
            $breaks[] = 'the release-window declaration names '.$window['pending']
                .' as pending while the document describes '.$documented;
        }

        if ($window['tagged'] !== $constant) {
            $breaks[] = 'the release-window declaration names '.$window['tagged']
                .' as tagged while BuiltForCloud::VERSION reads '.$constant;
        }

        if ($breaks === [] && version_compare($window['pending'], $window['tagged'], '<')) {
            $breaks[] = 'the release-window declaration has '.$window['pending']
                .' pending behind '.$window['tagged'].' tagged, so tagging it would go backwards';
        }

        return $breaks;
    }

    /**
     * Every semver token in the document, in one of two buckets.
     *
     * @return array{release: list<string>, foreign: list<string>}
     */
    private static function classifyVersions(string $doc): array
    {
        $doc = (string) preg_replace(self::RELEASE_WINDOW, ' ', $doc);

        preg_match_all(
            '/"([A-Za-z_][A-Za-z0-9_]*)"\s*:\s*"(\d+\.\d+\.\d+[^"]*)"|(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)/',
            $doc,
            $matches,
            PREG_SET_ORDER,
        );

        $release = [];
        $foreign = [];

        foreach ($matches as $match) {
            if (($match[1] ?? '') !== '') {
                if ($match[1] === 'bfc_version') {
                    $release[] = $match[2];
                } else {
                    $foreign[] = $match[1].': '.$match[2];
                }

                continue;
            }

            $release[] = $match[3];
        }

        return ['release' => $release, 'foreign' => $foreign];
    }

    /**
     * Capabilities the document never names, in back-quotes, anywhere.
     *
     * @param  list<string>  $capabilities
     * @return list<string>
     */
    public static function capabilitiesNotNamedIn(string $doc, array $capabilities): array
    {
        return array_values(array_filter(
            $capabilities,
            static fn (string $capability): bool => ! str_contains($doc, '`'.$capability.'`'),
        ));
    }
}
