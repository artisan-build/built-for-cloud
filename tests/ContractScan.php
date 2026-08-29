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
 * WHAT THESE SCANS CHECK, and the boundary of each — worded as what is
 * checked rather than as how complete the set is, because the first
 * revision of this docblock claimed to state its blind spots "in full"
 * and then missed one. A duplicate classification row was invisible: the
 * map was keyed by route, so a second row silently overwrote the first
 * and a document classifying `GET /a` as both `metadata` and `content`
 * produced no unclassified route and no phantom route. That is now
 * {@see conflictingClassifications()}, and the lesson is kept in the
 * wording: an instrument that reports its own completeness has made the
 * one kind of claim it exists to prevent.
 *
 *  - {@see unclassifiedRoutes()} checks that a documented route HAS a
 *    classification. Not that the classification is CORRECT — a route
 *    returning free text under a `metadata` row passes here. The truth
 *    of a row against a real response is
 *    `ContractAssertions::assertBuiltForCloudMetadataEndpoint()`'s job,
 *    in `tests/MetadataShapeTest.php`, and it covers this package's own
 *    metadata endpoints only.
 *  - {@see conflictingClassifications()} checks that a route carries at
 *    most ONE classification row, so the table cannot state two answers
 *    for one route. {@see duplicateRouteHeadings()} is the same property
 *    one level up, over the `### METHOD /path` headings themselves.
 *  - {@see documentedRoutes()} sees only routes the document declares
 *    with such a heading. A route that exists and is documented nowhere
 *    is caught against the ROUTER instead, by the route-completeness
 *    checks in `tests/HttpContractDocTest.php`.
 *  - {@see capabilitiesNotNamedIn()} checks that a capability's NAME
 *    occurs in the document. Not that what the document says about it is
 *    true, and not that the condition under which the package emits it
 *    matches the predicate the document states — those are driven
 *    behaviourally, per capability, in the Console suites.
 *  - {@see releaseVersionExamplesIn()} checks that the document's
 *    `bfc_version` examples agree with EACH OTHER. It is deliberately
 *    doc-internal: it says nothing about whether they agree with
 *    `BuiltForCloud::VERSION`, which lags until the release is tagged.
 *  - Nothing here reads the `basis` column of the classification table.
 */
final class ContractScan
{
    /**
     * Every `### METHOD /path` heading — the machine-checkable
     * convention the document commits to in its own opening.
     *
     * @return list<string>
     */
    public static function documentedRoutes(string $doc): array
    {
        preg_match_all('/^### (GET|POST|PUT|PATCH|DELETE) (\/\S+)$/m', $doc, $matches, PREG_SET_ORDER);

        $routes = array_map(
            static fn (array $match): string => $match[1].' '.$match[2],
            $matches,
        );

        sort($routes);

        return array_values(array_unique($routes));
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
            '/^\| `(GET|POST|PUT|PATCH|DELETE) (\/[^`]+)` \| `(metadata|content)` \|/m',
            $doc,
            $matches,
            PREG_SET_ORDER,
        );

        $classified = [];

        foreach ($matches as $match) {
            $classified[$match[1].' '.$match[2]][] = $match[3];
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
        preg_match_all('/^### (GET|POST|PUT|PATCH|DELETE) (\/\S+)$/m', $doc, $matches, PREG_SET_ORDER);

        $counts = [];

        foreach ($matches as $match) {
            $route = $match[1].' '.$match[2];
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
