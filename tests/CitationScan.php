<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 * The convention that keeps this package's security claims honest, made
 * checkable: **every guarantee sentence names the test that pins it, in
 * a `Pinned by` citation, and every title a citation quotes resolves to
 * a real test.**
 *
 * WHY IT EXISTS. Four consecutive review rounds on the Console guard
 * found the same defect — prose claiming more than the code delivered —
 * so the guarantees were made to cite their tests. But a citation is
 * only as good as its resolvability: **a renamed test silently orphans
 * its citation while the document still looks checkable**, which is the
 * exact failure the citations were introduced to fix, one level up. This
 * scan closes that. It found three stale titles and two abbreviations on
 * its first run, which is the argument for it.
 *
 * THE CONVENTION IT ENFORCES, and it is a formatting rule as much as a
 * content one:
 *
 *  - A citation begins with the words `Pinned by` and runs to the end of
 *    its PARAGRAPH — a blank line in Markdown, an empty ` *` line in a
 *    docblock. It must therefore be its own paragraph; prose that runs
 *    on would be read as part of the citation.
 *  - Every double-quoted string inside a citation is a TEST TITLE and
 *    must match one exactly. Not "starts with", not "contains" — an
 *    abbreviation like `"…when the store is still down"` is not
 *    checkable, and this scan refuses it.
 *  - Line wrapping is normalised first, so a title may wrap across lines
 *    and across a docblock's ` * ` markers.
 *
 * TWO QUESTIONS, because they fail differently.
 * {@see orphansIn()} asks "does every cited title resolve to a real
 * test" — the drift a rename causes. {@see shortfallsIn()} and
 * {@see unexpectedIn()} ask "does every file that is SUPPOSED to carry
 * guarantees actually cite anything", which is the drift a NEW file
 * causes. The second pair exists because the first cannot see it: a
 * scanner that only checks citations that already exist reports
 * "clean" for a document that makes ten guarantees and cites none, and
 * an AGGREGATE floor over every scanned file hides it behind the
 * older files' counts. That is exactly what happened to the first PR
 * written after this convention shipped.
 *
 * WHAT IT DOES NOT COVER. It resolves titles against `it('…')` and
 * `it("…")` declarations under `tests/`, and against PHPUnit-style
 * `public function test_snake_case()` methods, which it humanises the
 * way Pest's own reporter does (drop `test_`, underscores to spaces) —
 * so a fact that has to be driven PHPUnit-style, as a config-before-boot
 * test must be, is citable rather than pushing its author towards
 * citing nothing. It does not check that the named FILE contains the
 * named test, only that some test somewhere has that title — a title
 * moved between files still resolves. It says nothing about whether the
 * test actually pins the claim beside it; that is a reader's job, and
 * the citation exists to make it possible.
 *
 * And the per-file expectation is an ENUMERATION, with an enumeration's
 * residue: a brand-new guarantee-bearing document that nobody adds to
 * the scanned surfaces is invisible to it. Adding the file is the
 * human step, and the moment it is added a zero-citation file reds the
 * suite. This is a tripwire against the ordinary omission, not a proof
 * about every file that could exist.
 */
final class CitationScan
{
    /** The marker that opens a citation. */
    public const string MARKER = 'Pinned by';

    /**
     * Every title quoted by a citation in one file, in the order they
     * appear, with line wrapping and docblock markers normalised away.
     *
     * @return list<string>
     */
    public static function citedTitlesIn(string $contents): array
    {
        $titles = [];

        foreach (self::citations($contents) as $citation) {
            preg_match_all('/"([^"]+)"/', $citation, $matches);

            foreach ($matches[1] as $title) {
                $titles[] = $title;
            }
        }

        return $titles;
    }

    /**
     * How many citations a file carries — the floor that stops a scanner
     * which matched nothing from reporting "clean".
     */
    public static function countCitationsIn(string $contents): int
    {
        return count(self::citations($contents));
    }

    /**
     * Every cited title across a set of files, keyed by relative path.
     *
     * @param  list<string>  $paths
     * @return array<string, list<string>>
     */
    public static function scan(string $root, array $paths): array
    {
        $found = [];

        foreach ($paths as $path) {
            $target = $root.'/'.$path;

            foreach (is_dir($target) ? self::phpFiles($target, $path) : [$path => $target] as $relative => $file) {
                $titles = self::citedTitlesIn((string) file_get_contents($file));

                if ($titles !== []) {
                    $found[$relative] = $titles;
                }
            }
        }

        ksort($found);

        return $found;
    }

    /**
     * Every title declared by a Pest `it()` under a tests directory.
     *
     * @return list<string>
     */
    public static function declaredTitles(string $testsRoot): array
    {
        $titles = [];

        foreach (self::phpFiles($testsRoot, '') as $file) {
            $contents = (string) file_get_contents($file);

            preg_match_all("/\\bit\\(\\s*'((?:[^'\\\\]|\\\\.)*)'/", $contents, $single);
            preg_match_all('/\bit\(\s*"((?:[^"\\\\]|\\\\.)*)"/', $contents, $double);
            // PHPUnit-style cases, humanised the way Pest's own reporter
            // prints them. Some facts can only be driven this way — a
            // config key consumed at provider boot has to be in place
            // before the application exists — and a convention that
            // could not cite them would push their authors into citing
            // nothing at all.
            preg_match_all('/\bfunction\s+test_([A-Za-z0-9_]+)\s*\(/', $contents, $phpunit);

            foreach ($single[1] as $title) {
                $titles[] = str_replace(["\\'", '\\\\'], ["'", '\\'], $title);
            }

            foreach ($double[1] as $title) {
                $titles[] = str_replace('\\"', '"', $title);
            }

            foreach ($phpunit[1] as $method) {
                $titles[] = str_replace('_', ' ', $method);
            }
        }

        return array_values(array_unique($titles));
    }

    /**
     * Cited titles that resolve to no declared test — the orphans this
     * scan exists to name, each as `path: "title"`.
     *
     * @param  list<string>  $paths
     * @return list<string>
     */
    public static function orphansIn(string $root, array $paths, string $testsRoot): array
    {
        $declared = self::declaredTitles($testsRoot);
        $orphans = [];

        foreach (self::scan($root, $paths) as $relative => $titles) {
            foreach ($titles as $title) {
                if (! in_array($title, $declared, true)) {
                    $orphans[] = $relative.': "'.$title.'"';
                }
            }
        }

        return $orphans;
    }

    /**
     * Files that carry FEWER citations than they are expected to — the
     * drift an orphan check cannot see, because a file that cites
     * nothing has no citation to orphan.
     *
     * Reported as `path: expected N, found M`, and a file expected to
     * carry citations that carries none reports `found 0` rather than
     * vanishing.
     *
     * @param  list<string>  $paths
     * @param  array<string, int>  $expected
     * @return list<string>
     */
    public static function shortfallsIn(string $root, array $paths, array $expected): array
    {
        $found = self::scan($root, $paths);
        $shortfalls = [];

        foreach ($expected as $path => $minimum) {
            $count = count($found[$path] ?? []);

            if ($count < $minimum) {
                $shortfalls[] = $path.': expected '.$minimum.', found '.$count;
            }
        }

        sort($shortfalls);

        return $shortfalls;
    }

    /**
     * Files carrying citations that the expectation does not name — a
     * new guarantee-bearing file nobody added to the map, which must be
     * a deliberate diff rather than a silent one.
     *
     * @param  list<string>  $paths
     * @param  array<string, int>  $expected
     * @return list<string>
     */
    public static function unexpectedIn(string $root, array $paths, array $expected): array
    {
        $unexpected = array_keys(array_diff_key(self::scan($root, $paths), $expected));

        sort($unexpected);

        return array_values($unexpected);
    }

    /**
     * Each citation in a file as one normalised line.
     *
     * @return list<string>
     */
    private static function citations(string $contents): array
    {
        $lines = explode("\n", $contents);
        $citations = [];
        $index = 0;

        while ($index < count($lines)) {
            if (! str_contains($lines[$index], self::MARKER)) {
                $index++;

                continue;
            }

            $buffer = [];
            $cursor = $index;

            while ($cursor < count($lines)) {
                $stripped = self::stripMarkers($lines[$cursor]);

                if ($cursor > $index && $stripped === '') {
                    break;
                }

                $buffer[] = $stripped;
                $cursor++;
            }

            $citations[] = (string) preg_replace('/\s+/', ' ', implode(' ', $buffer));
            $index = $cursor;
        }

        return $citations;
    }

    /**
     * A line with its docblock marker and indentation removed, so a
     * wrapped title reads as one string.
     */
    private static function stripMarkers(string $line): string
    {
        return trim((string) preg_replace('/^\s*\*\s?/', '', $line));
    }

    /**
     * @return iterable<string, string>
     */
    private static function phpFiles(string $root, string $prefix): iterable
    {
        $files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
        );

        /** @var SplFileInfo $file */
        foreach ($files as $file) {
            if ($file->isFile() && $file->getExtension() === 'php') {
                $relative = substr($file->getPathname(), strlen($root) + 1);

                yield ($prefix === '' ? $relative : $prefix.'/'.$relative) => $file->getPathname();
            }
        }
    }
}
