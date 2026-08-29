<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 * **A guarantee this package states at three or more places is stated
 * at three or more places on purpose, and the places are written down.**
 * Narrowing such a claim means narrowing every site; this names the
 * sites so a narrowing round has the list instead of a memory of it.
 *
 * WHY IT IS THIS AND NOT A VOCABULARY DETECTOR. The obvious instrument
 * — find absolute words, require each to be paired with a test or a
 * residue note — was built and measured first, and it does not
 * enumerate. Two measurements say so, and they are recorded here
 * because the next person to have the idea deserves them:
 *
 *  - Over the guarantee-bearing surfaces, 389 of 1,209 prose blocks
 *    carry one of *never, cannot, always, only, every path, in full,
 *    forever, complete, from nowhere else, no … can*; 287 of them carry
 *    no citation and no residue note. Requiring a pairing means writing
 *    287 annotations, most of them onto sentences that are already true
 *    and already enforced.
 *  - The decisive one: **this package's own corrections KEEP the
 *    absolute word.** `dedup_key` stores a sha256 digest, never a
 *    caller's string" became "**The emission point stores a sha256
 *    digest in `dedup_key`**, never a caller's string". "there is
 *    nowhere in this table for prose to go" became a sentence about
 *    what the recorder writes. What changed in each was the SUBJECT the
 *    absolute is predicated of, not the vocabulary. A word list cannot
 *    tell the defect from its own fix, and an instrument that cannot is
 *    looking for the wrong thing.
 *
 * So this looks for the shape the defect actually had. The claim that
 * survived three narrowing rounds — "there is nowhere in this table for
 * prose to go" — survived because it was written at three sites (the
 * migration, the contract, the model) and each round corrected the
 * sites someone had open. Restatement is what made the miss possible,
 * and restatement is enumerable.
 *
 * WHAT IT RECOGNISES. Prose only — PHP comment and doc-comment tokens,
 * JavaScript comments, Blade comments, Markdown in full — lower-cased,
 * with emphasis and back-quote characters dropped and runs of
 * non-word characters treated as one break. Over that it slides a
 * window of {@see PHRASE_WORDS} words, keeps the windows containing a
 * word from {@see ABSOLUTES}, and reports those occurring in
 * {@see RESTATEMENT_SITES} or more FILES, each collapsed to its longest
 * form ({@see restatedClaimsIn()} explains the collapse).
 *
 * THE RESIDUE, and it is large. Stated as what is not seen, not as a
 * measure of how much is:
 *
 *  - **A restatement that is not word-for-word is not a restatement
 *    here.** A claim paraphrased at its second site — the same promise
 *    in different words — shares no window and is reported nowhere.
 *    That is the majority of how a claim can be repeated, and closing
 *    it is a semantic comparison, not a text one.
 *  - **Two sites are below the threshold.** A claim written at exactly
 *    two places is outside this pin, and the threshold is a judgement
 *    about how many entries a person will maintain rather than a
 *    property of claims. The two-site case is asserted as unreported in
 *    `tests/ClaimSurfaceTest.php`, so the bound is driven rather than
 *    described.
 *  - **The window length is a threshold too.** A restated claim shorter
 *    than {@see PHRASE_WORDS} words shares no window.
 *  - **Nothing here reads whether a claim is TRUE**, whether it is
 *    absolute, or whether the sites agree about anything beyond the
 *    matched words. Two sites can carry the same ten words inside
 *    sentences that say opposite things.
 *  - **A file outside the surfaces passed in is invisible.** The
 *    surfaces are an argument, and choosing them is the human step —
 *    the same residue `tests/CitationScan.php` names for the same
 *    reason. The migration that carried the surviving claim is inside
 *    them because of it.
 */
final class ClaimSurfaceScan
{
    /**
     * The window, in words. Long enough that an ordinary turn of
     * phrase is not a "claim" and short enough to survive a wrapped
     * line; it is a chosen number, and the residue above says so.
     */
    public const int PHRASE_WORDS = 10;

    /**
     * How many distinct files a phrase must occur in before it is
     * reported. Three, because three is where the defect lived: a claim
     * at three sites is one a correcting round can half-fix.
     */
    public const int RESTATEMENT_SITES = 3;

    /**
     * The vocabulary a window must contain to count as claim-bearing.
     *
     * This is the same word list the pairing instrument was built on,
     * used for the one job it can do: narrowing 31,000 windows to the
     * ones that assert something. It is NOT used to decide whether a
     * sentence is true, and the class docblock says why it could not be.
     *
     * @var list<string>
     */
    public const array ABSOLUTES = [
        'never', 'cannot', 'always', 'only', 'forever', 'immutable',
        'nowhere', 'complete', 'completely', 'completeness', 'every',
        'no', 'none',
    ];

    /**
     * The file extensions prose travels in here, matched
     * case-insensitively for the reason `CitationScan` matches its own
     * that way: a `.PHP` or a `.MD` is not a way past a walk.
     *
     * @var list<string>
     */
    public const array PROSE_EXTENSIONS = ['md', 'php', 'inc', 'js'];

    /**
     * Restated claim phrases, as phrase => the files carrying it.
     *
     * REPORTED AS THE WHOLE RESTATED RUN. A restated sentence produces
     * one window per starting word, so a twenty-word claim at three
     * sites arrives as eleven overlapping windows carrying identical
     * site lists. Reporting all eleven would say one thing eleven times
     * and make an inventory nobody can read, so the chain is walked
     * back to its start and reported once, as the full run of words the
     * sites share.
     *
     * The chain is followed by SITE LIST, not by text: two claims that
     * happen to overlap have different site lists and stay apart, and a
     * run that genuinely branches — the same opening continued two
     * different ways at two different site sets — is reported as the
     * two runs it is.
     *
     * @param  array<string, string>  $prose  path => prose
     * @return array<string, list<string>>
     */
    public static function restatedClaimsIn(array $prose): array
    {
        $windows = [];

        foreach ($prose as $path => $contents) {
            foreach (self::claimWindowsIn($contents) as $window) {
                $windows[$window][$path] = true;
            }
        }

        $repeated = [];

        foreach ($windows as $window => $sites) {
            if (count($sites) < self::RESTATEMENT_SITES) {
                continue;
            }

            $paths = array_keys($sites);
            sort($paths);
            $repeated[$window] = $paths;
        }

        $runs = [];

        foreach ($repeated as $window => $sites) {
            $tail = implode(' ', array_slice(explode(' ', $window), 1)).' ';

            foreach ($repeated as $other => $otherSites) {
                if ($other !== $window && $otherSites === $sites && str_starts_with($other, $tail)) {
                    continue 2;
                }
            }

            $runs[self::runEndingAt($window, $sites, $repeated)] = $sites;
        }

        ksort($runs);

        return $runs;
    }

    /**
     * One window walked back to the start of its run: every window
     * carrying the same site list that ends where this one begins,
     * prepended a word at a time.
     *
     * The walk stops when the run has no further predecessor and, as a
     * guard rather than an expectation, when a phrase repeats — a
     * document whose words cycle (`a b a b a b`) can otherwise extend a
     * run without ever reaching a start.
     *
     * @param  list<string>  $sites
     * @param  array<string, list<string>>  $repeated
     */
    private static function runEndingAt(string $window, array $sites, array $repeated): string
    {
        $phrase = $window;
        $seen = [$window => true];

        while (true) {
            $head = ' '.implode(' ', array_slice(explode(' ', $phrase), 0, self::PHRASE_WORDS - 1));
            $previous = null;

            foreach ($repeated as $other => $otherSites) {
                if ($otherSites === $sites && str_ends_with($other, $head)) {
                    $previous = $other;

                    break;
                }
            }

            if ($previous === null) {
                return $phrase;
            }

            $phrase = explode(' ', $previous)[0].' '.$phrase;

            if (isset($seen[$phrase])) {
                return $phrase;
            }

            $seen[$phrase] = true;
        }
    }

    /**
     * Every claim-bearing window in one document, de-duplicated: a file
     * that says the same thing twice is one SITE, because the sites are
     * what a narrowing round has to visit.
     *
     * @return list<string>
     */
    public static function claimWindowsIn(string $contents): array
    {
        $words = self::words($contents);
        $windows = [];

        for ($start = 0; $start + self::PHRASE_WORDS <= count($words); $start++) {
            $window = array_slice($words, $start, self::PHRASE_WORDS);

            if (array_intersect($window, self::ABSOLUTES) === []) {
                continue;
            }

            $windows[implode(' ', $window)] = true;
        }

        return array_keys($windows);
    }

    /**
     * Prose normalised to a word list: lower-cased, with emphasis and
     * back-quote characters dropped so `**never**` and `never` are one
     * word, and every other run of non-word characters read as one
     * break so a line wrap cannot split a phrase.
     *
     * @return list<string>
     */
    public static function words(string $contents): array
    {
        $flattened = str_replace(['**', '`', '*', '_', '#'], ' ', strtolower($contents));

        return preg_split('/[^a-z0-9\'-]+/', $flattened, -1, PREG_SPLIT_NO_EMPTY) ?: [];
    }

    /**
     * The PROSE of one file: comments for code, everything for
     * Markdown.
     *
     * **Code is excluded deliberately, and it is not tidiness.** An
     * identifier repeated across four controllers is not a restated
     * claim, and a walk that counted it would bury the sentences this
     * exists to find under `public function actor request auditactor`.
     *
     * Recognition is by extension: `.md` is prose entire; `.js` and
     * Blade files give up their comment syntax by regex; every other
     * PHP file is tokenised, so a `//` inside a string literal is not
     * mistaken for a comment. A file whose extension is none of these
     * yields nothing.
     */
    public static function proseIn(string $path, string $contents): string
    {
        $extension = strtolower(pathinfo($path, PATHINFO_EXTENSION));

        if ($extension === 'md') {
            return $contents;
        }

        if ($extension === 'js') {
            preg_match_all('#/\*.*?\*/|//[^\n]*#s', $contents, $matches);

            return implode("\n\n", $matches[0]);
        }

        if (str_ends_with(strtolower($path), '.blade.php')) {
            preg_match_all('/\{\{--.*?--\}\}|<!--.*?-->/s', $contents, $matches);

            return implode("\n\n", $matches[0]);
        }

        if ($extension !== 'php' && $extension !== 'inc') {
            return '';
        }

        return implode("\n\n", array_map(
            static fn (array $token): string => $token[1],
            array_filter(
                array_filter(token_get_all($contents), is_array(...)),
                static fn (array $token): bool => in_array($token[0], [T_COMMENT, T_DOC_COMMENT], true),
            ),
        ));
    }

    /**
     * The prose of every file under the given surfaces, keyed by path
     * relative to the root — the one method here that touches the disk,
     * so every other method can be driven over a fixture the way
     * `tests/ContractScan.php`'s can.
     *
     * @param  list<string>  $surfaces
     * @return array<string, string>
     */
    public static function proseAcross(string $root, array $surfaces): array
    {
        $prose = [];

        foreach ($surfaces as $surface) {
            $target = $root.'/'.$surface;

            foreach (is_dir($target) ? self::filesIn($target, $surface) : [$surface => $target] as $relative => $file) {
                $prose[$relative] = self::proseIn($relative, (string) file_get_contents($file));
            }
        }

        ksort($prose);

        return $prose;
    }

    /**
     * @return iterable<string, string>
     */
    private static function filesIn(string $root, string $prefix): iterable
    {
        $files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
        );

        /** @var SplFileInfo $file */
        foreach ($files as $file) {
            if ($file->isFile() && in_array(strtolower($file->getExtension()), self::PROSE_EXTENSIONS, true)) {
                yield $prefix.'/'.substr($file->getPathname(), strlen($root) + 1) => $file->getPathname();
            }
        }
    }
}
