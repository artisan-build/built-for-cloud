<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 * **WHAT THIS RECOGNISES: a run of ten or more words, containing a word
 * from {@see ABSOLUTES}, that occurs word-for-word in three or more of
 * the files it is given.** Each such run is reported with the files
 * carrying it. Narrowing a claim at some of its sites and not the
 * others changes that list, so the change is visible in the diff
 * instead of resting on somebody's memory of where else the sentence
 * was written.
 *
 * It exists because the surviving example of this build's dominant
 * defect had exactly that shape: "there is nowhere in this table for
 * prose to go" was written at the events migration, the contract and
 * the model, and the round that corrected two of them left the third
 * word for word.
 *
 * WHY IT IS THIS AND NOT A VOCABULARY DETECTOR. The obvious instrument
 * — find absolute words, require each occurrence to be paired with a
 * citation or a residue note — was built and measured before this one.
 * The measurement is runnable rather than quoted:
 * {@see AbsolutePairingMeasurement}, pinned by
 * `tests/ClaimSurfaceTest.php`. Two results, stated at the size of
 * their evidence:
 *
 *  - **What the counts reject is a GATE.** Over the guarantee-bearing
 *    surfaces the withdrawn instrument finds 418 of 1,276 prose blocks
 *    carrying its vocabulary and 305 of those carrying neither a
 *    citation nor a residue note, so requiring every occurrence to be
 *    paired means writing 305 annotations, most onto sentences already
 *    true and already enforced. **That is an argument against a gate
 *    and against nothing else** — a pinned baseline over the same
 *    blocks, or a detector firing only where prose CHANGED, would cost
 *    something different and these counts say nothing about either.
 *  - **The reason the family was set aside is the five corrections
 *    themselves.** Of the five sentences the PR7 review required PR8 to
 *    narrow, the vocabulary finds **two**; and for both of those it
 *    finds the replacement too, because PR8 kept the absolute word and
 *    changed the SUBJECT it was predicated of. So on this build's own
 *    corrections the detector misses three outright and cannot
 *    distinguish the other two from their own fixes.
 *
 * That is what argued for looking at restatement instead. It is a
 * judgement from five corrections, not a proof about the family, and
 * anyone with a better instrument in it should build it.
 *
 * **WHY NOTHING IN `docs/` OR `src/` CITES THIS.** `AppActionReadTransportScan`
 * and the version-pair check both added `Pinned by` lines to the
 * contract, and this one deliberately did not. Those two hold sentences
 * the contract makes to consumers; this holds claims made in DOCBLOCKS,
 * which are not contract surface, and writing a contract sentence about
 * an internal tripwire would promise consumers something about our
 * tooling. This docblock is the right home for it. (Ed's ruling, rework
 * round 1 — recorded so the omission is not later "fixed".)
 *
 * WHAT IT DOES NOT RECOGNISE. Each entry names a CLASS of thing and
 * then says what follows from it — those are the two halves a residue
 * needs. What it must not carry is the falsifiable third: a count, a
 * quantifier, or a fact about this codebase that can go stale. **Strip
 * what can go stale; keep what tells the reader what the gap means.**
 * And check each entry against what this actually does: a bullet can
 * be quantifier-free and still name a limitation that is not one, or
 * one that is narrower than it sounds. Each below is driven in
 * `tests/ClaimSurfaceTest.php`.
 *
 *  - **A claim whose SUBJECT is rewritten at every site, where the
 *    rewritten words fall outside the absolute-bearing region of the
 *    run.** Such a rewrite leaves the map byte-identical, so the suite
 *    stays green through it — and this is the correction shape the
 *    class was built for, which makes it the sharpest thing it misses.
 *    A narrowing round cannot lean on this map for that case.
 *  - **A restatement that is not word-for-word.** The same promise in
 *    different words shares no window, so a claim paraphrased at its
 *    second site is reported nowhere and its sites are not listed.
 *  - **A claim at fewer sites than {@see RESTATEMENT_SITES}**, and **a
 *    claim shorter than {@see PHRASE_WORDS} words.** Both are outside
 *    the map entirely, so a two-site guarantee narrowed at one of them
 *    reds nothing.
 *  - **A cycle producing one distinct window is reported; one
 *    producing several distinct windows is reported nowhere.** Where
 *    there are several, each continues another with the same site
 *    list, so none is maximal and the run vanishes from the map — a
 *    claim written that way is unpinned rather than pinned short. The
 *    axis is the number of DISTINCT WINDOWS, not the length of the run
 *    or the period of the cycle: exactly {@see PHRASE_WORDS} words of a
 *    two-word cycle is one window and is reported, and the same cycle
 *    two words longer is two windows and is not. Both are driven.
 *  - **Whether a claim is TRUE.** Nothing here reads a claim, only
 *    where its words recur, so an entry in the map is evidence about
 *    duplication and about nothing else.
 *  - **A file outside the surfaces it is handed.** Choosing them is the
 *    human step — the residue `tests/CitationScan.php` names for the
 *    same reason — so a guarantee written somewhere nobody added is
 *    invisible here however many times it is restated.
 *
 * The thresholds are numbers somebody chose and the vocabulary is a
 * list somebody wrote; a claim written just outside either is not on
 * it.
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
     * REPORTED AS THE ABSOLUTE-BEARING REGION OF THE RUN, WHICH IS NOT
     * THE WHOLE SENTENCE. A restated sentence produces one window per
     * starting word, so a twenty-word claim at three sites arrives as
     * eleven overlapping windows carrying identical site lists;
     * reporting all eleven would say one thing eleven times, so the
     * chain is walked back and reported once.
     *
     * **But the chain is built only from windows that contain a word
     * from {@see ABSOLUTES}, so it stops wherever ten consecutive words
     * carry none — and the words beyond that stop are not in the
     * reported phrase and are not pinned.** An earlier revision of this
     * paragraph said "the full run of words the sites share", which is
     * more than the walk does. Two consequences, both fixtured in
     * `tests/ClaimSurfaceTest.php` — "reports only the absolute-bearing
     * region of a restated sentence, so words beyond it are not pinned":
     *
     *  - A restated sentence is clipped at both ends and across any
     *    interior stretch of ten words with no absolute in it.
     *  - **A subject changed at every site, where the changed words fall
     *    outside that region, leaves this map byte-identical.** That is
     *    the correction shape this class was built for, so it is the
     *    sharpest thing it does not see. Driven over the reviewer's
     *    input in `tests/ClaimSurfaceTest.php`.
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
     * One window walked back: each window carrying the same site list
     * that ends where the current phrase begins, prepended a word at a
     * time, until no unused predecessor is left.
     *
     * **`$seen` HOLDS WINDOWS, NOT THE GROWING PHRASE, AND THAT IS WHAT
     * MAKES THIS TERMINATE.** The first revision recorded the phrase,
     * which gains a word every pass and is therefore never one it has
     * recorded before — so the guard could not fire, and three files
     * each holding ten repetitions of one absolute word ran until the
     * process died. A hanging test is worse than a failing one: CI has
     * no signal to give. Windows come from a finite set, so the loop
     * cannot run more times than that set has members.
     *
     * The consequence, which is a real trade and not a technicality: a
     * window that genuinely recurs later in the same run is used once,
     * so a run whose words cycle is reported CLIPPED at the repeat
     * rather than followed round it. That is pinned in
     * `tests/ClaimSurfaceTest.php` — "walks a run of repeated words to a
     * finite phrase instead of running forever".
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
                if ($otherSites === $sites && ! isset($seen[$other]) && str_ends_with($other, $head)) {
                    $previous = $other;

                    break;
                }
            }

            if ($previous === null) {
                return $phrase;
            }

            $seen[$previous] = true;
            $phrase = explode(' ', $previous)[0].' '.$phrase;
        }
    }

    /**
     * The claim-bearing windows this parse finds in one document,
     * de-duplicated: a file that says the same thing twice is one SITE,
     * because the sites are what a narrowing round has to visit.
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
