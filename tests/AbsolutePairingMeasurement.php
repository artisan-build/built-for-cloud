<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

/**
 * THE WITHDRAWN INSTRUMENT, kept runnable so the numbers that argued
 * against it can be checked instead of taken on trust.
 *
 * `ClaimSurfaceScan` exists because a different instrument was built
 * first and rejected: find absolute words in the guarantee-bearing
 * prose, and require each occurrence to be paired with a citation or a
 * residue note. The argument for rejecting it was a pair of
 * measurements quoted in a docblock, and a measurement quoted in a
 * docblock with no way to re-run it is a citation nobody can follow —
 * which is the defect this whole PR is about, committed by the PR.
 *
 * So the counting rules are here as code, and
 * `tests/ClaimSurfaceTest.php` runs them and pins what they produce.
 *
 * WHAT THE THREE TERMS MEAN, since the argument turns on them:
 *
 *  - A **prose block** is one PHP comment or doc-comment token, or one
 *    blank-line-separated paragraph of Markdown, JavaScript comment
 *    text or Blade comment text. It is the unit an annotation would be
 *    attached to.
 *  - A **citation** is the string {@see CitationScan::MARKER} —
 *    `Pinned by` — occurring in the block. Exactly the convention
 *    `tests/CitationScan.php` already enforces.
 *  - A **residue note** is a block matching {@see RESIDUE}: the words
 *    this package's own residue paragraphs are written with.
 *
 * **WHAT THE NUMBERS DO AND DO NOT SUPPORT.** They say what a gate
 * requiring every unpaired occurrence to be annotated would cost right
 * now, in blocks somebody would have to write an annotation onto. They
 * do NOT say that every instrument in that family is unworkable: a
 * pinned baseline over the same blocks, or a detector that fires only
 * on blocks whose prose CHANGED, would pay a different price and this
 * measurement says nothing about either.
 *
 * The reason the family was set aside is the second fixture here,
 * {@see CORRECTIONS} — five sentences, the ones the PR7 review required
 * PR8 to narrow, before and after. Each pair is a real correction of a
 * real false claim, and the check on them is whether an absolute-word
 * detector can tell the two apart.
 *
 * THE RESIDUE. `RESIDUE` is a list of markers somebody thought of, and
 * a residue paragraph phrased some other way is counted as unpaired
 * here. The block split is a convention, not a parse of English: a
 * docblock stating four things is one block, and annotating it would
 * satisfy this count while leaving three of the four unaddressed. Five
 * corrections is what the PR7 list enumerated, not a sample of some
 * larger population.
 */
final class AbsolutePairingMeasurement
{
    /**
     * The vocabulary the withdrawn instrument looked for, as the brief
     * for it spelled them.
     *
     * @var array<string, string>
     */
    public const array VOCABULARY = [
        'never' => '/\bnever\b/i',
        'cannot' => '/\b(?:cannot|can not|can\'t)\b/i',
        'always' => '/\balways\b/i',
        'only' => '/\bonly\b/i',
        'every path' => '/\bevery\s+path\b/i',
        'in full' => '/\bin full\b/i',
        'forever' => '/\bforever\b/i',
        'complete' => '/\bcomplete(?:ly|ness)?\b/i',
        'from nowhere else' => '/\bfrom nowhere else\b/i',
        'no X can' => '/\bno\b[^.]{0,60}\bcan\b/i',
    ];

    /** What counts as a residue note. */
    public const string RESIDUE = '/\bresidue\b|\bdoes not\b|\bnot enforced\b|\bwhat it does not\b/i';

    /**
     * The five corrections the PR7 security review required, as the
     * false sentence and the sentence that replaced it.
     *
     * Sources: the false halves are quoted in
     * `~/Herd/brain/projects/built-for-cloud/pr7-surviving-absolutes.md`
     * items 1-5; the true halves are the wording that shipped in
     * `dc7afce`.
     *
     * @var list<array{0: string, 1: string}>
     */
    public const array CORRECTIONS = [
        [
            'exactly one event per action',
            'one event per caller-identified action, and only for calls that supply a natural key',
        ],
        [
            'What the schema constrains is that it accompanies a delegated actor',
            'AppActionRecorder can carry an agency only through a delegated AppActionActor',
        ],
        [
            'an immutable dedup ledger, append-only and complete: one row per app-action event, forever',
            'for each successful emission both rows are inserted transactionally, and the package never prunes them',
        ],
        [
            'the only shape this table stores',
            'the column itself enforces only 64 characters and uniqueness',
        ],
        [
            'there is nowhere in this table for prose to go',
            'the schema has no column designated for arbitrary app content or notes',
        ],
    ];

    /**
     * The counts the withdrawn instrument produced, over the RAW
     * contents of each file keyed by path.
     *
     * Raw rather than {@see ClaimSurfaceScan::proseAcross()}'s output,
     * because the block split differs by file type and that output has
     * already flattened the difference away.
     *
     * @param  array<string, string>  $files
     * @return array{blocks: int, absolute: int, paired: int, unpaired: int}
     */
    public static function measure(array $files): array
    {
        $blocks = 0;
        $absolute = 0;
        $paired = 0;

        foreach ($files as $path => $contents) {
            foreach (self::blocksIn($path, $contents) as $block) {
                $blocks++;

                if (self::vocabularyIn($block) === []) {
                    continue;
                }

                $absolute++;

                if (str_contains($block, CitationScan::MARKER) || preg_match(self::RESIDUE, $block) === 1) {
                    $paired++;
                }
            }
        }

        return [
            'blocks' => $blocks,
            'absolute' => $absolute,
            'paired' => $paired,
            'unpaired' => $absolute - $paired,
        ];
    }

    /**
     * The blocks of one file.
     *
     * A PHP file gives up one block per comment or doc-comment TOKEN,
     * so a doc comment is one block however many blank ` *` lines it
     * contains; every other file is split on blank lines. The two rules
     * differ because the unit an annotation would attach to differs: a
     * docblock is annotated once, a Markdown section paragraph by
     * paragraph.
     *
     * @return list<string>
     */
    public static function blocksIn(string $path, string $contents): array
    {
        $extension = strtolower(pathinfo($path, PATHINFO_EXTENSION));

        if ($extension === 'php' && ! str_ends_with(strtolower($path), '.blade.php')) {
            return array_values(array_map(
                static fn (array $token): string => $token[1],
                array_filter(
                    array_filter(token_get_all($contents), is_array(...)),
                    static fn (array $token): bool => in_array($token[0], [T_COMMENT, T_DOC_COMMENT], true),
                ),
            ));
        }

        return array_values(array_filter(
            array_map(trim(...), (array) preg_split('/\n\s*\n/', $contents)),
            static fn (string $block): bool => $block !== '',
        ));
    }

    /**
     * Every file under the surfaces, RAW — the input {@see measure()}
     * takes.
     *
     * @param  list<string>  $surfaces
     * @return array<string, string>
     */
    public static function filesAcross(string $root, array $surfaces): array
    {
        $files = [];

        foreach (ClaimSurfaceScan::proseAcross($root, $surfaces) as $relative => $ignored) {
            $files[$relative] = (string) file_get_contents($root.'/'.$relative);
        }

        return $files;
    }

    /**
     * Which vocabulary entries one block contains.
     *
     * @return list<string>
     */
    public static function vocabularyIn(string $text): array
    {
        return array_values(array_keys(array_filter(
            self::VOCABULARY,
            static fn (string $pattern): bool => preg_match($pattern, $text) === 1,
        )));
    }
}
