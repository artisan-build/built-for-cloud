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
 * {@see CORRECTIONS} — five phrases the PR7 review required PR8 to
 * narrow, with what replaced each. The check on them is what an
 * absolute-word detector does with the two halves.
 *
 * WHAT THESE COUNTS DO NOT COVER. Each entry names a CLASS of thing
 * and nothing else:
 *
 *  - **A residue paragraph phrased outside {@see RESIDUE}**, which is
 *    counted as unpaired.
 *  - **A block that states more than one thing.** The split is a
 *    convention, not a parse of English, so annotating such a block
 *    satisfies the count without addressing what else it says.
 *  - **Corrections outside the enumerated PR7 list**, which is not a
 *    sample of a larger population.
 *  - **The rest of the paragraph each correction rewrote.**
 *    {@see CORRECTIONS} stores one chosen phrase from it and says what
 *    choosing costs.
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
     * false phrase and the phrase that replaced it AT ONE NAMED SITE.
     *
     * **EVERY HALF OF THIS WAS WRONG BEFORE, AND THAT MATTERS MORE
     * THAN THE FIXTURE DOES.** The first version of this table was
     * hand-authored from the review's *proposed* wording — the
     * "smallest accepted wording" the PR7 list suggests — rather than
     * from what `dc7afce` actually shipped. Not one of the five `after`
     * halves occurred in the merged tree. A fixture standing in for a
     * history that did not happen is a weaker control than it looks,
     * which is this PR's own subject committed inside this PR for the
     * second time.
     *
     * So both halves are now CHECKED, by
     * `tests/ClaimSurfaceTest.php` — "shows what the vocabulary does
     * with the five corrections this build had to make":
     *
     *  - the `after` phrase occurs verbatim in the named file as it
     *    stands today, and
     *  - the `before` phrase occurs nowhere in it, which is what makes
     *    "this was corrected" a fact the suite holds rather than a
     *    claim in a comment.
     *
     * WHAT IS STILL NOT CHECKED HERE, and it is the half a test in this
     * repository cannot reach: that each `before` was the wording at
     * that site BEFORE the correction. Those come from the enumerated
     * review list in
     * `~/Herd/brain/projects/built-for-cloud/pr7-surviving-absolutes.md`
     * items 1-5, verified by hand against the tree at `a53deac`, and
     * brain is not readable from here. A reader wanting that half has
     * to run `git grep -F` at `a53deac`.
     *
     * **THE SPAN IS A JUDGEMENT.** Each correction rewrote a paragraph;
     * what is stored is one phrase from it, chosen to be the phrase the
     * PR7 list itself quotes as the offence. A different span from the
     * same paragraph would give different vocabulary counts, so the
     * numbers below are a property of these five spans, not of the five
     * corrections in the abstract.
     *
     * @var list<array{before: string, after: string, file: string}>
     */
    public const array CORRECTIONS = [
        // Item 1. The dedup guarantee, unconditional while the recorder
        // explicitly permits no deduplication without a natural key.
        [
            'before' => 'exactly one event per action',
            'after' => 'one event per CALLER-IDENTIFIED action',
            'file' => 'src/Audit/AppActionOutboxEntry.php',
        ],
        // Item 2. Table-wide agency enforcement attributed to a schema
        // that has no such constraint.
        [
            'before' => 'What the schema constrains',
            'after' => 'can carry an agency only through a delegated',
            'file' => 'src/Audit/AppActionEvent.php',
        ],
        // Item 3. The absolute history claim.
        [
            'before' => 'append-only and complete',
            'after' => 'the package prunes none of them',
            'file' => 'src/Audit/AppActionOutboxEntry.php',
        ],
        // Item 4. The digest shape, claimed of the table.
        [
            'before' => 'the only shape this table stores',
            'after' => 'The TABLE enforces only 64 characters and uniqueness',
            'file' => 'src/Audit/AppActionOutboxEntry.php',
        ],
        // Item 5. The structural no-free-text claim — the one that
        // survived three narrowing rounds at three sites.
        [
            'before' => 'there is nowhere in this table for prose to go',
            'after' => 'No column is designated for arbitrary app content.',
            'file' => 'docs/http-contract.md',
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
