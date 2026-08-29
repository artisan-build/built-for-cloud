<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\Audit\AppActionEvent;
use ArtisanBuild\BuiltForCloud\Audit\AppActionRecorder;
use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 * The RETENTION DECLARATION, made checkable as far as an enumeration
 * can: **no file under `src/` that names the app-action stream also uses
 * one of the ENUMERATED deletion spellings** (Console PRD D17's
 * "declared retention").
 *
 * WHY A SCAN AND NOT A SENTENCE. "App-action events are never pruned" is
 * a claim about ABSENCE, and this build has three separate findings from
 * instruments that could not see a missing thing. A behavioural test can
 * show that {@see AppActionEvent} refuses a delete today; it cannot show
 * that no OTHER file deletes rows some other way — a scheduled command,
 * a `Prunable` trait, a `destroy()` call. An enumeration over `src/`
 * can, for the spellings it enumerates, and this is it.
 *
 * **THE NAME OF THE CLAIM IS "THESE SPELLINGS", NOT "NO PRUNING PATH",
 * and an earlier revision of the test that drives this said the wider
 * thing.** {@see PRUNE_NEEDLES} is a fixed textual list; what the walk
 * establishes is that none of those strings appears in a file that also
 * names the stream. That is a tripwire against the ordinary
 * reintroduction, which is what it is for. It is not a proof that no
 * deletion path exists, and the test title, the citations and this
 * docblock all now say the narrower thing.
 *
 * THE RULE: a file is reported when it names the stream — a model class
 * or its table — AND uses one of {@see PRUNE_NEEDLES}. Either alone is
 * innocent: the package deletes plenty of other things, and the model
 * and the doc name the stream constantly. Comments and docblocks are
 * stripped first, so the model's own prose about never deleting does not
 * make it a deleter.
 *
 * WHAT IT DOES NOT COVER, named because an unlisted gap reads as a
 * covered one:
 *
 *  - **A deletion spelling this list does not know.** `::destroy(`,
 *    `->deleteQuietly(`, `->pruneAll(` and the `Prunable` traits were
 *    all ABSENT from an earlier revision, which is the argument for
 *    naming this limit rather than trusting the list: real deletion
 *    paths sat outside a walk whose test claimed there were none. A raw
 *    `DB::statement('DELETE FROM ...')`, a table name assembled at
 *    runtime, and a `delete()` reached through a variable are still
 *    outside it, and no addition to a textual list closes that class.
 *  - **Precision, in the other direction.** The rule is FILE-LEVEL
 *    co-occurrence, so a file that names this stream while pruning
 *    something ELSE is a FALSE POSITIVE. That is not hypothetical: the
 *    one emitter, `ConsoleEnter`, prunes expired assertion burns, and it
 *    stays out of this walk only because it happens to reach the stream
 *    through {@see AppActionRecorder}
 *    and never names a model — a type hint added tomorrow would turn it
 *    red for a deletion that has nothing to do with this stream. That is
 *    a known cost of a textual walk, it is NOT enforced by anything, and
 *    it is deliberately not answered with a file exemption: an exemption
 *    on the sole emitter is precisely the blind spot this scan exists to
 *    prevent. Whoever meets that red is meant to read this paragraph and
 *    decide, not to add a name to an allowlist.
 *  - **Anything outside the scanned root.** The migration's own `down()`
 *    calls `Schema::dropIfExists()` on these tables, and that is
 *    correct: dropping a table is schema management by an operator
 *    running migrations, not the package pruning history behind their
 *    back. `database/` is deliberately not scanned, and this is what
 *    that exclusion means rather than something the scan quietly skips.
 *  - **The consuming APP**, which owns its own database and can delete
 *    whatever it likes. The declaration is about what THIS PACKAGE
 *    does, and it cannot be about anything else.
 *
 * Every enumerated spelling is driven over a fixture carrying it, so the
 * walk is proven able to fail on each one rather than merely reporting
 * clean.
 *   Pinned by `tests/AppActionAuditTest.php` — "finds no enumerated
 *   deletion spelling against the app-action stream anywhere in src" and
 *   "names every enumerated deletion spelling when the walk meets one".
 */
final class AppActionRetentionScan
{
    /**
     * Everything that names the app-action stream: the model class as it
     * is used, and the table as the schema names it.
     *
     * @var list<string>
     */
    public const array STREAM_NEEDLES = [
        'AppActionEvent',
        'AppActionOutboxEntry',
        'bfc_app_action_events',
        'bfc_app_action_outbox',
    ];

    /**
     * The deletion spellings this walk knows. A file is REPORTED when it
     * contains one of these AND names the stream.
     *
     * It is a fixed textual list and the claim is worded to match: what
     * the walk establishes is that none of THESE appears, not that no
     * deletion path exists. `Prunable` and `MassPrunable` are trait
     * names rather than call sites, because a model that uses either has
     * a pruning path whether or not it spells `prune(` anywhere —
     * `model:prune` calls it. Ordered so a reader can see the four
     * families: ordinary deletes, quiet deletes (which fire no model
     * events and so slip past the append-only guards), the Laravel
     * pruning machinery, and schema drops.
     *
     * @var list<string>
     */
    public const array PRUNE_NEEDLES = [
        '->delete(',
        '::destroy(',
        '->deleteQuietly(',
        '->forceDelete(',
        '->forceDeleteQuietly(',
        '->truncate(',
        '::truncate(',
        '->prune(',
        '::prune(',
        '->pruneAll(',
        '::pruneAll(',
        'MassPrunable',
        'Prunable',
        '->dropIfExists(',
        '::dropIfExists(',
        '::drop(',
    ];

    /**
     * The enumerated deletion spellings a file uses, but only when it
     * also names the stream — that combination is what the walk reports.
     *
     * @return list<string>
     */
    public static function pruningVerbsIn(string $contents): array
    {
        $code = self::withoutComments($contents);

        if (self::matches($code, self::STREAM_NEEDLES) === []) {
            return [];
        }

        return self::matches($code, self::PRUNE_NEEDLES);
    }

    /**
     * Every file under the root that names the app-action stream AND
     * uses an enumerated deletion spelling, keyed by relative path and
     * NAMING the spellings it uses.
     *
     * @return array<string, list<string>>
     */
    public static function scan(string $root): array
    {
        $found = [];

        foreach (self::phpFiles($root) as $relativePath => $file) {
            $hits = self::pruningVerbsIn((string) file_get_contents($file->getPathname()));

            if ($hits !== []) {
                $found[$relativePath] = $hits;
            }
        }

        ksort($found);

        return $found;
    }

    /**
     * Every file under the root that names the stream at all — the floor
     * that stops a scanner which matched NOTHING from reporting "clean".
     * A scan whose needles had drifted would find no pruning paths and no
     * references either, and the second is what makes the first readable.
     *
     * @return list<string>
     */
    public static function referencesIn(string $root): array
    {
        $found = [];

        foreach (self::phpFiles($root) as $relativePath => $file) {
            $code = self::withoutComments((string) file_get_contents($file->getPathname()));

            if (self::matches($code, self::STREAM_NEEDLES) !== []) {
                $found[] = $relativePath;
            }
        }

        sort($found);

        return $found;
    }

    /**
     * @param  list<string>  $needles
     * @return list<string>
     */
    private static function matches(string $code, array $needles): array
    {
        return array_values(array_filter(
            $needles,
            static fn (string $needle): bool => str_contains($code, $needle),
        ));
    }

    private static function withoutComments(string $contents): string
    {
        return implode('', array_map(
            static fn (array|string $token): string => is_string($token)
                ? $token
                : (in_array($token[0], [T_COMMENT, T_DOC_COMMENT], true) ? ' ' : $token[1]),
            token_get_all($contents),
        ));
    }

    /**
     * @return iterable<string, SplFileInfo>
     */
    private static function phpFiles(string $root): iterable
    {
        $files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
        );

        /** @var SplFileInfo $file */
        foreach ($files as $file) {
            if ($file->isFile() && $file->getExtension() === 'php') {
                yield substr($file->getPathname(), strlen($root) + 1) => $file;
            }
        }
    }
}
