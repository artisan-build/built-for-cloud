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
 * The RETENTION DECLARATION, made checkable: **no file under `src/` that
 * names the app-action stream also carries a pruning verb** (Console PRD
 * D17's "declared retention").
 *
 * WHY A SCAN AND NOT A SENTENCE. "App-action events are never pruned" is
 * a claim about ABSENCE, and this build has three separate findings from
 * instruments that could not see a missing thing. A behavioural test can
 * show that {@see AppActionEvent} refuses a delete today; it cannot show
 * that no OTHER file deletes rows some other way — a `DB::table(...)`
 * sweep, a scheduled command, a `truncate()` on a differently obtained
 * builder. An enumeration over `src/` can, and this is it.
 *
 * THE RULE: a file is a pruning path when it names the stream — the model
 * class or its table — AND uses one of {@see PRUNE_NEEDLES}. Either alone
 * is innocent: the package deletes plenty of other things, and the model
 * and the doc name the stream constantly. Comments and docblocks are
 * stripped first, so the model's own prose about never deleting does not
 * make it a deleter.
 *
 * WHAT IT DOES NOT COVER, named because an unlisted gap reads as a
 * covered one:
 *
 *  - **A pruning verb this list does not know.** It is a FIXED TEXTUAL
 *    LIST, so a raw `DB::statement('DELETE FROM ...')`, a `delete()`
 *    reached through a variable, or a driver-level sweep is not caught.
 *    Like the session-writer scan, this catches the ordinary
 *    reintroduction, not somebody deliberately hiding one.
 *  - **A table name assembled at runtime**, which matches no literal.
 *  - **Anything outside the scanned root.** The migration's own `down()`
 *    calls `Schema::dropIfExists()` on this table, and that is correct:
 *    dropping a table is schema management by an operator running
 *    migrations, not the package pruning history behind their back.
 *    `database/` is deliberately not scanned, and this is what that
 *    exclusion means rather than something the scan quietly skips.
 *  - **Precision, in the other direction.** The rule is FILE-LEVEL
 *    co-occurrence, so a file that names this stream while pruning
 *    something else entirely is a FALSE POSITIVE, not a miss. That is
 *    the safe direction and it is not free: `ConsoleEnter` prunes
 *    expired assertion burns and is the one emitter, so it is kept off
 *    the stream's models — it reaches them only through
 *    {@see AppActionRecorder} — rather
 *    than being exempted, because an exemption on the emitter is
 *    exactly the hole this scan exists to watch.
 *  - **The consuming APP**, which owns its own database and can delete
 *    whatever it likes. The declaration is about what THIS PACKAGE
 *    does, and it cannot be about anything else.
 *
 * It is driven over a fixture carrying the offence, so it is proven able
 * to fail rather than merely reporting clean.
 *   Pinned by `tests/AppActionAuditTest.php` — "ships no pruning path for
 *   the app-action stream anywhere in src" and "names a pruning path when
 *   the walk meets one".
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
     * Row-removal verbs. A file is a PRUNING PATH when it contains one of
     * these AND names the stream.
     *
     * @var list<string>
     */
    public const array PRUNE_NEEDLES = [
        '->delete(',
        '->forceDelete(',
        '->truncate(',
        '::truncate(',
        '->prune(',
        '::prune(',
        '->dropIfExists(',
        '::dropIfExists(',
        '::drop(',
    ];

    /**
     * The pruning verbs a file uses, but only when it also names the
     * stream — that combination is what makes it a pruning path.
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
     * Every file under the root that can prune the app-action stream,
     * keyed by relative path and NAMING the verbs it uses.
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
