<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Console\ConsoleGuard;
use ArtisanBuild\BuiltForCloud\Console\ConsoleSession;
use ArtisanBuild\BuiltForCloud\Console\ConsoleSessionClock;
use ArtisanBuild\BuiltForCloud\Tests\DelegatedSessionWriterScan;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\SurfaceWithExtraPublicMethod;
use ArtisanBuild\BuiltForCloud\Tests\PublicSurfaceScan;

/**
 * THE PACKAGE-WIDE MINTING GUARANTEE, expressed as an enumeration.
 *
 * "Only `redeem()` mints a delegated session through this package" used
 * to be cited by three tests that could not express it — a fixed list of
 * absent method names, a single class with no writer, and a tampered
 * token. A differently named writer would have left all three green
 * while falsifying the claim, so the citation looked checkable and was
 * not.
 *
 * These enumerate `src/` instead, the way the key-custody and repoint
 * scans do, and the walk is driven over a fixture so it is proven able
 * to fail.
 */
it('has exactly one file in src/ that can write a delegated session key', function (): void {
    $root = dirname(__DIR__).'/src';

    expect(DelegatedSessionWriterScan::countPhpFiles($root))->toBeGreaterThan(100)
        ->and(DelegatedSessionWriterScan::scanWriters($root))
        ->toBe([DelegatedSessionWriterScan::PERMITTED_WRITER => ['->put(']]);
});

it('has exactly four files in src/ that name a delegated session key at all', function (): void {
    // Readers count too: a second place deciding what a delegated claim
    // means is the divergence hazard this package has already deleted
    // twice (DelegatedClaims::isAdmin(), DelegatedClaims::fromAssertion()).
    expect(array_keys(DelegatedSessionWriterScan::scanReferences(dirname(__DIR__).'/src')))
        ->toBe([
            // The one writer.
            'Console/ConsoleGuard.php',
            // The contract: the key definitions and the atomic reader.
            'Console/ConsoleSession.php',
            // D7's clock, which reads the issued-at marker and nothing else.
            'Console/ConsoleSessionClock.php',
            // The eviction listener clears every key but interprets none.
            'Listeners/EvictConsolePrincipal.php',
        ]);
});

it('keeps the one writer unreachable from outside the guard', function (): void {
    // The enumeration says ConsoleGuard is the only file that CAN write.
    // This says the method that does it is not callable from anywhere
    // else, so "only redeem() mints" is about reachability and not just
    // about which file the code sits in.
    $writer = new ReflectionMethod(ConsoleGuard::class, 'beginSession');

    expect($writer->isPrivate())->toBeTrue();
});

it('collects and names a differently-named writer when the walk meets one', function (): void {
    // The claim is about ABSENCE, so the walk has to be able to fail —
    // and it has to fail on the case the old citation missed: a writer
    // with a name nobody listed.
    $root = sys_get_temp_dir().'/bfc-session-writer-'.bin2hex(random_bytes(6));

    mkdir($root.'/nested', 0700, true);

    $files = [
        // A new class nobody named, reaching the keys through the
        // constants. This is exactly what the fixed-list citation missed.
        $root.'/nested/SomeOtherWriter.php' => "<?php\n\nfinal class SomeOtherWriter\n{\n    public function begin(\$session, \$claims): void\n    {\n        \$session->put(ConsoleSession::ROLE, \$claims->role->value);\n    }\n}\n",
        // The same thing spelled with the literal key.
        $root.'/LiteralWriter.php' => "<?php\n\nfunction begin(\$session): void { \$session->put('bfc_console.display_name', 'Jane'); }\n",
        // A writer that iterates the published key set.
        $root.'/BulkWriter.php' => "<?php\n\nfunction wipe(\$session, \$values): void { foreach (ConsoleSession::keys() as \$k) { \$session->put(\$k, \$values[\$k]); } }\n",
        // A READER. Names the keys, writes nothing — not an offence.
        $root.'/Reader.php' => "<?php\n\nfunction role(\$session): mixed { return \$session->get(ConsoleSession::ROLE); }\n",
        // Prose that names a key, which is the shape of every docblock
        // in src/ that explains the contract — must NOT count.
        $root.'/TalksAboutIt.php' => "<?php\n\n/** Writes bfc_console.role via ->put() only inside the guard. */\nfunction fine(): bool { return true; }\n",
        // A session write that has nothing to do with the Console.
        $root.'/UnrelatedPut.php' => "<?php\n\nfunction remember(\$cache): void { \$cache->put('some.other.key', 1); }\n",
        // Not PHP: ignored, so a .txt full of offences cannot make this
        // pass for the wrong reason.
        $root.'/notes.txt' => "\$session->put(ConsoleSession::ROLE, 'admin');",
    ];

    foreach ($files as $path => $contents) {
        file_put_contents($path, $contents);
    }

    try {
        expect(DelegatedSessionWriterScan::countPhpFiles($root))->toBe(6)
            ->and(DelegatedSessionWriterScan::scanWriters($root))->toBe([
                'BulkWriter.php' => ['->put('],
                'LiteralWriter.php' => ['->put('],
                'nested/SomeOtherWriter.php' => ['->put('],
            ]);

        // The reader is named by the reference scan and by neither
        // writer assertion — the two questions really are different.
        expect(array_keys(DelegatedSessionWriterScan::scanReferences($root)))
            ->toContain('Reader.php')
            ->not->toContain('TalksAboutIt.php')
            ->not->toContain('UnrelatedPut.php');
    } finally {
        array_map(unlink(...), array_keys($files));
        rmdir($root.'/nested');
        rmdir($root);
    }
});

it('names every session mutator it knows about, and none of them in prose', function (string $code, array $expected): void {
    expect(DelegatedSessionWriterScan::writersIn('<?php '.$code))->toBe($expected);
})->with([
    'put with a constant' => ['$s->put(ConsoleSession::ROLE, "admin");', ['->put(']],
    'put with a literal' => ['$s->put("bfc_console.role", "admin");', ['->put(']],
    'replace' => ['$s->replace(["bfc_console.role" => "admin"]);', ['->replace(']],
    'merge' => ['$s->merge(["bfc_console.display_name" => "Jane"]);', ['->merge(']],
    'flash' => ['$s->flash("bfc_console.role", "admin");', ['->flash(']],
    'a read is not a write' => ['$r = $s->get(ConsoleSession::ROLE);', []],
    'a write of something else is not a write' => ['$s->put("unrelated", 1);', []],
    'a comment is not a write' => ['// $s->put(ConsoleSession::ROLE, "admin");', []],
    'a docblock is not a write' => ['/** never $s->put("bfc_console.role", …) here */', []],
]);

// ─── The public surface: the escape a file scan cannot see ──────────────────

it('has exactly the public surface it is meant to have on the one class that can write', function (): void {
    // THE ESCAPE THIS CLOSES. The file scan above says only ConsoleGuard
    // can write a delegated session key. It cannot see a NEW PUBLIC
    // METHOD on ConsoleGuard that calls the existing private
    // beginSession(): every file assertion stays green while "only
    // redeem() mints" becomes false. The scan enumerated files; the
    // guarantee is about reachable operations, so this enumerates those.
    //
    // Adding a public method reds this test, and whoever adds it has to
    // extend the list in the same diff. That is the enforcement — not
    // prevention, which PHP cannot give, but a change that cannot be
    // made silently.
    // Grouped so each name says why it is allowed to exist, then sorted
    // to meet the scan's own contract — this is a SET, and the order it
    // is written in should serve the reader.
    $expected = [
        '__construct',
        // The delegated principal, typed, plus its session-bound claims
        // and the refusal reason the structured 401 reports.
        'actor',
        'claims',
        'refusalReason',
        // THE ONE OPERATION THAT MINTS. Everything else on this list
        // either reads or ends a session.
        'redeem',
        // Ends one. Deliberately not the framework's logout().
        'logout',
        // The Guard contract's own six, none of which can mint:
        // validate() is false for every input, and setUser() writes
        // nothing to the session.
        'check',
        'guest',
        'hasUser',
        'id',
        'setUser',
        'user',
        'validate',
        // Read-only: names a session key, grants nothing.
        'getName',
    ];

    sort($expected);

    expect(PublicSurfaceScan::of(ConsoleGuard::class))->toBe($expected);
});

it('has exactly the public surface it is meant to have on the two classes that read the keys', function (): void {
    // Symmetric cover: a new public writer on either of these would be
    // caught by the file scan, but a new public READER is drift too —
    // a second place deciding what a delegated claim means is the
    // divergence hazard this package has already deleted twice.
    expect(PublicSurfaceScan::of(ConsoleSession::class))->toBe(['claims', 'hasState', 'keys'])
        ->and(PublicSurfaceScan::of(ConsoleSessionClock::class))->toBe(['evaluate']);
});

it('names an unremarked public method, and a removed one', function (): void {
    // Proven able to fail, on the reviewer's exact scenario: a class
    // with a private writer and a second public method reaching it.
    expect(PublicSurfaceScan::unexpectedIn(SurfaceWithExtraPublicMethod::class, ['redeem']))
        ->toBe(['enterFromTrustedSource']);

    // A REMOVAL is drift too: if redeem() vanished the guarantee would
    // still read as true while meaning something else entirely.
    expect(PublicSurfaceScan::missingFrom(SurfaceWithExtraPublicMethod::class, ['redeem', 'mintDirectly']))
        ->toBe(['mintDirectly'])
        ->and(PublicSurfaceScan::unexpectedIn(SurfaceWithExtraPublicMethod::class, ['redeem', 'enterFromTrustedSource']))
        ->toBe([]);
});
