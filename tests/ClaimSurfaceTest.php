<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Tests\ClaimSurfaceScan;

/**
 * THE CLAIM SURFACE, made enumerable in the one direction it turned out
 * to be enumerable in.
 *
 * The build this closes had one dominant defect: sentences asserting
 * properties nothing enforced. Three rounds of hand-narrowing each fixed
 * the sentences somebody had open and missed the ones nobody had
 * enumerated — one finding, arrived at three times. The thing that made
 * the miss possible is visible in the surviving example: "there is
 * nowhere in this table for prose to go" was written at THREE sites —
 * the events migration, the contract document and the model — and a
 * round that corrected the contract and the model left the migration
 * word for word.
 *
 * So the property pinned here is restatement, not truth: **a guarantee
 * phrase this package writes at three or more places is listed below
 * with its places.** Narrow it at two of three sites and this suite
 * reds, naming the site still carrying the old words. That is the exact
 * failure mode, and it is the one an instrument can actually decide.
 *
 * **WHAT WAS TRIED FIRST AND DOES NOT WORK**, recorded because the idea
 * is a natural one and somebody will have it again. Detecting absolute
 * VOCABULARY — *never, cannot, always, only, forever, complete* — and
 * requiring each instance to be paired with a citation or a residue
 * note was built and measured before this was written. It does not
 * separate the defect from the fix: this package's own corrections keep
 * the absolute word and change the SUBJECT it is predicated of.
 * "`dedup_key` stores a sha256 digest, never a caller's string" was
 * false; "**The emission point stores a sha256 digest in `dedup_key`**,
 * never a caller's string" is true; both say "never". The measurements
 * are in {@see ClaimSurfaceScan}'s docblock and the finding is a debt
 * row, not a silent omission.
 *
 * THE RESIDUE IS ON THE SCAN, and it is large: word-for-word
 * restatement only, three sites or more, ten words or more, and nothing
 * at all about whether any of it is true.
 */
$claimSurfaces = ['src', 'docs', 'release-notes', 'database/migrations', 'resources', 'README.md'];

/**
 * Every claim phrase this package writes at three or more sites, with
 * the sites.
 *
 * **A pinned map, not a floor.** Both directions are defects and they
 * are different ones: a phrase that LOSES a site is a claim narrowed in
 * some places and not others — the shape that produced this file — and
 * a phrase that GAINS one, or a new phrase entirely, is a guarantee
 * copied to a third place without anyone deciding to. Neither can
 * happen without this diff saying so.
 *
 * It is generated, and it is meant to be regenerated rather than hand
 * edited: the failure message names the phrase and the sites, and the
 * work is to visit them, not to update the number.
 *
 * @var array<string, list<string>>
 */
$restatedClaims = [
    'a declaration that has not opted in denies every override' => [
        'docs/http-contract.md',
        'release-notes/rotation.md',
        'src/Actions/RotateCredential.php',
    ],
    'a deployment whose database is unwritable cannot refuse an entry with a 403 it' => [
        'docs/http-contract.md',
        'release-notes/console-enter.md',
        'src/Http/Controllers/ConsoleEnter.php',
    ],
    'a traversal segment in any decoded form allowlist or no allowlist' => [
        'docs/http-contract.md',
        'release-notes/console-enter.md',
        'src/Console/ConsoleEntryState.php',
        'src/Console/ConsoleReturnTo.php',
    ],
    'a unique index only rejects a duplicate while the row it collides with' => [
        'database/migrations/2026_08_29_300002_create_bfc_app_action_outbox_table.php',
        'docs/http-contract.md',
        'src/Audit/AppActionOutboxEntry.php',
    ],
    'answers 404 the same answer an id that never existed gets' => [
        'docs/http-contract.md',
        'release-notes/personal-credentials.md',
        'src/Http/Controllers/PersonalCredentials.php',
    ],
    'as its holder and holds no operator mcp or signing power' => [
        'docs/http-contract.md',
        'release-notes/personal-credentials.md',
        'src/Contracts/DeclaresSelfServiceMintPolicy.php',
        'src/PersonalCredentialSurface.php',
    ],
    'at the model layer refuses every enumerated bulk mutation on the app-action stream' => [
        'docs/http-contract.md',
        'src/Audit/AppActionEvent.php',
        'src/Audit/AppActionOutboxEntry.php',
    ],
    'audience or an expired token because it is the only refusal that reaches the state binding the shadow-actor upsert' => [
        'docs/http-contract.md',
        'release-notes/console-enter.md',
        'src/Http/Controllers/ConsoleEnter.php',
    ],
    'authenticates as its holder and holds no operator mcp or' => [
        'docs/http-contract.md',
        'release-notes/personal-credentials.md',
        'src/PersonalCredentialSurface.php',
    ],
    'because crate\'s authorize reads the credential\'s own abilities and never the holder\'s role' => [
        'docs/http-contract.md',
        'release-notes/personal-credentials.md',
        'src/PersonalCredentialSurface.php',
    ],
    'burn key so two different issuer and mint pairs cannot hash alike' => [
        'docs/http-contract.md',
        'release-notes/console-enter.md',
        'src/Console/AssertionBurn.php',
    ],
    'consults the subject the row declares never anything the caller supplies sec-v3-07' => [
        'src/Actions/ActivateCredential.php',
        'src/Actions/RevokeCredential.php',
        'src/Actions/RotateCredential.php',
    ],
    'every bound credential in every lifecycle state active rotation-grace and pending unexchanged enrollments and' => [
        'docs/http-contract.md',
        'release-notes/offboarding.md',
        'src/Actions/OffboardSubject.php',
    ],
    'every other driver reports pending from the connection\'s own size' => [
        'docs/http-contract.md',
        'src/Vitals/CollectVitals.php',
        'src/Vitals/QueueVitals.php',
    ],
    'exactly a known set so a new public method cannot quietly call that private writer while every file assertion stays green both are' => [
        'docs/http-contract.md',
        'release-notes/unified-store-guard.md',
        'src/Console/ConsoleGuard.php',
    ],
    'get at the enter path so an assertion can never ride a query string' => [
        'docs/http-contract.md',
        'release-notes/console-enter.md',
        'src/Http/Controllers/ConsoleEnter.php',
    ],
    'has no credential-shaped entry point on the guard at all' => [
        'docs/http-contract.md',
        'src/Console/ConsoleGuard.php',
        'src/Console/DelegatedActor.php',
        'src/Console/DelegatedActorProvider.php',
    ],
    'is a token api that wants no session these three' => [
        'docs/http-contract.md',
        'release-notes/personal-credentials.md',
        'src/BuiltForCloudServiceProvider.php',
    ],
    'is ddl and no row trigger sees it a raw insert' => [
        'database/migrations/2026_08_29_300002_create_bfc_app_action_outbox_table.php',
        'docs/http-contract.md',
        'src/Audit/AppActionEvent.php',
    ],
    'is shared by every live session for the same subject' => [
        'src/Audit/AppActionActor.php',
        'src/Console/ActingPrincipal.php',
        'src/Console/ConsoleSession.php',
        'src/Console/DelegatedClaims.php',
        'src/Http/Controllers/ConsoleEnter.php',
    ],
    'it means the row structurally cannot carry a usage signal' => [
        'docs/http-contract.md',
        'release-notes/subjects-authority.md',
        'src/ReportedStatus.php',
    ],
    'leaves a contained actor\'s mint unspent so every attempt audits as containment' => [
        'docs/http-contract.md',
        'release-notes/console-enter.md',
        'src/Console/AssertionBurn.php',
        'src/Http/Controllers/ConsoleEnter.php',
    ],
    'never behind a configurable prefix never behind its own env flag' => [
        'docs/http-contract.md',
        'src/BuiltForCloudServiceProvider.php',
        'src/Http/Controllers/ManageOnboarding.php',
    ],
    'never produce a credential a mint of that shape could' => [
        'src/Actions/Concerns/ConsultsDeclaration.php',
        'src/Actions/RotateCredential.php',
        'src/Contracts/AuthorizesRotationOverrides.php',
    ],
    'no package api assembles a delegated session without verified assertion' => [
        'docs/http-contract.md',
        'release-notes/unified-store-guard.md',
        'src/Console/ConsoleSession.php',
    ],
    'php cannot express no future public method may call this private method' => [
        'docs/http-contract.md',
        'release-notes/unified-store-guard.md',
        'src/Console/ConsoleGuard.php',
    ],
    'php requires both halves of the delegated seam on every registered chrome route' => [
        'docs/http-contract.md',
        'src/Console/ServesConsoleChrome.php',
        'src/Http/Controllers/ConsoleChromeScript.php',
    ],
    'pinned by tests assertionsecrecytest php marks every frame in this package' => [
        'docs/http-contract.md',
        'src/Console/AssertionVerifier.php',
        'src/Http/Controllers/ConsoleEnter.php',
    ],
    'records every refusal it serves one row per refused entry' => [
        'docs/http-contract.md',
        'release-notes/console-enter.md',
        'src/Http/Controllers/ConsoleEnter.php',
    ],
    'records no entry event when the entry transaction rolls back' => [
        'docs/http-contract.md',
        'release-notes/console-enter.md',
        'src/Http/Controllers/ConsoleEnter.php',
    ],
    'refuses every credential lookup unconditionally not merely the ones that do' => [
        'docs/http-contract.md',
        'src/Console/ConsoleGuard.php',
        'src/Console/DelegatedActor.php',
        'src/Console/DelegatedActorProvider.php',
    ],
    'refuses every enumerated bulk mutation on the app-action stream on both' => [
        'docs/http-contract.md',
        'src/Audit/AppActionEvent.php',
        'src/Audit/AppActionOutboxEntry.php',
        'src/Audit/AppendOnlyBuilder.php',
    ],
    'revokes every credential under the subject and every credential bound to the user' => [
        'docs/http-contract.md',
        'release-notes/personal-credentials.md',
        'src/PersonalCredentialSurface.php',
    ],
    'shared by every live session for the same subject so' => [
        'src/Audit/AppActionActor.php',
        'src/Console/ConsoleSession.php',
        'src/Console/DelegatedClaims.php',
    ],
    'straight out of the sealed carrier and accepts no secret input of any kind' => [
        'src/Commands/CredentialMintCommand.php',
        'src/Commands/CredentialRotateCommand.php',
        'src/Commands/InvitationIssueCommand.php',
    ],
    'surface cannot honestly make when it does not know whose credentials' => [
        'docs/http-contract.md',
        'release-notes/personal-credentials.md',
        'src/Http/Controllers/PersonalCredentials.php',
    ],
    'tests assertionsecrecytest php marks every frame in this package that holds console assertion bytes' => [
        'docs/http-contract.md',
        'release-notes/console-enter.md',
        'src/Console/AssertionVerifier.php',
        'src/Http/Controllers/ConsoleEnter.php',
    ],
    'tests consoledelegatedactortest php refuses every credential lookup unconditionally not merely the ones' => [
        'docs/http-contract.md',
        'src/Console/ConsoleGuard.php',
        'src/Console/DelegatedActorProvider.php',
    ],
    'that assertion stays presentable until its ttl runs out every presentation refused every one audited as actor deactivated spending it' => [
        'docs/http-contract.md',
        'release-notes/console-enter.md',
        'src/Console/AssertionBurn.php',
    ],
    'the acting principal and for all ui attribution branching never a union' => [
        'docs/http-contract.md',
        'release-notes/console-reservations.md',
        'release-notes/unified-store-guard.md',
        'src/Auth/CredentialGuard.php',
    ],
    'the lock is only as exclusive as the cache store is shared' => [
        'release-notes/hmac-kind.md',
        'src/Commands/HmacRewrapCommand.php',
        'src/Hmac/HmacWriterBarrier.php',
    ],
    'the matrix consults the subject the row declares never anything the' => [
        'src/Actions/ActivateCredential.php',
        'src/Actions/RevokeCredential.php',
        'src/Actions/RotateCredential.php',
        'src/Http/Controllers/ManageTokens.php',
    ],
    'the mint signed it refuses an entry that presents no state at all refuses a mint that signed no state whatever state is presented and refuses a state' => [
        'docs/http-contract.md',
        'release-notes/console-enter.md',
        'src/Console/ConsoleEntryState.php',
    ],
    'the package cannot invalidate an arbitrary session store it does not own' => [
        'docs/http-contract.md',
        'release-notes/offboarding.md',
        'src/Actions/OffboardSubject.php',
    ],
    'unmarked and the object those vendor frames hold no longer carries it' => [
        'docs/http-contract.md',
        'release-notes/console-enter.md',
        'src/Http/Controllers/ConsoleEnter.php',
    ],
    'when the walk meets one names the shapes it cannot reach so the claim beside it stays true and' => [
        'docs/http-contract.md',
        'release-notes/console-enter.md',
        'src/Http/Controllers/ConsoleEnter.php',
    ],
];

it('lists every guarantee phrase this package restates at three or more sites', function () use ($claimSurfaces, $restatedClaims): void {
    $prose = ClaimSurfaceScan::proseAcross(dirname(__DIR__), $claimSurfaces);

    // THE FLOOR FIRST. A walk whose surfaces had drifted, or whose
    // extension list had, would read no prose at all and report a clean
    // empty map — the failure this package has now met four times, in
    // which a filter cannot see the thing that is missing. So the
    // enumeration is asserted before anything is concluded from it.
    expect(count($prose))->toBeGreaterThan(250)
        ->and($prose['docs/http-contract.md'])->toContain('bfc_version')
        ->and($prose['src/Console/ConsoleGuard.php'])->not->toBe('');

    expect(ClaimSurfaceScan::restatedClaimsIn($prose))->toBe($restatedClaims);
});

it('names a claim narrowed at some of its sites and left standing at another', function (): void {
    // THE FIXTURE IS THE REAL OFFENCE, taken verbatim from the three
    // sites it survived at through PR7's three narrowing rounds: the
    // events migration, the contract document and the model. Every
    // round corrected the sites someone had open; the migration kept
    // the sentence word for word while a green suite watched.
    $claim = 'What each column can hold is bounded by its own kind, and that part is '
        .'structural: there is nowhere in this table for prose to go.';

    $narrowed = 'The schema has no column designated for arbitrary app content or notes. '
        .'Recorder emissions use bounded enums and identifiers.';

    $sites = [
        'database/migrations/2026_08_29_300001_create_bfc_app_action_events_table.php' => "<?php\n\n// ".$claim."\n",
        'docs/http-contract.md' => "## Storage\n\n".$claim."\n",
        'src/Audit/AppActionEvent.php' => "<?php\n\n/**\n * ".$claim."\n */\n",
    ];

    $prose = array_map(ClaimSurfaceScan::proseIn(...), array_keys($sites), $sites);
    $prose = array_combine(array_keys($sites), $prose);

    // All three sites carrying it: reported, with the sites named.
    expect(ClaimSurfaceScan::restatedClaimsIn($prose))
        ->toBe([
            'own kind and that part is structural there is nowhere in this table for prose to go'
                => array_keys($sites),
        ]);

    // Round two: the contract and the model narrowed, the migration
    // left exactly as it was. The map CHANGES — which is what reds a
    // pinned inventory, and the failure names the site still carrying
    // the old words.
    $round2 = $prose;
    $round2['docs/http-contract.md'] = "## Storage\n\n".$narrowed."\n";
    $round2['src/Audit/AppActionEvent.php'] = ClaimSurfaceScan::proseIn(
        'src/Audit/AppActionEvent.php',
        "<?php\n\n/**\n * ".$narrowed."\n */\n",
    );

    expect(ClaimSurfaceScan::restatedClaimsIn($round2))->toBe([]);
});

it('leaves a claim at two sites, a short claim and an unremarkable phrase unreported', function (): void {
    // THE THREE BOUNDS, DRIVEN RATHER THAN DESCRIBED. Each is a
    // threshold somebody chose, so each is asserted where it lands:
    // a reader who wants to know what this misses can read these
    // rather than trust the docblock.
    $absolute = 'the delegated session is destroyed and the operator can never reach the console again';

    // 1. Two sites is below the threshold. This is the largest single
    //    thing the pin does not cover.
    expect(ClaimSurfaceScan::restatedClaimsIn([
        'docs/a.md' => $absolute,
        'docs/b.md' => $absolute,
    ]))->toBe([]);

    // 2. Three sites, but shorter than the window.
    expect(ClaimSurfaceScan::restatedClaimsIn([
        'docs/a.md' => 'never truncates',
        'docs/b.md' => 'never truncates',
        'docs/c.md' => 'never truncates',
    ]))->toBe([]);

    // 3. Three sites, long enough, and carrying no claim vocabulary at
    //    all — boilerplate a package repeats everywhere is not a
    //    guarantee, and reporting it would bury the ones that are.
    $boilerplate = 'this file is part of the built for cloud package and is published under the mit licence';

    expect(ClaimSurfaceScan::restatedClaimsIn([
        'docs/a.md' => $boilerplate,
        'docs/b.md' => $boilerplate,
        'docs/c.md' => $boilerplate,
    ]))->toBe([]);

    // And the same three sites WITH claim vocabulary are reported, so
    // the three assertions above are read as bounds rather than as a
    // scan that finds nothing.
    expect(ClaimSurfaceScan::restatedClaimsIn([
        'docs/a.md' => $absolute,
        'docs/b.md' => $absolute,
        'docs/c.md' => $absolute,
    ]))->toBe([$absolute => ['docs/a.md', 'docs/b.md', 'docs/c.md']]);
});

it('reads prose and not code, so a repeated identifier is not a repeated claim', function (): void {
    // The distinction the walk rests on. Four controllers declaring the
    // same private helper share a great deal of text and claim nothing;
    // a scan that counted it would report the identifiers and bury the
    // sentences.
    $code = "<?php\n\nfinal class A { private function actor(Request \$request): ?AuditActor { return null; } }\n";
    $comment = "<?php\n\n/**\n * The matrix consults the subject the row declares, never anything the caller supplies.\n */\nfinal class B {}\n";

    expect(ClaimSurfaceScan::proseIn('src/A.php', $code))->toBe('')
        ->and(ClaimSurfaceScan::proseIn('src/B.php', $comment))
        ->toContain('never anything the caller supplies');

    // A `//` inside a string literal is not a comment, which is why
    // this tokenises rather than matching a regex.
    expect(ClaimSurfaceScan::proseIn('src/C.php', "<?php\n\n\$url = 'https://example.test/never';\n"))->toBe('');

    // Markdown is prose entire; a file whose extension carries no prose
    // convention here yields nothing rather than being read raw.
    expect(ClaimSurfaceScan::proseIn('docs/a.md', '# never'))->toBe('# never')
        ->and(ClaimSurfaceScan::proseIn('config/a.json', '{"never": 1}'))->toBe('');
});

it('reads a wrapped and emphasised claim as the same phrase as a plain one', function (): void {
    // Normalisation is what makes "the same claim" decidable at all,
    // and it is the same trade `tests/ContractScan.php` names: a list
    // of the variants somebody thought of. Wrapping and emphasis are on
    // it because this package's own restatements differ in exactly
    // those two ways — a docblock wraps at 72 characters and bolds the
    // load-bearing half; the contract does neither.
    $plain = "the emission point stores a sha256 digest and never a caller's string";
    $wrapped = "<?php\n\n/**\n * The **emission point** stores a sha256 digest and\n * never a caller's string.\n */\n";

    expect(ClaimSurfaceScan::words($plain))
        ->toBe(ClaimSurfaceScan::words(ClaimSurfaceScan::proseIn('src/A.php', $wrapped)));
});
