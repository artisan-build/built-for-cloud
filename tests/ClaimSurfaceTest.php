<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Tests\AbsolutePairingMeasurement;
use ArtisanBuild\BuiltForCloud\Tests\ClaimSurfaceScan;

/**
 * THE RESTATEMENT MAP, and the measurement that argued for it.
 *
 * The build this closes had one dominant defect: sentences asserting
 * properties nothing enforced. Three rounds of hand-narrowing each fixed
 * the sentences somebody had open. The surviving example says why that
 * was possible — "there is nowhere in this table for prose to go" was
 * written at the events migration, the contract and the model, and the
 * round that corrected two of them left the third word for word.
 *
 * So what is pinned here is restatement, not truth: the runs this parse
 * finds at three or more sites, with their sites. Narrow one at two of
 * three and the map changes, naming the site still carrying the old
 * words. `tests/ClaimSurfaceScan.php` states what the parse recognises
 * and what it does not; the tests below drive each of those bounds.
 *
 * **WHAT WAS BUILT FIRST AND SET ASIDE**, with the measurement runnable
 * instead of quoted. Detecting absolute VOCABULARY and requiring each
 * occurrence to be paired with a citation or a residue note was built
 * and measured before this was written. The counting rules are
 * {@see AbsolutePairingMeasurement} and the numbers are asserted below,
 * because a measurement supporting a design decision that a reader
 * cannot re-run is a citation nobody can follow — the defect this PR is
 * about, committed by the PR.
 *
 * The numbers reject a GATE requiring every unpaired occurrence to be
 * annotated. They do not reject a pinned baseline or a changed-prose
 * detector over the same blocks; nothing here was measured about those.
 * What argued against the family is the five corrections: the
 * vocabulary finds two of the five false sentences, and finds both of
 * their replacements too.
 */
$claimSurfaces = [
    'src',
    'docs',
    'release-notes',
    'database/migrations',
    'resources',
    'README.md',
    // E5. 521 lines of it, 32 blocks carrying an absolute, and one live
    // three-site guarantee was being REPORTED AS TWO because its third
    // site is here. That is the map being wrong about a real guarantee
    // rather than merely narrow, which is why this path is added and
    // nothing else is: `config/` is where this package explains what
    // each knob does, and explaining a knob is making a claim about it.
    'config/built-for-cloud.php',
];

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
    'so a nonce accepted once cannot be accepted again anywhere in its valid window boundary' => [
        'config/built-for-cloud.php',
        'release-notes/hmac-kind.md',
        'src/Hmac/HmacVerifier.php',
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
    $phrase = 'own kind and that part is structural there is nowhere in this table for prose to go';

    expect(ClaimSurfaceScan::restatedClaimsIn($prose))
        ->toBe([$phrase => array_keys($sites)]);

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

it('walks a run of repeated words to a finite phrase instead of running forever', function (): void {
    // D1, AND IT WAS NOT A THEORETICAL INPUT. Three files each holding
    // ten repetitions of one absolute word made the leftward walk
    // prepend words until the process ran out of memory, because the
    // cycle guard recorded the GROWING PHRASE — which gains a word every
    // pass and is therefore never one it has recorded before — instead
    // of the predecessor WINDOW, which comes from a finite set.
    //
    // A hanging test is worse than a failing one: CI has no signal to
    // give. So the guard is pinned with a finite expected result rather
    // than described in a docblock.
    $repeated = trim(str_repeat('never ', 10));

    expect(ClaimSurfaceScan::restatedClaimsIn([
        'docs/a.md' => $repeated,
        'docs/b.md' => $repeated,
        'docs/c.md' => $repeated,
    ]))->toBe([$repeated => ['docs/a.md', 'docs/b.md', 'docs/c.md']]);

    // THE AXIS IS THE NUMBER OF DISTINCT WINDOWS, and it is driven on
    // both sides of the boundary because the residue was worded twice
    // from whichever side happened to be fixtured and was wrong twice.
    //
    // A two-word cycle exactly PHRASE_WORDS long is ONE window: nothing
    // continues it, so it is maximal and it is reported.
    $atTheBoundary = trim(str_repeat('never always ', 5));

    expect(count(ClaimSurfaceScan::words($atTheBoundary)))->toBe(ClaimSurfaceScan::PHRASE_WORDS)
        ->and(ClaimSurfaceScan::restatedClaimsIn([
            'docs/a.md' => $atTheBoundary,
            'docs/b.md' => $atTheBoundary,
            'docs/c.md' => $atTheBoundary,
        ]))->toBe([$atTheBoundary => ['docs/a.md', 'docs/b.md', 'docs/c.md']]);

    // Two words longer is TWO distinct windows, each continuing the
    // other with the same site list, so neither is maximal and the run
    // is reported nowhere.
    $pastTheBoundary = trim(str_repeat('never always ', 6));

    expect(ClaimSurfaceScan::restatedClaimsIn([
        'docs/a.md' => $pastTheBoundary,
        'docs/b.md' => $pastTheBoundary,
        'docs/c.md' => $pastTheBoundary,
    ]))->toBe([]);

    // And further along the same axis, so the boundary reads as a rule
    // rather than as an accident of one length.
    $alternating = trim(str_repeat('never always ', 8));

    expect(ClaimSurfaceScan::restatedClaimsIn([
        'docs/a.md' => $alternating,
        'docs/b.md' => $alternating,
        'docs/c.md' => $alternating,
    ]))->toBe([]);
});

it('reports only the absolute-bearing region of a restated sentence, so words beyond it are not pinned', function (): void {
    // D2, AND IT IS THE SHARPEST THING THIS INSTRUMENT DOES NOT SEE.
    // The chain is built from windows that contain an absolute, so it
    // stops wherever ten consecutive words carry none — and everything
    // past that stop is outside the reported phrase and outside the pin.
    $sites = static fn (string $prose): array => [
        'docs/a.md' => $prose,
        'docs/b.md' => $prose,
        'docs/c.md' => $prose,
    ];

    // The reviewer's input. Reported from `table` onward: the three
    // words before it are outside the region.
    $claim = 'the package database table holding app action events and ledger rows can never '
        .'contain caller supplied prose';

    expect(array_keys(ClaimSurfaceScan::restatedClaimsIn($sites($claim))))
        ->toBe(['table holding app action events and ledger rows can never contain caller supplied prose']);

    // AND THE CONSEQUENCE, DRIVEN RATHER THAN DESCRIBED: the SUBJECT
    // rewritten at every site, outside the region, leaves the map
    // byte-identical. This is the correction shape the class was built
    // for — PR8 kept "never" and changed what the sentence was about —
    // so a reader needs to know it is invisible here when the changed
    // words sit far enough from the nearest absolute.
    $subjectChanged = 'the recorder emission point table holding app action events and ledger rows '
        .'can never contain caller supplied prose';

    expect(ClaimSurfaceScan::restatedClaimsIn($sites($subjectChanged)))
        ->toBe(ClaimSurfaceScan::restatedClaimsIn($sites($claim)));

    // A change INSIDE the region does red it, so the assertion above is
    // read as a bound rather than as an instrument that sees nothing.
    $insideChanged = 'the package database table holding app action events and ledger rows can never '
        .'contain operator supplied prose';

    expect(ClaimSurfaceScan::restatedClaimsIn($sites($insideChanged)))
        ->not->toBe(ClaimSurfaceScan::restatedClaimsIn($sites($claim)));

    // An interior stretch of ten words with no absolute clips the run
    // there, which is the same bound in the middle of a sentence.
    $withGap = 'the ledger never records anything that the consuming application has not first '
        .'written down inside its own database transaction and committed successfully to disk';

    expect(array_keys(ClaimSurfaceScan::restatedClaimsIn($sites($withGap))))
        ->toBe(['the ledger never records anything that the consuming application has not first']);
});

it('reproduces the measurement the pairing instrument was set aside on', function () use ($claimSurfaces): void {
    // D3. The counts were quoted in a docblock and nowhere runnable, so
    // a reader had to take a design decision on trust. These are the
    // same surfaces `tests/CitationScan.php` treats as guarantee-bearing
    // — the ones an annotation gate would have applied to — and the
    // counting rules are in AbsolutePairingMeasurement's docblock.
    //
    // THEY ARE PINNED EXACTLY, AND THAT MEANS PROSE EDITS RED THIS.
    // Deliberate: the numbers are cited in ClaimSurfaceScan's docblock,
    // and a cited number that drifts silently is the thing this package
    // exists to prevent. When it reds, update both.
    $gateSurfaces = [
        'src/Console', 'src/Audit', 'src/Http/Controllers/ConsoleEnter.php',
        'src/Http/Controllers/ConsoleChromeScript.php', 'resources/views', 'resources/js',
        'docs/http-contract.md', 'release-notes/console-enter.md',
        'release-notes/unified-store-guard.md', 'release-notes/console-reservations.md',
    ];

    expect(AbsolutePairingMeasurement::measure(
        AbsolutePairingMeasurement::filesAcross(dirname(__DIR__), $gateSurfaces),
    ))->toBe([
        'blocks' => 1239,
        'absolute' => 406,
        'paired' => 110,
        'unpaired' => 296,
    ]);

    // The surfaces the restatement map runs over are wider than the
    // gate's, and deliberately so — the migration that carried the
    // surviving claim is in one of them and in none of the gate's.
    expect($claimSurfaces)->toContain('database/migrations')
        ->and($gateSurfaces)->not->toContain('database/migrations');
});

it('shows what the vocabulary does with the five corrections this build had to make', function (): void {
    // E4. THE FIRST VERSION OF THIS FIXTURE WAS HAND-AUTHORED FROM THE
    // REVIEW'S PROPOSED WORDING, and not one of its five `after` halves
    // occurred in the merged tree — a fixture standing in for a history
    // that did not happen, which is this PR's own subject committed
    // inside this PR. So the halves are checked against the artifacts
    // before anything is concluded from them.
    $root = dirname(__DIR__);

    foreach (AbsolutePairingMeasurement::CORRECTIONS as $correction) {
        $contents = (string) file_get_contents($root.'/'.$correction['file']);

        expect($contents)->toContain($correction['after'])
            ->and($contents)->not->toContain($correction['before']);
    }

    // Only then, what the vocabulary makes of them.
    $flagged = array_map(
        static fn (array $correction): array => [
            AbsolutePairingMeasurement::vocabularyIn($correction['before']) !== [],
            AbsolutePairingMeasurement::vocabularyIn($correction['after']) !== [],
        ],
        AbsolutePairingMeasurement::CORRECTIONS,
    );

    // THE LOAD-BEARING NUMBER: three of the five false phrases carry no
    // word from the list at all. "exactly one event per action", "What
    // the schema constrains …" and "there is nowhere in this table for
    // prose to go" are absolute claims the vocabulary never sees, so a
    // gate over it would have demanded annotations on sentences that
    // were fine and demanded nothing on three that were false.
    expect(count(array_filter($flagged, static fn (array $pair): bool => $pair[0])))->toBe(2);

    // And of the two it does find, ONE has a replacement it finds too —
    // PR8 kept "only" and moved it from the table to the column. Where
    // that happens the detector cannot tell the defect from its own fix.
    //
    // This number was reported as 2 before the fixture was checked
    // against the artifacts. It is 1. The miss rate above is what the
    // argument rests on.
    expect(count(array_filter($flagged, static fn (array $pair): bool => $pair[0] && $pair[1])))->toBe(1);

    // That one pair, spelled out, so the claim is legible without
    // running anything.
    expect(AbsolutePairingMeasurement::vocabularyIn('the only shape this table stores'))->toBe(['only'])
        ->and(AbsolutePairingMeasurement::vocabularyIn('The TABLE enforces only 64 characters and uniqueness'))
        ->toBe(['only']);
});
