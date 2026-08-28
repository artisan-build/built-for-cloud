<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CsvFieldSanitizer;
use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use LogicException;

uses(RefreshDatabase::class);

function appendAuditRow(?string $note = null): CredentialAuditEvent
{
    return DB::transaction(fn (): CredentialAuditEvent => app(LifecycleEventRecorder::class)->record(
        event: LifecycleEventType::Revoked,
        credentialId: '00000000-0000-0000-0000-000000000001',
        note: $note,
    ));
}

it('rejects update and delete at the model layer', function (): void {
    $row = appendAuditRow();

    expect(fn (): bool => $row->update(['note' => 'rewritten history']))
        ->toThrow(LogicException::class, 'append-only');

    expect(fn (): ?bool => $row->delete())
        ->toThrow(LogicException::class, 'append-only');

    $stored = CredentialAuditEvent::query()->findOrFail($row->id);
    expect($stored->note)->toBeNull();
});

it('rejects truncate on both the static and the query-builder paths', function (): void {
    $row = appendAuditRow();

    // TRUNCATE is DDL on mysql, where the row triggers never fire — the
    // model layer must refuse it before the driver sees it. Raw
    // `DB::table(...)->truncate()` and raw TRUNCATE SQL bypass the model
    // and are outside the package's enforcement boundary (a
    // database-privilege matter, per the model docblock).
    expect(fn (): mixed => CredentialAuditEvent::truncate())
        ->toThrow(LogicException::class, 'never truncated');

    expect(fn (): mixed => CredentialAuditEvent::query()->truncate())
        ->toThrow(LogicException::class, 'never truncated');

    expect(CredentialAuditEvent::query()->whereKey($row->id)->exists())->toBeTrue();
});

it('rejects raw query-builder update and delete at the database layer on sqlite', function (): void {
    // Model guards do not see raw writes; the sqlite triggers do. (The
    // honest limit, documented in the migration: a connection with schema
    // access can DROP the trigger — append-only is by construction, not
    // cryptographic. mysql/pgsql ship equivalent triggers this suite's
    // driver cannot exercise.)
    $row = appendAuditRow();

    expect(fn (): int => DB::table('credential_audit_events')->where('id', $row->id)->update(['note' => 'tampered']))
        ->toThrow(QueryException::class, 'append-only');

    expect(fn (): int => DB::table('credential_audit_events')->where('id', $row->id)->delete())
        ->toThrow(QueryException::class, 'append-only');

    expect(CredentialAuditEvent::query()->findOrFail($row->id)->note)->toBeNull();
})->skip(fn (): bool => DB::connection()->getDriverName() !== 'sqlite', 'database-layer enforcement is per-driver; this suite runs sqlite');

it('stores hostile reason notes verbatim and neutralizes them through the export helper', function (string $hostile): void {
    $row = appendAuditRow($hostile);

    // Stored VERBATIM: neutralization is a render/export concern, and
    // mangling the stored value would falsify the record. (Escaping-on-
    // render is each renderer's own default behaviour — Blade escapes
    // interpolations — and is not re-tested here; what the PACKAGE ships
    // is the export helper every export path must use.)
    $stored = CredentialAuditEvent::query()->findOrFail($row->id);
    expect($stored->note)->toBe($hostile);

    // The stored value round-trips the export helper: a formula-leading
    // note comes out defanged, anything else comes out byte-identical.
    $expected = in_array($hostile[0], ['=', '+', '-', '@', "\t", "\r"], true) ? "'".$hostile : $hostile;

    expect(CsvFieldSanitizer::sanitize((string) $stored->note))->toBe($expected);
})->with([
    'formula with dde pipe' => ['=cmd|\' /C calc\'!A0'],
    'at-formula' => ['@SUM(1+9)*cmd|\' /C calc\'!A0'],
    'plus formula' => ['+2+5+cmd|\' /C calc\'!A0'],
    'minus formula' => ['-2+3'],
    'leading tab' => ["\t=1+2"],
    'embedded newlines' => ["line one\r\n=HYPERLINK(\"http://evil.test\")\nline three"],
    'html' => ['<script>alert(1)</script><img src=x onerror=alert(1)>'],
]);

it('bounds the free-text note to 500 characters', function (): void {
    $row = appendAuditRow(str_repeat('a', 700));

    expect(mb_strlen((string) CredentialAuditEvent::query()->findOrFail($row->id)->note))->toBe(500);
});

it('neutralizes formula-leading cells in the export helper and leaves benign cells alone', function (): void {
    // Every formula leader is defanged with a leading single quote…
    expect(CsvFieldSanitizer::sanitize('=cmd|\' /C calc\'!A0'))->toBe("'=cmd|' /C calc'!A0")
        ->and(CsvFieldSanitizer::sanitize('@SUM(1+9)'))->toBe("'@SUM(1+9)")
        ->and(CsvFieldSanitizer::sanitize('+2+5'))->toBe("'+2+5")
        ->and(CsvFieldSanitizer::sanitize('-2+3'))->toBe("'-2+3")
        ->and(CsvFieldSanitizer::sanitize("\t=1+2"))->toBe("'\t=1+2")
        ->and(CsvFieldSanitizer::sanitize("\r=1+2"))->toBe("'\r=1+2");

    // …interior content is preserved untouched (quoting interior newlines
    // is the CSV writer's job, not a formula concern)…
    expect(CsvFieldSanitizer::sanitize("safe\n=not-a-formula"))->toBe("safe\n=not-a-formula");

    // …and benign cells pass through byte-identical.
    expect(CsvFieldSanitizer::sanitize('operator asked politely'))->toBe('operator asked politely')
        ->and(CsvFieldSanitizer::sanitize(''))->toBe('')
        ->and(CsvFieldSanitizer::sanitize('rotation'))->toBe('rotation');
});
