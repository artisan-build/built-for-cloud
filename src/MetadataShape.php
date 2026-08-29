<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyring;
use ArtisanBuild\BuiltForCloud\Testing\ContractAssertions;
use ArtisanBuild\BuiltForCloud\Vitals\CollectVitals;

/**
 * The three bounded string forms the SHARED metadata vocabulary defines
 * (Console PRD D15, docs/http-contract.md "Endpoint classification"), in
 * ONE place.
 *
 * They are not the only permissible forms: a field bounded in a charset
 * of its own gets its own NAMED type here — {@see self::CONSOLE_KEY_ID}
 * is the one such field today. Loosening the three shared patterns to
 * accommodate it would have let a capitalised word through everywhere,
 * which is the whole failure they exist to prevent.
 *
 * Named, and only named. The conformance instrument used to let a schema
 * supply an arbitrary regex for a field, which put the definition of
 * "bounded" in the hands of the party being checked: `'/^.*$/sD'` is a
 * valid pattern and certifies free text. Every bounded form a schema can
 * name now lives in this class, where it is enumerable, reviewable, and
 * the same object the producer validates against.
 *
 * It lives here rather than in the test trait because the same patterns
 * are load-bearing on both sides: {@see CollectVitals} refuses to echo an
 * operator-authored `app_version` that does not match
 * {@see self::SEMVER}, and {@see ContractAssertions} fails a payload
 * carrying a string that matches none of the three. Two copies of these
 * patterns is exactly how a payload comes to pass a conformance check
 * while carrying something the producer's own bound would have refused —
 * an earlier revision of this PR had them separately defined and the
 * looser one won.
 *
 * Every pattern is anchored, `D`-modified (so a trailing newline cannot
 * satisfy `$`), and LENGTH-BOUNDED. None carries the `u` modifier, which
 * is deliberate: the character classes are ASCII, so any multi-byte
 * sequence fails on its individual bytes and unicode free text is
 * refused rather than partially matched.
 */
final class MetadataShape
{
    /**
     * A bounded identifier: lowercase alphanumeric runs joined by single
     * `.`, `_`, `:` or `-` separators, 1..64 characters. Enum members
     * (`ok`, `degraded`, `seconds`), ability names (`metadata:read`),
     * capability names (`console-vitals`) and uuids all take this shape;
     * a sentence, a display name, a path and an email address do not.
     */
    public const string TOKEN = '/^(?=.{1,64}$)[a-z0-9]+(?:[._:-][a-z0-9]+)*$/D';

    /**
     * Semver, 1..32 characters, with LOWERCASE pre-release and build
     * parts.
     *
     * Deliberately narrower than the semver specification, which permits
     * `[0-9A-Za-z-]` there and no length at all. That latitude was this
     * instrument's fail-open branch: `1.4.2+Jane.Operator` and
     * `1.4.2-ReleaseCandidateTuesday` are both valid semver, both carry
     * operator-authored free text, and both passed. A version string
     * that cannot be spelled in lowercase is not one this contract will
     * forward to the vendor.
     */
    public const string SEMVER = '/^(?=.{1,32}$)\d{1,6}\.\d{1,6}\.\d{1,6}(?:-[0-9a-z]+(?:[.-][0-9a-z]+)*)?(?:\+[0-9a-z]+(?:[.-][0-9a-z]+)*)?$/D';

    /** An ISO-8601 instant with an explicit offset or `Z`, 1..40 characters. */
    public const string TIMESTAMP = '/^(?=.{1,40}$)\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})$/D';

    /**
     * A console countersigning-key id — the ONE field in the contract
     * that is bounded and deliberately not lowercase.
     *
     * The pattern is {@see ConsoleKeyring::KEY_ID_PATTERN} itself, not a
     * copy: the keyring is the authority on what a `kid` may be, and a
     * second regex here would be the drift that class's docblock already
     * warns about.
     */
    public const string CONSOLE_KEY_ID = ConsoleKeyring::KEY_ID_PATTERN;

    public static function isToken(string $value): bool
    {
        return preg_match(self::TOKEN, $value) === 1;
    }

    public static function isSemver(string $value): bool
    {
        return preg_match(self::SEMVER, $value) === 1;
    }

    public static function isTimestamp(string $value): bool
    {
        return preg_match(self::TIMESTAMP, $value) === 1;
    }

    public static function isConsoleKeyId(string $value): bool
    {
        return preg_match(self::CONSOLE_KEY_ID, $value) === 1;
    }

    /**
     * Any of the three — the LEXICAL check, and the whole of what a
     * shape test can decide about a string in isolation. It says the
     * value is bounded; it cannot say the FIELD is bounded, which is
     * what a schema says. See
     * {@see ContractAssertions::assertBuiltForCloudMetadataSchema}.
     */
    public static function isBounded(string $value): bool
    {
        return self::isToken($value) || self::isSemver($value) || self::isTimestamp($value);
    }
}
