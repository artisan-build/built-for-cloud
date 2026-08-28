<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

/**
 * CSV-formula neutralization for customer-visible audit text (D8
 * adjustment 3). `note` and `reason` are stored VERBATIM and escaped per
 * renderer; any export path that writes them into a spreadsheet-consumable
 * file MUST pass every cell through {@see sanitize()} first.
 *
 * This PR ships no export surface — the audit read verb rides the
 * two-transport PR — so the helper ships tested, as the contract that
 * surface must use.
 *
 * The neutralization is the OWASP CSV-injection rule: a cell whose first
 * character would make a spreadsheet evaluate it (`=`, `+`, `-`, `@`, tab,
 * carriage return) is prefixed with a single quote. Interior newlines and
 * quotes are the CSV writer's quoting problem, not a formula problem, and
 * are preserved untouched.
 */
final class CsvFieldSanitizer
{
    private const array FORMULA_LEADERS = ['=', '+', '-', '@', "\t", "\r"];

    public static function sanitize(string $value): string
    {
        if ($value === '') {
            return $value;
        }

        if (in_array($value[0], self::FORMULA_LEADERS, true)) {
            return "'".$value;
        }

        return $value;
    }
}
