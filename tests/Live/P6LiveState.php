<?php

declare(strict_types=1);

namespace App\Support;

use Illuminate\Support\Facades\DB;

final class P6LiveState
{
    public static function increment(string $name): int
    {
        DB::statement(
            'INSERT INTO bfc_p6_runtime_state (name, value) VALUES (?, 1) '
            .'ON CONFLICT (name) DO UPDATE SET value = bfc_p6_runtime_state.value + 1',
            [$name],
        );

        return self::get($name);
    }

    public static function put(string $name, int $value): void
    {
        DB::statement(
            'INSERT INTO bfc_p6_runtime_state (name, value) VALUES (?, ?) '
            .'ON CONFLICT (name) DO UPDATE SET value = EXCLUDED.value',
            [$name, $value],
        );
    }

    public static function get(string $name): int
    {
        return (int) (DB::table('bfc_p6_runtime_state')->where('name', $name)->value('value') ?? 0);
    }

    /** @return array<string, int> */
    public static function all(): array
    {
        return DB::table('bfc_p6_runtime_state')
            ->orderBy('name')
            ->pluck('value', 'name')
            ->map(static fn (mixed $value): int => (int) $value)
            ->all();
    }
}
