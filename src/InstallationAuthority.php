<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use Illuminate\Support\Facades\DB;

final class InstallationAuthority
{
    public const string KEY = 'installation';

    public static function current(?string $connection = null): AuthorityState
    {
        $authority = DB::connection($connection)
            ->table('bfc_authority')
            ->where('key', self::KEY)
            ->first(['mode', 'generation']);

        return is_object($authority)
            ? AuthorityState::fromRaw((string) $authority->mode, (int) $authority->generation)
            : AuthorityState::fromRaw('', 0);
    }

    public static function change(
        AuthorityState $expected,
        AuthorityMode $mode,
        ?string $connection = null,
    ): ?AuthorityState {
        if (! $expected->isValid()) {
            return null;
        }

        $database = DB::connection($connection);
        $changed = $database
            ->table('bfc_authority')
            ->where('key', self::KEY)
            ->where('mode', $expected->mode?->value)
            ->where('generation', $expected->generation)
            ->update([
                'mode' => $mode->value,
                'generation' => $database->raw('generation + 1'),
                'updated_at' => now(),
            ]);

        return $changed === 1
            ? AuthorityState::fromRaw($mode->value, $expected->generation + 1)
            : null;
    }
}
