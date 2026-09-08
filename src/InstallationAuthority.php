<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use InvalidArgumentException;

/**
 * @property string $key
 * @property string $mode
 * @property int $generation
 */
final class InstallationAuthority extends Model
{
    public const string KEY = 'installation';

    protected $table = 'bfc_authority';

    protected $primaryKey = 'key';

    public $incrementing = false;

    protected $keyType = 'string';

    /** @var list<string> */
    protected $guarded = [];

    protected static function booted(): void
    {
        self::saving(function (self $authority): void {
            if ($authority->key !== self::KEY
                || AuthorityMode::tryFrom($authority->mode) === null
                || $authority->generation < 1) {
                throw new InvalidArgumentException('The installation authority record is invalid.');
            }

            if ($authority->exists && $authority->isDirty('generation')) {
                $original = (int) $authority->getOriginal('generation');

                if ($authority->generation <= $original) {
                    throw new InvalidArgumentException('Authority generation must increase monotonically.');
                }
            }
        });
    }

    public static function current(?string $connection = null): AuthorityState
    {
        $authority = self::onConnection($connection)->whereKey(self::KEY)->first();

        return $authority instanceof self
            ? AuthorityState::fromRaw($authority->mode, $authority->generation)
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

        $changed = self::onConnection($connection)
            ->whereKey(self::KEY)
            ->where('mode', $expected->mode?->value)
            ->where('generation', $expected->generation)
            ->update([
                'mode' => $mode->value,
                'generation' => DB::raw('generation + 1'),
                'updated_at' => now(),
            ]);

        return $changed === 1 ? self::current($connection) : null;
    }

    /** @return Builder<self> */
    private static function onConnection(?string $connection): Builder
    {
        $authority = new self;
        $authority->setConnection($connection);

        return $authority->newQuery();
    }

    /** @return array<string, string> */
    protected function casts(): array
    {
        return ['generation' => 'integer'];
    }
}
