<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Actions;

use Illuminate\Support\Facades\DB;

final readonly class PruneCredentialAuthorizations
{
    private const int BATCH_SIZE = 500;

    public function __invoke(): int
    {
        $deleted = 0;

        do {
            $batch = DB::transaction(function (): int {
                $cutoff = now()->subDay();
                $ids = DB::table('credential_authorizations')
                    ->where(function ($query) use ($cutoff): void {
                        $query->where(function ($live) use ($cutoff): void {
                            $live->whereIn('status', ['pending', 'approved'])
                                ->where('expires_at', '<=', $cutoff);
                        })->orWhere(function ($denied) use ($cutoff): void {
                            $denied->where('status', 'denied')
                                ->where('decided_at', '<=', $cutoff);
                        })->orWhere(function ($consumed) use ($cutoff): void {
                            $consumed->where('status', 'consumed')
                                ->where('consumed_at', '<=', $cutoff);
                        });
                    })
                    ->orderByRaw("CASE WHEN status IN ('pending', 'approved') THEN expires_at WHEN status = 'denied' THEN decided_at ELSE consumed_at END")
                    ->orderBy('id')
                    ->limit(self::BATCH_SIZE)
                    ->lockForUpdate()
                    ->pluck('id')
                    ->all();

                if ($ids === []) {
                    return 0;
                }

                return DB::table('credential_authorizations')->whereIn('id', $ids)->delete();
            });
            $deleted += $batch;
        } while ($batch === self::BATCH_SIZE);

        return $deleted;
    }
}
