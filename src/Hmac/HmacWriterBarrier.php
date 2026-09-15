<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Hmac;

use ArtisanBuild\BuiltForCloud\Exceptions\RewrapInProgress;
use Closure;
use Illuminate\Contracts\Cache\LockTimeoutException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

/**
 * The mutual exclusion between hmac ciphertext WRITERS and the rewrap's
 * completion verification (SEC-V3-08, rework Fix 1).
 *
 * THE LOCK DISCIPLINE, stated once: `bfc:hmac:rewrap` is one shared-cache
 * refusal lock and `bfc_hmac_writer_barriers:rewrap` is the database
 * commit fence. The rewrap command holds both for its ENTIRE run —
 * acquired before the first re-encryption and released only AFTER the
 * final verify-zero-old-version-rows count — and every ciphertext-
 * producing verb (hmac mint, hmac rotation's replacement mint, the
 * exchange redelivery re-key) runs its check AND its write AND its
 * transaction COMMIT while holding the same lock. A version check alone
 * cannot close the race: a writer on a lagging old-primary instance
 * could pass `cutoverInProgress()` before the sweep, and commit its
 * old-version row after the zero-count had already authorized dropping
 * the old key. The cache lease gives fast retry-later behavior, while the
 * database row lock is crash-releasing and cannot expire before the outer
 * transaction commits. The zero-count is therefore authoritative even if
 * a writer outlives its cache lease.
 *
 * Writers hold the lock only for the duration of one verb (seconds), so
 * they block each other briefly and block the rewrap's start briefly;
 * the rewrap holds it for the whole sweep, so a writer that cannot
 * acquire within the block window treats it as "rewrap in progress" and
 * refuses retry-later. The lock is only as exclusive as the cache store
 * is shared — the rewrap command warns on instance-local stores.
 */
final class HmacWriterBarrier
{
    public const string LOCK = 'bfc:hmac:rewrap';

    public const string FENCE_TABLE = 'bfc_hmac_writer_barriers';

    public const string FENCE_NAME = 'rewrap';

    /**
     * A writer's lease: generous for one verb's transaction, short
     * enough that a writer killed mid-hold frees the lock quickly.
     */
    private const int WRITER_LOCK_SECONDS = 30;

    /**
     * How long a writer waits out OTHER writers before concluding the
     * long-holding rewrap has the lock.
     */
    private const int BLOCK_SECONDS = 3;

    public function __construct(private readonly HmacKeyring $keyring) {}

    /**
     * The mint/rotate shape: refuse while a rewrap run holds the lock OR
     * the store is mid-cutover (mixed key-versions), and otherwise run
     * the write — its whole transaction — under the lock.
     *
     * @template TReturn
     *
     * @param  Closure(): TReturn  $write
     * @return TReturn
     */
    public function exclusive(string $verb, Closure $write): mixed
    {
        return $this->locked(
            write: function () use ($verb, $write): mixed {
                if ($this->keyring->cutoverInProgress()) {
                    throw RewrapInProgress::refusing($verb);
                }

                return $write();
            },
            onBusy: static fn (): mixed => throw RewrapInProgress::refusing($verb),
        );
    }

    /**
     * The lock alone — serialization with a running rewrap, without the
     * mid-cutover refusal. The exchange delivery path uses this: a FIRST
     * delivery writes no ciphertext and stays allowed mid-cutover, while
     * its transaction still must not straddle the rewrap's verification
     * (a concurrent exchange can turn it into a re-key after the
     * pre-read); the re-key branch keeps its own in-transaction
     * mid-cutover refusal.
     *
     * @template TReturn
     *
     * @param  Closure(): TReturn  $write
     * @param  Closure(): TReturn  $onBusy
     * @return TReturn
     */
    public function locked(Closure $write, Closure $onBusy): mixed
    {
        $lock = Cache::lock(self::LOCK, self::WRITER_LOCK_SECONDS);

        try {
            $lock->block(self::BLOCK_SECONDS);
        } catch (LockTimeoutException) {
            return $onBusy();
        }

        try {
            return $this->withDatabaseFence($write);
        } finally {
            $lock->release();
        }
    }

    /**
     * @template TReturn
     *
     * @param  Closure(): TReturn  $write
     * @return TReturn
     */
    public function withDatabaseFence(Closure $write): mixed
    {
        return DB::transaction(function () use ($write): mixed {
            DB::table(self::FENCE_TABLE)
                ->where('name', self::FENCE_NAME)
                ->lockForUpdate()
                ->sole();

            return $write();
        });
    }
}
