<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Commands;

use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\Exceptions\HmacKeyUnreadable;
use ArtisanBuild\BuiltForCloud\Hmac\HmacKeyring;
use ArtisanBuild\BuiltForCloud\Hmac\HmacWriterBarrier;
use ArtisanBuild\BuiltForCloud\ManagedClientSecretStore;
use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\FileStore;
use Illuminate\Cache\Lock;
use Illuminate\Contracts\Cache\Lock as LockContract;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\Cache;

/**
 * Stage 3 of the APP_KEY rotation over the hmac store (SEC-V3-08): after
 * the read-keyring is deployed everywhere (old key in APP_PREVIOUS_KEYS)
 * and the write-primary switched (new APP_KEY), this command re-encrypts
 * every hmac ciphertext under the write-primary and updates its
 * key-version. It touches EVERY row that carries a ciphertext —
 * active, pending, in-grace, even revoked and expired — because a row
 * whose ciphertext outlives its ring key is fossilized forever.
 *
 * LOCKED: a cache lock admits one run at a time and a database row lock
 * fences every ciphertext commit — a second concurrent invocation
 * refuses or waits behind the commit fence. RESTARTABLE: the rows themselves
 * are the cursor (each is either on the write-primary version or not), so
 * a graceful failed run keeps completed rows while a crashed transaction
 * rolls its current sweep back for the next run; nothing is lost or
 * double-processed. Each row's update is guarded
 * on the version that was read, so a concurrent re-key (the exchange's
 * re-claim writes under the write-primary already) is never clobbered.
 *
 * COMPLETION IS GATED on verify-zero-old-version-rows: the command exits
 * successfully only when NO hmac ciphertext carries a non-primary
 * version — and, since P1 custody, neither does the managed client
 * secret row, which this sweep re-encrypts under the same discipline.
 * Until then the cutover is in progress and hmac activation and
 * rotation stay paused ({@see HmacKeyring::cutoverInProgress()}). A row
 * whose key-version names no ring key is reported BY ID and fails the
 * run — restore the old key to APP_PREVIOUS_KEYS rather than dropping
 * ciphertexts.
 *
 * Output carries ids, versions and counts only — never key material,
 * plaintext or ciphertext.
 */
final class HmacRewrapCommand extends SystemAuthorityCommand
{
    protected $signature = 'bfc:hmac:rewrap
        {--chunk=100 : Rows re-encrypted per batch}';

    protected $description = 'Re-encrypt every hmac signing key under the current APP_KEY (locked, restartable); succeeds only at zero old-version rows';

    /**
     * The lock lease is {@see LOCK_SECONDS} and is REFRESHED every batch,
     * so a long sweep never outlives it while a killed run still frees
     * the lock by expiry.
     */
    private const int LOCK_SECONDS = 600;

    public function handle(HmacKeyring $keyring, HmacWriterBarrier $barrier): int
    {
        // The lock is only as exclusive as the cache store is SHARED: an
        // instance-local store (array, file) cannot exclude a concurrent
        // run on another instance — warn loudly rather than pretend.
        $store = Cache::getStore();

        if ($store instanceof ArrayStore || $store instanceof FileStore) {
            $this->warn(sprintf(
                'The default cache store (%s) is instance-local: this lock cannot exclude concurrent rewrap runs '
                .'on OTHER instances. In a multi-instance deployment, point the default cache at a shared store '
                .'(redis, memcached, database) before rewrapping.',
                $store::class,
            ));
        }

        // THE LOCK DISCIPLINE (see {@see HmacWriterBarrier}): this is the
        // same cache lock and database fence every ciphertext writer
        // takes around its check+write+commit. This run holds both from before the first
        // re-encryption THROUGH the final verify-zero-old-version-rows
        // count (released only in the finally below, after rewrap()
        // returns) — so while the completion verification runs, no writer
        // anywhere is between its version check and its commit, and the
        // zero-count is authoritative.
        $lock = Cache::lock(HmacWriterBarrier::LOCK, self::LOCK_SECONDS);

        if (! $lock->get()) {
            $this->error('Another rewrap run (or an in-flight hmac ciphertext write) holds the lock; only one holder at a time. Retry shortly.');

            return self::FAILURE;
        }

        try {
            return $barrier->withDatabaseFence(fn (): int => $this->rewrap($keyring, $lock));
        } finally {
            $lock->release();
        }
    }

    private function rewrap(HmacKeyring $keyring, LockContract $lock): int
    {
        $writeVersion = $keyring->writeVersion();
        $chunk = max(1, (int) $this->option('chunk'));
        $rewrapped = 0;

        /** @var array<string, string> $unreadable credential id => failure */
        $unreadable = [];

        while (true) {
            // A long sweep must not outlive its lease: renew per batch —
            // and if the renewal says ownership is LOST (the lease
            // expired and someone else took the lock), ABORT the sweep
            // immediately: continuing to write without the lock is
            // exactly the overlap the lock exists to forbid. The rows
            // already crossed stay crossed; a re-run resumes. Every
            // framework store's lock is an Illuminate\Cache\Lock, which
            // has refresh() from laravel/framework v13.16.0 — the floor
            // this package requires. A lock from outside that hierarchy
            // is not renewed at all: it keeps its original lease and the
            // sweep runs on without renewal.
            if ($lock instanceof Lock) {
                if (! $lock->refresh(self::LOCK_SECONDS)) {
                    $this->error(
                        'The rewrap lock lease could not be renewed — ownership was lost mid-sweep. Aborting so two '
                        .'sweeps can never overlap; progress is kept, re-run bfc:hmac:rewrap to resume.',
                    );

                    return self::FAILURE;
                }
            }

            /** @var list<Credential> $rows */
            $rows = $this->oldVersionRows($writeVersion)
                ->when($unreadable !== [], fn ($query) => $query->whereKeyNot(array_keys($unreadable)))
                ->orderBy('id')
                ->limit($chunk)
                ->get()
                ->all();

            if ($rows === []) {
                break;
            }

            foreach ($rows as $row) {
                try {
                    $plaintext = $keyring->decrypt((string) $row->secret_ciphertext, $row->secret_key_version);
                } catch (HmacKeyUnreadable $failure) {
                    $unreadable[$row->id] = $failure->getMessage();

                    continue;
                }

                $encrypted = $keyring->encrypt($plaintext);

                // Guarded on the version this run READ: if the row was
                // re-keyed concurrently (already under the write-primary),
                // zero rows match and the fresher write stands.
                $rewrapped += Credential::query()
                    ->whereKey($row->id)
                    ->where(function ($query) use ($row): void {
                        $row->secret_key_version === null
                            ? $query->whereNull('secret_key_version')
                            : $query->where('secret_key_version', $row->secret_key_version);
                    })
                    ->update([
                        'secret_ciphertext' => $encrypted->ciphertext,
                        'secret_key_version' => $encrypted->keyVersion,
                    ]);
            }
        }

        $this->line(sprintf('%d hmac row(s) re-encrypted under key-version %s.', $rewrapped, $writeVersion));

        foreach ($unreadable as $id => $message) {
            $this->error(sprintf('Credential %s could not be re-encrypted: %s', $id, $message));
        }

        // The managed client secret rides the same staged cutover (P1
        // custody): the singleton row is swept like any hmac ciphertext
        // and counted by the same completion gate, so APP_PREVIOUS_KEYS
        // may not drop the old key while it is still the only thing
        // that can open the enrolment secret.
        $this->rewrapManagedClientSecret($keyring, $writeVersion);

        // The completion gate: verify ZERO old-version rows, freshly
        // counted — completion is a verified state, never an assumption.
        $hmacRemaining = $this->oldVersionRows($writeVersion)->count();
        $managedRemaining = app(ManagedClientSecretStore::class)->oldVersionRow($writeVersion) !== null;

        if ($hmacRemaining > 0) {
            $this->error(sprintf(
                '%d hmac row(s) still carry a non-primary key-version: the cutover is NOT complete, and hmac '
                .'activation/rotation stay paused. Fix the ring (see above) and run bfc:hmac:rewrap again.',
                $hmacRemaining,
            ));
        }

        if ($managedRemaining) {
            $this->error('The managed client secret still carries a non-primary key-version: the cutover is NOT '
                .'complete. Restore the old key to APP_PREVIOUS_KEYS rather than deleting the enrolment secret, '
                .'then run bfc:hmac:rewrap again.');
        }

        if ($hmacRemaining > 0 || $managedRemaining) {
            return self::FAILURE;
        }

        $this->info('Verified zero old-version rows: the APP_KEY cutover over the hmac store is complete. APP_PREVIOUS_KEYS may now drop the old key.');

        return self::SUCCESS;
    }

    /**
     * @return Builder<Credential>
     */
    private function oldVersionRows(string $writeVersion)
    {
        return Credential::query()
            ->where('kind', CredentialKind::Hmac->value)
            ->whereNotNull('secret_ciphertext')
            ->where(function ($query) use ($writeVersion): void {
                $query->whereNull('secret_key_version')
                    ->orWhere('secret_key_version', '!=', $writeVersion);
            });
    }

    /**
     * Sweep the singleton managed client secret row (P1 custody): it is
     * re-encrypted exactly like an hmac ciphertext — decrypt by the
     * version the row carries, re-encrypt under the write-primary,
     * update guarded on the version this run READ so a concurrent
     * rotation's fresher ciphertext is never clobbered. An unreadable
     * row is reported and left in place: restore the ring rather than
     * deleting the enrolment secret. Output carries versions only —
     * never key material, plaintext or ciphertext.
     */
    private function rewrapManagedClientSecret(HmacKeyring $keyring, string $writeVersion): void
    {
        $row = app(ManagedClientSecretStore::class)->oldVersionRow($writeVersion);

        if ($row === null) {
            return;
        }

        try {
            $plaintext = $keyring->decrypt($row->secret_ciphertext, $row->secret_key_version);
        } catch (HmacKeyUnreadable $failure) {
            $this->error(sprintf('The managed client secret could not be re-encrypted: %s', $failure->getMessage()));

            return;
        }

        app(ManagedClientSecretStore::class)->rewrap($row->secret_key_version, $keyring->encrypt($plaintext));

        $this->line(sprintf('Managed client secret re-encrypted under key-version %s.', $writeVersion));
    }
}
