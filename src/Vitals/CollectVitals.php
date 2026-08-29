<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Vitals;

use ArtisanBuild\BuiltForCloud\BuiltForCloud;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresHeadlineStat;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ConsoleVitals;
use ArtisanBuild\BuiltForCloud\MetadataShape;
use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Throwable;

/**
 * Assembles the vitals payload (Console PRD D9/D15).
 *
 * THE RULE THIS CLASS EXISTS TO KEEP: nothing it reads may turn a vitals
 * request into an error. Every dependency read is individually guarded,
 * a failed read contributes a null field and flips health to `degraded`,
 * and assembly continues. D9: a vN-1 or half-broken app "renders as
 * degraded-but-honest vitals, never an error — displaying skew is part of
 * the dashboard's job", and a vitals endpoint that 500s when the queue is
 * unreachable is exactly the thing that defeats a fleet dashboard.
 *
 * THE SECOND RULE, and the reason this class caches: the route it serves
 * is POLLED, up to sixty times a minute per credential. Work that is
 * merely acceptable once a request is not acceptable at that rate, so a
 * queue snapshot is shared by every poll inside a
 * `built-for-cloud.vitals.queue_cache_seconds` window, and the database
 * path takes ONE aggregate pass over the jobs table rather than the two
 * counts and a `min` an earlier revision ran (the failed-job count is a
 * separate query, on a separate table, either way). What the package
 * cannot do portably is impose a wall-clock deadline on the read itself,
 * and what the cache does NOT do is serialise concurrent misses — see
 * {@see self::queueSnapshot} for both.
 *
 * The audit append is deliberately NOT inside the first rule; it lives in
 * {@see ConsoleVitals}, is transactional, and is the one thing that can
 * fail this route. See that controller.
 */
final class CollectVitals
{
    /**
     * The default life of a cached queue snapshot. Long enough that a
     * one-second dashboard poll costs one read per fifteen, short enough
     * that a backlog forming is visible inside a render or two.
     */
    private const int DEFAULT_QUEUE_CACHE_SECONDS = 15;

    private const string CACHE_KEY = 'bfc:vitals:queue';

    /**
     * The version of the cached ARRAY SHAPE, not of the payload. It
     * bumps when {@see self::snapshotFrom}'s expectations change, so an
     * upgrade reads a new key instead of rejecting the old one on every
     * poll until it expires.
     */
    private const int CACHE_SHAPE_VERSION = 1;

    /**
     * @param  string|null  $statedContractVersion  the `api_version` the
     *                                              caller believes this
     *                                              app speaks, if it said
     *                                              (D9's vN-1 case)
     */
    public function __invoke(?string $statedContractVersion = null): VitalsPayload
    {
        $degraded = false;

        $appVersion = $this->appVersion($degraded);
        $deployedAt = $this->deployedAt($degraded);
        $queue = $this->queue($degraded);
        $headline = $this->headline($degraded);

        // Contract skew (D9's vN-1 row). A caller that states which
        // major it expects and is wrong gets an honest answer — this
        // app's REAL `api_version`, every other field it can fill, and
        // `degraded` — rather than a 406 or a 500. The dashboard needs
        // to render the skew, which it cannot do from an error.
        if ($statedContractVersion !== null
            && $statedContractVersion !== ''
            && $statedContractVersion !== (string) BuiltForCloud::API_VERSION) {
            $degraded = true;
        }

        // Computed BEFORE the payload is constructed: named arguments
        // evaluate in written order, and `health` is written first, so a
        // degradation raised while deriving the age would have been
        // computed after the health it must affect.
        $deployAgeSeconds = $deployedAt === null
            ? null
            : $this->age(CarbonImmutable::now()->getTimestamp() - $deployedAt->getTimestamp(), $degraded);

        return new VitalsPayload(
            apiVersion: BuiltForCloud::API_VERSION,
            bfcVersion: BuiltForCloud::VERSION,
            appVersion: $appVersion,
            health: Health::fromDegradation($degraded),
            deployedAt: $deployedAt?->toAtomString(),
            deployAgeSeconds: $deployAgeSeconds,
            queue: $queue,
            headline: $headline,
        );
    }

    /**
     * An age in seconds, or null when it falls outside the window this
     * payload will report ({@see VitalsPayload::MAX_AGE_SECONDS}) — a
     * deploy time from 1970, a corrupt `created_at`. Out of range is
     * `null` plus `degraded`, never a clamp: a clamped age is a wrong
     * number presented as a right one, and the schema's bound is read
     * from the same constant so producer and instrument cannot drift.
     *
     * Signed on purpose. A `deployed_at` in the future reports a
     * negative age rather than zero, because clock skew between the app
     * and the vendor is something an operator should see.
     */
    private function age(int $seconds, bool &$degraded): ?int
    {
        if (abs($seconds) > VitalsPayload::MAX_AGE_SECONDS) {
            $degraded = true;

            return null;
        }

        return $seconds;
    }

    /**
     * The app's own release, when it declares one AND the declaration
     * matches {@see MetadataShape::SEMVER} — the SAME pattern the
     * conformance instrument enforces on the wire, so a value this
     * endpoint would forward is never one the instrument would reject.
     * A declared-but-unusable value degrades: the app stated something
     * this endpoint refuses to forward, and silently reporting `null`
     * would look identical to declaring nothing at all.
     */
    private function appVersion(bool &$degraded): ?string
    {
        $declared = config('built-for-cloud.vitals.app_version');

        if ($declared === null || $declared === '') {
            return null;
        }

        if (is_string($declared) && MetadataShape::isSemver($declared)) {
            return $declared;
        }

        $degraded = true;

        return null;
    }

    /**
     * When this deployment last shipped, when the app declares it.
     * Unparseable is degraded for the same reason as `app_version`.
     */
    private function deployedAt(bool &$degraded): ?CarbonImmutable
    {
        $declared = config('built-for-cloud.vitals.deployed_at');

        if ($declared === null || $declared === '') {
            return null;
        }

        if (! is_string($declared)) {
            $degraded = true;

            return null;
        }

        try {
            return CarbonImmutable::parse($declared);
        } catch (Throwable) {
            $degraded = true;

            return null;
        }
    }

    /**
     * The backlog, from a cached snapshot.
     *
     * The snapshot carries its own degradation flag, so a poll served
     * from cache reports the same health as the poll that populated it —
     * a cache hit must not launder a failed read into an `ok`.
     */
    private function queue(bool &$degraded): QueueVitals
    {
        [$queue, $queueDegraded] = $this->queueSnapshot();

        if ($queueDegraded) {
            $degraded = true;
        }

        return $queue;
    }

    /**
     * The cached read, and the honest statement of what caching does and
     * does not do here. Three limits, all stated because an unstated one
     * reads as covered:
     *
     *  1. **It reduces frequency; it does not bound it.**
     *     `Cache::remember` is cache-aside, not a lock: concurrent
     *     misses each run the read and each write the result. In the
     *     steady state a window costs one read, which is the
     *     amplification that mattered — a dashboard polling once a
     *     second no longer puts a queue query on every request — but a
     *     burst arriving on a cold key runs the read once per concurrent
     *     request. Taking a lock would trade that for a new way for this
     *     route to fail or stall, on a route whose whole contract is
     *     that it does not.
     *  2. **It does not bound the DURATION of a read.** There is no
     *     portable wall-clock deadline across the drivers Laravel
     *     supports — a statement timeout is per-vendor SQL, and the
     *     queue drivers' `size()` calls take no timeout argument — so a
     *     genuinely hung dependency hangs the requests that miss the
     *     cache rather than every request. Bounding that properly is
     *     per-driver work this PR deliberately does not attempt.
     *  3. **A cache is not a trusted input.** Everything from the store
     *     is validated before use and the whole reconstruction happens
     *     inside the guard. An earlier revision read the cached members
     *     OUTSIDE the try, so a stale, malformed or colliding value
     *     turned a dependency problem into a 500 — breaking the one
     *     promise this class exists to keep. A value that does not
     *     validate is bypassed for a fresh read rather than trusted or
     *     reported.
     *
     * @return array{QueueVitals, bool}
     */
    private function queueSnapshot(): array
    {
        $seconds = config('built-for-cloud.vitals.queue_cache_seconds', self::DEFAULT_QUEUE_CACHE_SECONDS);
        $seconds = is_numeric($seconds) ? (int) $seconds : self::DEFAULT_QUEUE_CACHE_SECONDS;

        if ($seconds <= 0) {
            return $this->readQueue();
        }

        try {
            $cached = Cache::remember($this->cacheKey(), $seconds, function (): array {
                [$queue, $queueDegraded] = $this->readQueue();

                return [
                    'pending' => $queue->pending,
                    'reserved' => $queue->reserved,
                    'failed' => $queue->failed,
                    'oldest' => $queue->oldestPendingAgeSeconds,
                    'degraded' => $queueDegraded,
                ];
            });

            $snapshot = $this->snapshotFrom($cached);

            if ($snapshot !== null) {
                return $snapshot;
            }
        } catch (Throwable) {
            // A cache store that is itself unavailable must not become
            // the new failure mode.
        }

        return $this->readQueue();
    }

    /**
     * Rebuild a snapshot from whatever the cache handed back, or null
     * when that is not a snapshot this class wrote.
     *
     * Every member is checked: the four counts must be absent, null or
     * int, and the degradation flag must be a boolean. Nothing is cast.
     * A cached `"12"` is not a pending count — it is evidence that
     * something else owns this key — and a value that fails here is
     * bypassed rather than repaired, because repairing it would report a
     * number this deployment never read.
     *
     * @return array{QueueVitals, bool}|null
     */
    private function snapshotFrom(mixed $cached): ?array
    {
        if (! is_array($cached) || ! is_bool($cached['degraded'] ?? null)) {
            return null;
        }

        $counts = [];

        foreach (['pending', 'reserved', 'failed', 'oldest'] as $member) {
            $value = $cached[$member] ?? null;

            if ($value !== null && ! is_int($value)) {
                return null;
            }

            $counts[$member] = $value;
        }

        return [
            new QueueVitals(
                pending: $counts['pending'],
                reserved: $counts['reserved'],
                failed: $counts['failed'],
                oldestPendingAgeSeconds: $counts['oldest'],
            ),
            $cached['degraded'],
        ];
    }

    /**
     * The snapshot's cache key: versioned, and namespaced by the things
     * that change what a snapshot MEANS.
     *
     * A fixed global key was wrong in two ways at once. Two deployments
     * sharing a cache prefix — the same Redis with the same
     * `CACHE_PREFIX`, which is an ordinary staging arrangement — would
     * serve each other's backlogs. And changing the queue an app reads
     * would keep serving the previous queue's numbers until the window
     * expired. The version segment makes a future change to the cached
     * ARRAY SHAPE a new key rather than a value {@see self::snapshotFrom}
     * has to reject on every poll of the upgrade window.
     *
     * The namespace is a digest of the deployment identity and the
     * resolved queue configuration. It is a digest rather than the
     * values themselves so the key stays a bounded, printable string
     * whatever an operator put in those settings; none of the inputs is
     * a secret.
     */
    private function cacheKey(): string
    {
        $connection = config('queue.default');
        $connection = is_string($connection) ? $connection : '';

        $namespace = [
            (string) (config('built-for-cloud.cloud.application') ?? ''),
            (string) (config('built-for-cloud.product') ?? ''),
            app()->environment(),
            $connection,
            (string) (config('queue.connections.'.$connection.'.driver') ?? ''),
            (string) (config('queue.connections.'.$connection.'.connection') ?? ''),
            (string) (config('queue.connections.'.$connection.'.table') ?? ''),
        ];

        return self::CACHE_KEY.':v'.self::CACHE_SHAPE_VERSION.':'.hash('sha256', implode('|', $namespace));
    }

    /**
     * The uncached read. The `database` driver is the only one whose
     * numbers the package reads directly — it is the only one whose
     * storage the package can address without a driver-specific client —
     * so every other driver reports `pending` from the connection's own
     * `size()` and leaves the split and the enqueue age null. That is a
     * limitation, not a fault, and does not degrade health; a read that
     * THROWS does.
     *
     * @return array{QueueVitals, bool}
     */
    private function readQueue(): array
    {
        $degraded = false;

        $connection = config('queue.default');
        $connection = is_string($connection) ? $connection : '';
        $driver = config('queue.connections.'.$connection.'.driver');

        $failed = $this->attempt(fn (): ?int => $this->failedCount(), $degraded);

        if ($driver !== 'database') {
            return [
                new QueueVitals(
                    pending: $this->attempt(fn (): ?int => $this->connectionSize($connection), $degraded),
                    failed: $failed,
                ),
                $degraded,
            ];
        }

        $table = config('queue.connections.'.$connection.'.table');
        $table = is_string($table) && $table !== '' ? $table : 'jobs';
        $database = config('queue.connections.'.$connection.'.connection');
        $database = is_string($database) && $database !== '' ? $database : null;

        // ONE aggregate pass over the jobs table, not three. The earlier
        // revision ran two counts and a `min`, each its own scan, on
        // every poll of a route the vendor polls continuously.
        $row = $this->attemptRow(function () use ($database, $table): ?object {
            $aggregate = DB::connection($database)->table($table)->selectRaw(
                'sum(case when reserved_at is null then 1 else 0 end) as pending, '
                .'sum(case when reserved_at is null then 0 else 1 end) as reserved, '
                .'min(case when reserved_at is null then created_at else null end) as oldest'
            )->first();

            return $aggregate;
        }, $degraded);

        if ($row === null) {
            return [new QueueVitals(failed: $failed), $degraded];
        }

        $oldest = $row->oldest ?? null;

        return [
            new QueueVitals(
                pending: (int) ($row->pending ?? 0),
                reserved: (int) ($row->reserved ?? 0),
                failed: $failed,
                oldestPendingAgeSeconds: is_numeric($oldest)
                ? $this->age(CarbonImmutable::now()->getTimestamp() - (int) $oldest, $degraded)
                : null,
            ),
            $degraded,
        ];
    }

    /**
     * The failed-job count, when the app's failer can produce one.
     * A failer that cannot count is not a failure — it reports null and
     * leaves health alone; a failer that THROWS is caught by the
     * {@see self::attempt} wrapper around this call and degrades.
     */
    private function failedCount(): ?int
    {
        if (! app()->bound('queue.failer')) {
            return null;
        }

        $failer = app('queue.failer');

        if (! is_object($failer) || ! method_exists($failer, 'count')) {
            return null;
        }

        $count = $failer->count();

        return is_int($count) ? $count : null;
    }

    private function connectionSize(string $connection): ?int
    {
        if (! app()->bound('queue')) {
            return null;
        }

        $manager = app('queue');

        if (! is_object($manager) || ! method_exists($manager, 'connection')) {
            return null;
        }

        $queue = $manager->connection($connection === '' ? null : $connection);

        if (! is_object($queue) || ! method_exists($queue, 'size')) {
            return null;
        }

        return (int) $queue->size();
    }

    /**
     * The app's headline stat, or null — and null is by far the most
     * common honest answer.
     *
     * The vocabulary is a class CONSTANT naming an enum class
     * ({@see DeclaresHeadlineStat::HEADLINE_VOCABULARY},
     * {@see HeadlineLabel}), so both which vocabulary applies and what
     * is in it are settled at compile time, and nothing here has to
     * trust a runtime list. What this method still decides, because a
     * type cannot:
     *
     *  - the case belongs to the vocabulary this app DECLARED, not to
     *    some other enum that also implements the marker;
     *  - the vocabulary is at most {@see DeclaresHeadlineStat::MAX_LABELS}
     *    cases, and every case is backed by a bounded identifier;
     *  - the value is finite and within
     *    {@see VitalsPayload::MAX_HEADLINE_MAGNITUDE} — the same
     *    constant the conformance schema reads, so the bound cannot
     *    drift between the producer and the instrument;
     *  - a stat reported alongside NO declared vocabulary is refused.
     *
     * Each of those drops the headline AND degrades: the app asked for
     * something the contract forbids, and an operator should see that
     * rather than an absent field. Declaring no vocabulary and reporting
     * no stat is the ordinary case and degrades nothing.
     *
     * Everything runs inside the guard, because a declaration is app
     * code and may throw.
     */
    private function headline(bool &$degraded): ?HeadlineStat
    {
        $declaration = app(CredentialDeclaration::class);

        if (! $declaration instanceof DeclaresHeadlineStat) {
            return null;
        }

        try {
            $stat = $declaration->headlineStat();

            if ($stat === null) {
                return null;
            }

            $vocabulary = $declaration::HEADLINE_VOCABULARY;

            if ($vocabulary === null || ! enum_exists($vocabulary) || ! is_a($vocabulary, HeadlineLabel::class, true)) {
                $degraded = true;

                return null;
            }

            $cases = $vocabulary::cases();

            if ($cases === [] || count($cases) > DeclaresHeadlineStat::MAX_LABELS) {
                $degraded = true;

                return null;
            }

            foreach ($cases as $case) {
                if (! is_string($case->value) || ! MetadataShape::isToken($case->value)) {
                    $degraded = true;

                    return null;
                }
            }

            if (! $stat->label instanceof $vocabulary
                || ! is_finite((float) $stat->value)
                || abs((float) $stat->value) > VitalsPayload::MAX_HEADLINE_MAGNITUDE) {
                $degraded = true;

                return null;
            }
        } catch (Throwable) {
            $degraded = true;

            return null;
        }

        return $stat;
    }

    /**
     * @param  callable(): (int|null)  $read
     */
    private function attempt(callable $read, bool &$degraded): ?int
    {
        try {
            return $read();
        } catch (Throwable) {
            $degraded = true;

            return null;
        }
    }

    /**
     * @param  callable(): (object|null)  $read
     */
    private function attemptRow(callable $read, bool &$degraded): ?object
    {
        try {
            return $read();
        } catch (Throwable) {
            $degraded = true;

            return null;
        }
    }
}
