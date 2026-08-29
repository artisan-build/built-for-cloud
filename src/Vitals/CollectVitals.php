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
 * merely acceptable once a request is not acceptable at that rate, so the
 * queue block is read at most once per
 * `built-for-cloud.vitals.queue_cache_seconds` and shared by every poll
 * inside that window, and the database path takes ONE aggregate pass over
 * the jobs table rather than the two counts and a `min` an earlier
 * revision ran (the failed-job count is a separate query, on a separate
 * table, either way). What the package cannot do portably is impose a
 * wall-clock deadline on the read itself — see
 * {@see self::queueSnapshot}.
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

        return new VitalsPayload(
            apiVersion: BuiltForCloud::API_VERSION,
            bfcVersion: BuiltForCloud::VERSION,
            appVersion: $appVersion,
            health: Health::fromDegradation($degraded),
            deployedAt: $deployedAt?->toAtomString(),
            deployAgeSeconds: $deployedAt === null ? null : CarbonImmutable::now()->getTimestamp() - $deployedAt->getTimestamp(),
            queue: $queue,
            headline: $headline,
        );
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
     * does not bound here.
     *
     * IT BOUNDS FREQUENCY, and that is the amplification that mattered: a
     * dashboard polling once a second no longer puts a queue query (or a
     * redis/sqs round trip) on every request. It does NOT bound the
     * DURATION of the one read per window. There is no portable way to
     * impose a wall-clock deadline across the drivers Laravel supports —
     * a statement timeout is per-vendor SQL, and the queue drivers'
     * `size()` calls carry no timeout argument — so a genuinely hung
     * dependency will hang one request per window rather than every
     * request. Bounding that properly is a per-driver piece of work and
     * is deliberately not attempted here; the cap on how often it can
     * happen is what this PR carries.
     *
     * A cache store that is itself unavailable must not become the new
     * failure mode, so a throwing cache falls through to reading
     * directly.
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
            /** @var array{pending: int|null, reserved: int|null, failed: int|null, oldest: int|null, degraded: bool} $cached */
            $cached = Cache::remember(self::CACHE_KEY, $seconds, function (): array {
                [$queue, $queueDegraded] = $this->readQueue();

                return [
                    'pending' => $queue->pending,
                    'reserved' => $queue->reserved,
                    'failed' => $queue->failed,
                    'oldest' => $queue->oldestPendingAgeSeconds,
                    'degraded' => $queueDegraded,
                ];
            });
        } catch (Throwable) {
            return $this->readQueue();
        }

        return [
            new QueueVitals(
                pending: $cached['pending'],
                reserved: $cached['reserved'],
                failed: $cached['failed'],
                oldestPendingAgeSeconds: $cached['oldest'],
            ),
            $cached['degraded'],
        ];
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
                oldestPendingAgeSeconds: is_numeric($oldest) ? CarbonImmutable::now()->getTimestamp() - (int) $oldest : null,
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
     * The vocabulary is an ENUM CLASS ({@see HeadlineLabel}), so its
     * membership is settled at compile time and nothing here has to
     * trust a runtime list. What this method still decides, because a
     * type cannot:
     *
     *  - the case belongs to the vocabulary this app DECLARED, not to
     *    some other enum that also implements the marker;
     *  - the vocabulary is at most {@see DeclaresHeadlineStat::MAX_LABELS}
     *    cases, and every case is backed by a bounded identifier;
     *  - the value is finite;
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

            $vocabulary = $declaration->headlineVocabulary();

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

            if (! $stat->label instanceof $vocabulary || ! is_finite((float) $stat->value)) {
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
