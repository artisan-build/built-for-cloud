<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Vitals;

use ArtisanBuild\BuiltForCloud\BuiltForCloud;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresHeadlineStat;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ConsoleVitals;
use Carbon\CarbonImmutable;
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
 * The audit append is deliberately NOT inside that rule; it lives in
 * {@see ConsoleVitals} and is transactional, because an unrecorded
 * vendor read is a different kind of failure. See that controller.
 */
final class CollectVitals
{
    /**
     * Semver, with the optional pre-release and build metadata parts.
     * An `app_version` that does not match is dropped rather than
     * echoed: the config key is operator-authored, and a
     * `metadata`-classified response cannot carry an unbounded string
     * (D15). This is the same reasoning that keeps `product` — and with
     * it `GET /bfc/meta` — on the `content` side of the classification.
     */
    private const string SEMVER = '/^(?=.{1,64}$)\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?(?:\+[0-9A-Za-z.]+)?$/D';

    /**
     * The shape every member of an app's declared headline vocabulary
     * must take. Deliberately the same bounded-identifier shape the
     * conformance assertion enforces on the wire, so a vocabulary that
     * would fail the assertion is refused before it can be reported.
     */
    private const string LABEL = '/^(?=.{1,64}$)[a-z0-9]+(?:[._:-][a-z0-9]+)*$/D';

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
     * The app's own release, when it declares one AND the declaration is
     * semver-shaped. A declared-but-unusable value degrades: the app
     * stated something this endpoint refuses to forward, and silently
     * reporting `null` would look identical to declaring nothing at all.
     */
    private function appVersion(bool &$degraded): ?string
    {
        $declared = config('built-for-cloud.vitals.app_version');

        if ($declared === null || $declared === '') {
            return null;
        }

        if (is_string($declared) && preg_match(self::SEMVER, $declared) === 1) {
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
     * The backlog. The `database` driver is the only one whose numbers
     * the package reads directly — it is the only one whose storage the
     * package can address without a driver-specific client — so every
     * other driver reports `pending` from the connection's own `size()`
     * and leaves the split and the enqueue age null. That is a
     * limitation, not a fault, and does not degrade health; a read that
     * THROWS does.
     */
    private function queue(bool &$degraded): QueueVitals
    {
        $connection = config('queue.default');
        $connection = is_string($connection) ? $connection : '';
        $driver = config('queue.connections.'.$connection.'.driver');

        $failed = $this->attempt(fn (): ?int => $this->failedCount(), $degraded);

        if ($driver !== 'database') {
            return new QueueVitals(
                pending: $this->attempt(fn (): ?int => $this->connectionSize($connection), $degraded),
                failed: $failed,
            );
        }

        $table = config('queue.connections.'.$connection.'.table');
        $table = is_string($table) && $table !== '' ? $table : 'jobs';
        $database = config('queue.connections.'.$connection.'.connection');
        $database = is_string($database) && $database !== '' ? $database : null;

        return new QueueVitals(
            pending: $this->attempt(fn (): int => DB::connection($database)->table($table)->whereNull('reserved_at')->count(), $degraded),
            reserved: $this->attempt(fn (): int => DB::connection($database)->table($table)->whereNotNull('reserved_at')->count(), $degraded),
            failed: $failed,
            oldestPendingAgeSeconds: $this->attempt(function () use ($database, $table): ?int {
                $oldest = DB::connection($database)->table($table)->whereNull('reserved_at')->min('created_at');

                return is_numeric($oldest) ? CarbonImmutable::now()->getTimestamp() - (int) $oldest : null;
            }, $degraded),
        );
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
     * Four things drop the headline. Declaring no vocabulary, and
     * reporting no stat, are ordinary: health is untouched. Reporting a
     * stat the app's OWN declaration does not permit is not: a label
     * outside the vocabulary, a vocabulary member that is not a bounded
     * identifier, or a non-finite value each degrade, because the app
     * asked for something the contract forbids and the operator should
     * see that rather than an absent field.
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

            $vocabulary = $declaration->headlineLabels();
        } catch (Throwable) {
            $degraded = true;

            return null;
        }

        foreach ($vocabulary as $label) {
            if (preg_match(self::LABEL, $label) !== 1) {
                $degraded = true;

                return null;
            }
        }

        if (! in_array($stat->label, $vocabulary, true) || ! is_finite((float) $stat->value)) {
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
}
