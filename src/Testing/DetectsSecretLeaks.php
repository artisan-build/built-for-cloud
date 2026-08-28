<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use Illuminate\Cache\Events\KeyWritten;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Log\Events\MessageLogged;
use Illuminate\Queue\Queue;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Assert;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * The negative-leakage harness (D7 plaintext containment, PRD 1.8): assert
 * that a secret marker never escapes into any observable channel while an
 * action runs. Every later secret-producing surface (claim codes, mint
 * verbs, rotation, hmac) asserts with this trait.
 *
 * Channels watched by assertNoSecretLeakage() — or the lower-level
 * beginLeakWatch()/assertNoLeaks() pair:
 *
 * - **log** — every record (message + context) logged during the action.
 * - **database** — every INSERT/UPDATE binding during the action, plus a
 *   post-action sweep of every table's stored values. A value that is
 *   exactly `hash('sha256', marker)` is allowed: the hash is the intended
 *   at-rest form and is not a secret.
 * - **queue** — every queued payload (the serialized job body) created
 *   during the action, on any driver including sync.
 * - **cache** — every value written to the cache during the action.
 * - **session** — the entire session payload after the action.
 *
 * Per-artifact helpers cover the channels that live on an object rather
 * than a side effect: assertResponseCarriesNoSecret (body + headers),
 * assertConsoleOutputCarriesNoSecret, assertExceptionCarriesNoSecret
 * (message, rendered trace, context, previous chain).
 *
 * Failure messages name the leaking channel in square brackets and redact
 * the marker itself. No global state bleeds between tests: hooks are
 * registered per application instance, and the one process-static hook
 * (queue payload capture) is cleared when the application is torn down.
 *
 * Future (later PRs): the TTY-delivery commands, where printing once IS the
 * delivery, will need an explicit reveal-once console allowance
 * (an assertConsoleRevealsOnce-style helper). Deliberately not built until
 * those commands exist — this trait only asserts absence.
 */
trait DetectsSecretLeaks
{
    private ?string $leakWatchMarker = null;

    private bool $leakWatchActive = false;

    private bool $leakWatchHooksRegistered = false;

    /** @var list<array{channel: string, detail: string}> */
    private array $observedLeaks = [];

    /** @var list<string> */
    private array $watchedLogRecords = [];

    /** @var list<array{sql: string, bindings: list<mixed>}> */
    private array $watchedDatabaseWrites = [];

    /** @var list<string> */
    private array $watchedQueuePayloads = [];

    /** @var list<array{key: string, value: string}> */
    private array $watchedCacheWrites = [];

    /**
     * Watch every channel while the action runs, then assert the marker
     * escaped into none of them. Returns whatever the action returns.
     */
    public function assertNoSecretLeakage(string $marker, callable $act): mixed
    {
        $this->beginLeakWatch($marker);

        $result = $act();

        $this->assertNoLeaks();

        return $result;
    }

    public function beginLeakWatch(string $marker): void
    {
        $this->leakWatchMarker = $marker;
        $this->leakWatchActive = true;
        $this->observedLeaks = [];
        $this->watchedLogRecords = [];
        $this->watchedDatabaseWrites = [];
        $this->watchedQueuePayloads = [];
        $this->watchedCacheWrites = [];

        $this->registerLeakWatchHooks();
    }

    public function assertNoLeaks(): void
    {
        if (! $this->leakWatchActive || $this->leakWatchMarker === null) {
            Assert::fail('assertNoLeaks() was called without a beginLeakWatch().');
        }

        $marker = $this->leakWatchMarker;

        // Stop capturing before the sweep so the sweep's own SELECTs and any
        // teardown noise are not recorded as action-time writes.
        $this->leakWatchActive = false;

        foreach ($this->watchedLogRecords as $record) {
            if (str_contains($record, $marker)) {
                $this->recordLeak('log', 'a log record carried the marker: '.$record, $marker);
            }
        }

        foreach ($this->watchedDatabaseWrites as $write) {
            if (str_contains($write['sql'], $marker)) {
                $this->recordLeak('database', 'a write statement carried the marker inline: '.$write['sql'], $marker);
            }

            foreach ($write['bindings'] as $binding) {
                if (! is_string($binding) || $binding === hash('sha256', $marker)) {
                    continue;
                }

                if (str_contains($binding, $marker)) {
                    $this->recordLeak('database', 'a write binding carried the marker ('.$write['sql'].')', $marker);
                }
            }
        }

        $this->sweepDatabaseAtRest($marker);

        foreach ($this->watchedQueuePayloads as $payload) {
            if (str_contains($payload, $marker)) {
                $this->recordLeak('queue', 'a queued payload carried the marker: '.$payload, $marker);
            }
        }

        foreach ($this->watchedCacheWrites as $write) {
            if (str_contains($write['key'], $marker) || str_contains($write['value'], $marker)) {
                $this->recordLeak('cache', 'the cache write for key "'.$write['key'].'" carried the marker', $marker);
            }
        }

        $session = $this->stringifyForLeakScan(session()->all());

        if (str_contains($session, $marker)) {
            $this->recordLeak('session', 'the session payload carried the marker: '.$session, $marker);
        }

        $lines = array_map(
            static fn (array $leak): string => '['.$leak['channel'].'] '.$leak['detail'],
            $this->observedLeaks,
        );

        Assert::assertSame([], $lines, "The secret marker escaped:\n".implode("\n", $lines));
    }

    /**
     * The response-channel helper: the body and every header carry no
     * marker.
     *
     * @param  TestResponse<Response>  $response
     */
    public function assertResponseCarriesNoSecret(TestResponse $response, string $marker): void
    {
        $leaks = [];

        $content = $response->getContent();

        if (is_string($content) && str_contains($content, $marker)) {
            $leaks[] = '[response] the response body carried the marker';
        }

        foreach ($response->headers->all() as $name => $values) {
            foreach ($values as $value) {
                if (is_string($value) && str_contains($value, $marker)) {
                    $leaks[] = '[response] the "'.$name.'" header carried the marker';
                }
            }
        }

        Assert::assertSame([], $leaks, "The secret marker escaped:\n".implode("\n", $leaks));
    }

    /**
     * The console-channel helper: captured artisan output carries no
     * marker. Plain absence only — the reveal-once allowance for the
     * TTY-delivery commands of later PRs is deliberately not built yet.
     */
    public function assertConsoleOutputCarriesNoSecret(string $output, string $marker): void
    {
        Assert::assertFalse(
            str_contains($output, $marker),
            'The secret marker escaped: [console] the captured command output carried the marker.',
        );
    }

    /**
     * The exception-channel helper: the message, rendered form (trace
     * included), Laravel log context, and the entire previous chain carry
     * no marker.
     */
    public function assertExceptionCarriesNoSecret(Throwable $exception, string $marker): void
    {
        $leaks = [];

        $current = $exception;
        $depth = 0;

        while ($current !== null && $depth < 16) {
            $rendered = $current->getMessage()."\n".$current;

            if (method_exists($current, 'context')) {
                $rendered .= "\n".$this->stringifyForLeakScan($current->context());
            }

            if (str_contains($rendered, $marker)) {
                $leaks[] = '[exception] a '.$current::class.' at chain depth '.$depth.' carried the marker';
            }

            $current = $current->getPrevious();
            $depth++;
        }

        Assert::assertSame([], $leaks, "The secret marker escaped:\n".implode("\n", $leaks));
    }

    private function registerLeakWatchHooks(): void
    {
        if ($this->leakWatchHooksRegistered) {
            return;
        }

        $this->leakWatchHooksRegistered = true;

        Event::listen(MessageLogged::class, function (MessageLogged $event): void {
            if ($this->leakWatchActive) {
                $this->watchedLogRecords[] = $event->message.' '.$this->stringifyForLeakScan($event->context);
            }
        });

        Event::listen(KeyWritten::class, function (KeyWritten $event): void {
            if ($this->leakWatchActive) {
                $this->watchedCacheWrites[] = [
                    'key' => (string) $event->key,
                    'value' => $this->stringifyForLeakScan($event->value),
                ];
            }
        });

        DB::listen(function (QueryExecuted $query): void {
            if (! $this->leakWatchActive) {
                return;
            }

            if (preg_match('/^\s*(insert|update|replace)\b/i', $query->sql) !== 1) {
                return;
            }

            $this->watchedDatabaseWrites[] = [
                'sql' => $query->sql,
                'bindings' => array_values($query->bindings),
            ];
        });

        // The payload hook is the one process-static registration (it is
        // how sync-driver payloads are observable at all), so it is cleared
        // with the application.
        Queue::createPayloadUsing(function (?string $connection, ?string $queue, array $payload): array {
            if ($this->leakWatchActive) {
                $this->watchedQueuePayloads[] = $this->stringifyForLeakScan($payload);
            }

            return [];
        });

        $this->beforeApplicationDestroyed(function (): void {
            Queue::createPayloadUsing(null);
            $this->leakWatchActive = false;
            $this->leakWatchHooksRegistered = false;
        });
    }

    /**
     * Sweep every stored value of every table for the marker — the at-rest
     * complement to the write listener. Values that are exactly the
     * marker's sha256 are the intended at-rest form and pass.
     */
    private function sweepDatabaseAtRest(string $marker): void
    {
        $allowedHash = hash('sha256', $marker);

        foreach (Schema::getTableListing(schemaQualified: false) as $table) {
            foreach (DB::table($table)->get() as $row) {
                foreach ((array) $row as $column => $value) {
                    if (! is_string($value) || $value === $allowedHash) {
                        continue;
                    }

                    if (str_contains($value, $marker)) {
                        $this->recordLeak('database', 'the stored value in '.$table.'.'.$column.' carried the marker', $marker);
                    }
                }
            }
        }
    }

    private function recordLeak(string $channel, string $detail, string $marker): void
    {
        $redacted = str_replace($marker, '[REDACTED-SECRET-MARKER]', $detail);

        if (mb_strlen($redacted) > 300) {
            $redacted = mb_substr($redacted, 0, 300).'…';
        }

        $this->observedLeaks[] = ['channel' => $channel, 'detail' => $redacted];
    }

    private function stringifyForLeakScan(mixed $value): string
    {
        if (is_string($value)) {
            return $value;
        }

        try {
            return serialize($value);
        } catch (Throwable) {
            return (string) json_encode($value, JSON_PARTIAL_OUTPUT_ON_ERROR);
        }
    }
}
