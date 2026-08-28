<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use Illuminate\Cache\Events\KeyWritten;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Log\Events\MessageLogged;
use Illuminate\Queue\Events\JobProcessing;
use Illuminate\Queue\Events\JobQueued;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Testing\Fakes\QueueFake;
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
 * assertNoSecretLeakage() — or the lower-level beginLeakWatch() /
 * assertNoLeaks() pair — watches exactly five SIDE-EFFECT channels:
 *
 * - **log** — every record (message + context) logged during the action.
 * - **database** — write statements captured during the action, plus a
 *   post-action sweep of every table's stored values. The write listener
 *   recognizes INSERT/UPDATE/REPLACE statements (Eloquent's write shapes);
 *   data-modifying CTEs, stored procedures and raw PDO writes are out of
 *   its scope — whatever they land in a table is still caught by the
 *   at-rest sweep, but their in-flight bindings are not observed. A value
 *   that is exactly `hash('sha256', marker)` is allowed: the hash is the
 *   intended at-rest form and is not a secret.
 * - **queue** — the real enqueued artifact: the payload of every JobQueued
 *   event, the raw body of every job that starts processing (the sync
 *   driver's observable point), the serialized form of the job object
 *   itself (clone effects included), and — when the Queue facade is faked
 *   — a finalization sweep over the fake's pushed jobs. `Queue::fakeFor()`
 *   is out of scope (Laravel restores the real manager before
 *   finalization — use `Queue::fake()`), and `pushRaw` payloads are not
 *   swept.
 * - **cache** — every value written to the cache during the action.
 * - **session** — the entire session payload after the action.
 *
 * Channels that live on an object rather than a side effect are the named
 * separate helpers, NOT part of assertNoSecretLeakage():
 * assertResponseCarriesNoSecret (body + headers),
 * assertConsoleOutputCarriesNoSecret, and assertExceptionCarriesNoSecret
 * (message, rendered trace, context, previous chain).
 *
 * Every captured string is scanned for the marker in each RECOVERABLE
 * form, not just the literal bytes: plain substring, URL-decoded,
 * JSON-unescaped (every escape, surrogate pairs included), and base64 —
 * base64-alphabet runs are decoded (tolerating prefix junk, MIME
 * wrapping, and one nested base64 level) and their bytes scanned, which
 * is what catches a logged `Basic base64(user:secret)` header whatever
 * the prefix alignment. These are the COMMON ACCIDENTAL encodings,
 * because the threat model is accidental egress — deliberate obfuscation
 * (hex, compression, custom encodings) is outside this harness's scope.
 * Failures name the channel in square brackets, name the form that
 * matched, and redact the marker and its recoverable encodings.
 *
 * If the watched action throws, recording still stops and the captured
 * channels are still asserted: a leak fails the test (the failure names
 * the action's own exception so neither signal is lost); a clean throw
 * propagates the original exception untouched.
 *
 * No state bleeds between tests: every hook is an event listener on the
 * per-test application instance.
 *
 * The mint surfaces (the two-transport verbs, the installer mint) use two
 * additional helpers: assertNoSecretLeakageOfMinted(), for actions whose
 * marker is BORN inside the watched action (a mint generates its own
 * secret, so the caller extracts it from the action's result after the
 * fact), and assertRevealsSecretExactlyOnce(), the reveal-once allowance —
 * printing once to the TTY (or once in the HTTP response) IS the delivery,
 * and everything beyond that single reveal must be marker-free.
 */
trait DetectsSecretLeaks
{
    private ?string $leakWatchMarker = null;

    private bool $leakWatchActive = false;

    private bool $leakWatchHooksRegistered = false;

    private ?int $leakWatchHooksAppId = null;

    /** @var list<array{channel: string, detail: string}> */
    private array $observedLeaks = [];

    /** @var list<string> */
    private array $watchedLogRecords = [];

    /** @var list<array{sql: string, bindings: list<mixed>}> */
    private array $watchedDatabaseWrites = [];

    /** @var list<string> */
    private array $watchedQueueArtifacts = [];

    /** @var list<array{key: string, value: string}> */
    private array $watchedCacheWrites = [];

    /**
     * Watch every channel while the action runs, then assert the marker
     * escaped into none of them. Returns whatever the action returns. If
     * the action throws: a recorded leak still fails the test (naming the
     * original exception); a clean throw propagates untouched.
     */
    public function assertNoSecretLeakage(string $marker, callable $act): mixed
    {
        $this->beginLeakWatch($marker);

        try {
            $result = $act();
        } catch (Throwable $exception) {
            try {
                $leaks = $this->finishLeakWatch();
            } catch (Throwable) {
                // The channel evaluation itself broke (the action may have
                // left the schema mid-change); surface the action's own
                // failure rather than masking it.
                throw $exception;
            }

            if ($leaks !== []) {
                Assert::fail(
                    "The secret marker escaped:\n".implode("\n", $leaks)
                    ."\nThe watched action also threw ".$exception::class.': '
                    .$this->redactMarker($exception->getMessage(), $marker),
                );
            }

            throw $exception;
        }

        $this->assertNoLeaks();

        return $result;
    }

    /**
     * The mint-surface variant of assertNoSecretLeakage(): the marker is
     * born INSIDE the watched action (a mint generates its own secret), so
     * the caller extracts it from the action's result once the action has
     * run — `$markerFrom($result)` — and every side-effect channel captured
     * during the action is then asserted marker-free. The action's own
     * observable delivery (console output, the HTTP response object) is not
     * a side-effect channel; assert it separately with
     * {@see assertRevealsSecretExactlyOnce}.
     */
    public function assertNoSecretLeakageOfMinted(callable $act, callable $markerFrom): mixed
    {
        $this->beginLeakWatch('__bfc_marker_pending__'.bin2hex(random_bytes(8)));

        $result = $act();

        $marker = $markerFrom($result);

        if (! is_string($marker) || $marker === '') {
            Assert::fail('assertNoSecretLeakageOfMinted() could not extract the minted secret from the action result.');
        }

        $this->leakWatchMarker = $marker;

        $this->assertNoLeaks();

        return $result;
    }

    /**
     * The reveal-once allowance (D7): the delivery channel — captured
     * console output, an HTTP response body — must carry the secret
     * EXACTLY once, and beyond that single reveal must be marker-free in
     * every recoverable form.
     */
    public function assertRevealsSecretExactlyOnce(string $captured, string $marker): void
    {
        Assert::assertSame(
            1,
            substr_count($captured, $marker),
            'The delivery channel must reveal the secret exactly once.',
        );

        $beyondReveal = (string) preg_replace('/'.preg_quote($marker, '/').'/', '[THE-ONE-REVEAL]', $captured, 1);

        if (($form = $this->leakingFormOf($beyondReveal, $marker)) !== null) {
            Assert::fail('Beyond the single reveal, the delivery channel still carried the marker ('.$form.').');
        }
    }

    public function beginLeakWatch(string $marker): void
    {
        $this->leakWatchMarker = $marker;
        $this->leakWatchActive = true;
        $this->observedLeaks = [];
        $this->watchedLogRecords = [];
        $this->watchedDatabaseWrites = [];
        $this->watchedQueueArtifacts = [];
        $this->watchedCacheWrites = [];

        $this->registerLeakWatchHooks();
    }

    public function assertNoLeaks(): void
    {
        $leaks = $this->finishLeakWatch();

        Assert::assertSame([], $leaks, "The secret marker escaped:\n".implode("\n", $leaks));
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

        if (is_string($content) && ($form = $this->leakingFormOf($content, $marker)) !== null) {
            $leaks[] = '[response] the response body carried the marker ('.$form.')';
        }

        foreach ($response->headers->all() as $name => $values) {
            foreach ($values as $value) {
                if (is_string($value) && ($form = $this->leakingFormOf($value, $marker)) !== null) {
                    $leaks[] = '[response] the "'.$name.'" header carried the marker ('.$form.')';
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
        $leaks = [];

        if (($form = $this->leakingFormOf($output, $marker)) !== null) {
            $leaks[] = '[console] the captured command output carried the marker ('.$form.')';
        }

        Assert::assertSame([], $leaks, "The secret marker escaped:\n".implode("\n", $leaks));
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

            if (($form = $this->leakingFormOf($rendered, $marker)) !== null) {
                $leaks[] = '[exception] a '.$current::class.' at chain depth '.$depth.' carried the marker ('.$form.')';
            }

            $current = $current->getPrevious();
            $depth++;
        }

        Assert::assertSame([], $leaks, "The secret marker escaped:\n".implode("\n", $leaks));
    }

    /**
     * Stop recording and evaluate every watched channel; the returned
     * lines are the leaks found (empty means clean).
     *
     * @return list<string>
     */
    private function finishLeakWatch(): array
    {
        if (! $this->leakWatchActive || $this->leakWatchMarker === null) {
            Assert::fail('assertNoLeaks() was called without a beginLeakWatch().');
        }

        $marker = $this->leakWatchMarker;

        // Stop capturing before the sweep so the sweep's own SELECTs and any
        // teardown noise are not recorded as action-time writes.
        $this->leakWatchActive = false;

        // Details name the channel, the matched form and a locus — never the
        // captured content itself: an encoded form of a real plaintext
        // cannot be reliably redacted, so it is never echoed.
        foreach ($this->watchedLogRecords as $record) {
            if (($form = $this->leakingFormOf($record, $marker)) !== null) {
                $this->recordLeak('log', 'a log record carried the marker ('.$form.')', $marker);
            }
        }

        foreach ($this->watchedDatabaseWrites as $write) {
            if (($form = $this->leakingFormOf($write['sql'], $marker)) !== null) {
                $this->recordLeak('database', 'a write statement carried the marker inline ('.$form.')', $marker);
            }

            foreach ($write['bindings'] as $binding) {
                if (! is_string($binding) || $binding === hash('sha256', $marker)) {
                    continue;
                }

                if (($form = $this->leakingFormOf($binding, $marker)) !== null) {
                    $this->recordLeak('database', 'a write binding carried the marker ('.$form.') ('.$write['sql'].')', $marker);
                }
            }
        }

        $this->sweepDatabaseAtRest($marker);

        foreach ($this->watchedQueueArtifacts as $artifact) {
            if (($form = $this->leakingFormOf($artifact, $marker)) !== null) {
                $this->recordLeak('queue', 'a queued job artifact carried the marker ('.$form.')', $marker);
            }
        }

        $this->sweepFakedQueue($marker);

        foreach ($this->watchedCacheWrites as $write) {
            if (($form = $this->leakingFormOf($write['key']."\n".$write['value'], $marker)) !== null) {
                $this->recordLeak('cache', 'the cache write for key "'.$write['key'].'" carried the marker ('.$form.')', $marker);
            }
        }

        $session = $this->stringifyForLeakScan(session()->all());

        if (($form = $this->leakingFormOf($session, $marker)) !== null) {
            $this->recordLeak('session', 'the session payload carried the marker ('.$form.')', $marker);
        }

        return array_map(
            static fn (array $leak): string => '['.$leak['channel'].'] '.$leak['detail'],
            $this->observedLeaks,
        );
    }

    private function registerLeakWatchHooks(): void
    {
        if ($this->app === null) {
            Assert::fail('beginLeakWatch() requires a booted application.');
        }

        // Listeners live on the application's dispatcher: refreshing the
        // application discards them while the flag would stay true, so the
        // registration is keyed on the current instance and repeated when
        // it changes.
        $appId = spl_object_id($this->app);

        if ($this->leakWatchHooksRegistered && $this->leakWatchHooksAppId === $appId) {
            return;
        }

        $this->leakWatchHooksRegistered = true;
        $this->leakWatchHooksAppId = $appId;

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

        // The real enqueued artifact, both ways it becomes observable:
        // JobQueued carries the payload Laravel wrote to the store, and
        // JobProcessing exposes the raw body — the sync driver's only
        // observable point, since it never fires JobQueued.
        Event::listen(JobQueued::class, function (JobQueued $event): void {
            if (! $this->leakWatchActive) {
                return;
            }

            if (is_string($event->payload)) {
                $this->watchedQueueArtifacts[] = $event->payload;
            }

            if (is_object($event->job)) {
                $serialized = $this->serializedJobForm($event->job);

                if ($serialized !== null) {
                    $this->watchedQueueArtifacts[] = $serialized;
                }
            }
        });

        Event::listen(JobProcessing::class, function (JobProcessing $event): void {
            if ($this->leakWatchActive) {
                $this->watchedQueueArtifacts[] = $event->job->getRawBody();
            }
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

                    if (($form = $this->leakingFormOf($value, $marker)) !== null) {
                        $this->recordLeak('database', 'the stored value in '.$table.'.'.$column.' carried the marker ('.$form.')', $marker);
                    }
                }
            }
        }
    }

    /**
     * When the Queue facade is faked, JobQueued never fires — sweep the
     * fake's pushed jobs at finalization so the common fake-based test
     * path is covered too.
     */
    private function sweepFakedQueue(string $marker): void
    {
        $queue = Queue::getFacadeRoot();

        if (! $queue instanceof QueueFake) {
            return;
        }

        foreach ($queue->pushedJobs() as $pushes) {
            if (! is_array($pushes)) {
                continue;
            }

            foreach ($pushes as $push) {
                $job = is_array($push) ? ($push['job'] ?? null) : null;

                if (! is_object($job)) {
                    continue;
                }

                $serialized = $this->serializedJobForm($job);

                if ($serialized !== null && ($form = $this->leakingFormOf($serialized, $marker)) !== null) {
                    $this->recordLeak('queue', 'a job pushed onto the faked queue ('.$job::class.') carried the marker ('.$form.')', $marker);
                }
            }
        }
    }

    /**
     * The state Laravel would actually serialize for a queued job, clone
     * effects included. Null when the job refuses serialization — a
     * refusal means nothing egressed.
     */
    private function serializedJobForm(object $job): ?string
    {
        try {
            return serialize(clone $job);
        } catch (Throwable) {
            // A throwing __clone is not a refusal to serialize; try the
            // original before giving up.
        }

        try {
            return serialize($job);
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * Scan a captured string for the marker in every recoverable form.
     * Returns the name of the form that matched, or null when clean.
     *
     * The forms are the COMMON ACCIDENTAL encodings — plain, URL, JSON,
     * base64 (one nested level) — because the threat model is accidental
     * egress. Deliberate obfuscation (hex, compression, custom encodings)
     * is outside this harness's scope.
     */
    private function leakingFormOf(string $captured, string $marker): ?string
    {
        if (str_contains($captured, $marker)) {
            return 'plain';
        }

        $urlDecoded = rawurldecode($captured);

        if ($urlDecoded !== $captured && str_contains($urlDecoded, $marker)) {
            return 'url-decoded';
        }

        $jsonUnescaped = $this->jsonUnescape($captured);

        if ($jsonUnescaped !== $captured && str_contains($jsonUnescaped, $marker)) {
            return 'json-unescaped';
        }

        // MIME-style wrapping splits one base64 token across lines; a
        // whitespace-stripped copy restores it to a single run.
        $stripped = str_replace(["\r", "\n", "\t", ' '], '', $captured);

        $haystacks = $stripped === $captured ? [$captured] : [$captured, $stripped];

        foreach ($haystacks as $haystack) {
            foreach ($this->decodedBase64Runs($haystack, $marker) as $decoded) {
                if (str_contains($decoded, $marker)) {
                    return 'base64-decoded';
                }

                $innerUrl = rawurldecode($decoded);

                if ($innerUrl !== $decoded && str_contains($innerUrl, $marker)) {
                    return 'base64-decoded';
                }

                $innerJson = $this->jsonUnescape($decoded);

                if ($innerJson !== $decoded && str_contains($innerJson, $marker)) {
                    return 'base64-decoded';
                }

                // One more base64 level catches double-encoding; no deeper.
                foreach ($this->decodedBase64Runs($decoded, $marker) as $doubleDecoded) {
                    if (str_contains($doubleDecoded, $marker)) {
                        return 'base64-decoded';
                    }
                }
            }
        }

        return null;
    }

    /**
     * Decode every base64-alphabet run in the text, tolerating prefix junk
     * that joined a run: on a strict-decode failure, the token after the
     * last interior '=' and the start offsets 1..3 are retried before
     * giving up. The run-length threshold follows the marker's encoded
     * length so a short marker's encoding is not ignored.
     *
     * @return list<string>
     */
    private function decodedBase64Runs(string $text, string $marker): array
    {
        $threshold = max(8, min(16, strlen(base64_encode($marker))));

        if (preg_match_all('#[A-Za-z0-9+/\-_=]{'.$threshold.',}#', $text, $matches) === 0) {
            return [];
        }

        $decoded = [];

        foreach ($matches[0] as $run) {
            $candidates = [$run];

            // '=' only legally terminates base64; one mid-run means prefix
            // junk joined the token (`token=...`) — the real token starts
            // after the last interior '='.
            $interior = strrpos(rtrim($run, '='), '=');

            if ($interior !== false) {
                $candidates[] = substr($run, $interior + 1);
            }

            foreach ($candidates as $candidate) {
                for ($offset = 0; $offset <= 3; $offset++) {
                    $slice = substr($candidate, $offset);

                    if (strlen($slice) < $threshold) {
                        break;
                    }

                    $bytes = base64_decode(strtr(rtrim($slice, '='), '-_', '+/'), true);

                    if ($bytes !== false) {
                        $decoded[] = $bytes;

                        break;
                    }
                }
            }
        }

        return $decoded;
    }

    /**
     * Undo JSON string escaping — every simple escape (\b \f \n \r \t \"
     * \/ \\), lone \uXXXX sequences, and UTF-16 surrogate pairs combined
     * into their real code point — so an escaped marker cannot hide behind
     * its encoding.
     */
    private function jsonUnescape(string $captured): string
    {
        if (! str_contains($captured, '\\')) {
            return $captured;
        }

        return (string) preg_replace_callback(
            '/\\\\u([Dd][89ABab][0-9A-Fa-f]{2})\\\\u([Dd][C-Fc-f][0-9A-Fa-f]{2})|\\\\u([0-9A-Fa-f]{4})|\\\\(["\/\\\\bfnrt])/',
            static function (array $match): string {
                if ($match[1] !== '') {
                    $high = (int) hexdec($match[1]);
                    $low = (int) hexdec($match[2]);

                    return (string) mb_chr(0x10000 + (($high - 0xD800) << 10) + ($low - 0xDC00), 'UTF-8');
                }

                if (($match[3] ?? '') !== '') {
                    return mb_convert_encoding(pack('H*', $match[3]), 'UTF-8', 'UTF-16BE');
                }

                return match ($match[4]) {
                    'b' => "\x08",
                    'f' => "\x0C",
                    'n' => "\n",
                    'r' => "\r",
                    't' => "\t",
                    default => $match[4],
                };
            },
            $captured,
        );
    }

    private function recordLeak(string $channel, string $detail, string $marker): void
    {
        $redacted = $this->redactMarker($detail, $marker);

        if (mb_strlen($redacted) > 300) {
            $redacted = mb_substr($redacted, 0, 300).'…';
        }

        $this->observedLeaks[] = ['channel' => $channel, 'detail' => $redacted];
    }

    /**
     * Replace the marker — and its recoverable encodings, which a printed
     * message can no more carry than the literal — with a placeholder.
     */
    private function redactMarker(string $text, string $marker): string
    {
        $standard = base64_encode($marker);
        $urlSafe = strtr($standard, '+/', '-_');

        $needles = [
            $marker,
            $standard,
            rtrim($standard, '='),
            $urlSafe,
            rtrim($urlSafe, '='),
        ];

        $urlEncoded = rawurlencode($marker);

        if ($urlEncoded !== $marker) {
            $needles[] = $urlEncoded;
        }

        $jsonEncoded = json_encode($marker);

        if (is_string($jsonEncoded)) {
            $jsonEscaped = substr($jsonEncoded, 1, -1);

            if ($jsonEscaped !== '' && $jsonEscaped !== $marker) {
                $needles[] = $jsonEscaped;
            }
        }

        return str_replace(array_unique($needles), '[REDACTED-SECRET-MARKER]', $text);
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
