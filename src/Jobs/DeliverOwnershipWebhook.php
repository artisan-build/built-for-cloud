<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Jobs;

use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Support\Facades\Http;
use JsonException;

final class DeliverOwnershipWebhook implements ShouldQueue
{
    public int $tries = 3;

    /**
     * @var list<int>
     */
    public array $backoff = [30, 120, 300];

    /**
     * @param  array<string, mixed>  $payload
     */
    public function __construct(
        public readonly string $callbackUrl,
        public readonly string $secret,
        public readonly string $event,
        public readonly array $payload,
    ) {}

    /**
     * @throws JsonException
     */
    public function handle(): void
    {
        $timestamp = (string) now()->unix();
        $rawBody = json_encode([
            'event' => $this->event,
            'payload' => $this->payload,
            'timestamp' => (int) $timestamp,
        ], JSON_THROW_ON_ERROR);
        $signature = hash_hmac('sha256', $timestamp.'.'.$rawBody, $this->secret);

        Http::withBody($rawBody, 'application/json')
            ->withHeaders([
                'X-BFC-Timestamp' => $timestamp,
                'X-BFC-Signature' => $signature,
            ])
            ->post($this->callbackUrl);
    }
}
