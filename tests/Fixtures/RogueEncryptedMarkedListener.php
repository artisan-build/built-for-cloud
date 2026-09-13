<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Contracts\SystemAuthorityQueueEntry;
use Illuminate\Contracts\Queue\ShouldBeEncrypted;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use RuntimeException;
use Throwable;

/**
 * A PACKAGE queued listener with an encrypted payload. Reading its marked class means
 * decrypting first, so this is the positive half of the encryption branch: without the
 * decrypt the entry could only be framed by failing closed, and with a naive "treat
 * unreadable as host" it would escape entirely.
 */
final class RogueEncryptedMarkedListener implements ShouldBeEncrypted, ShouldQueue, SystemAuthorityQueueEntry
{
    public function handle(RogueListenerEvent $event): void
    {
        throw new RuntimeException('deliberate');
    }

    /**
     * Authenticates from failed(), deliberately NOT from handle().
     *
     * handle() is framed by the bus pipe, which reads the in-memory wrapper's class with
     * no payload and no decryption — so a cell authenticating there would stay green even
     * if the payload read returned false for every ciphertext. failed() runs outside the
     * pipe's frame, so this cell actually depends on the queue scope decrypting the
     * payload to identify us.
     */
    public function failed(RogueListenerEvent $event, Throwable $e): void
    {
        Cache::put('bfc-test.encrypted-marked-ran.'.$event->userId, true, 60);
        Auth::guard('web')->loginUsingId($event->userId);
    }
}
