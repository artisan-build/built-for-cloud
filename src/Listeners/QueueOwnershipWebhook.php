<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Listeners;

use ArtisanBuild\BuiltForCloud\Events\OwnershipReleasePending;
use ArtisanBuild\BuiltForCloud\Events\OwnershipTransferred;
use ArtisanBuild\BuiltForCloud\Jobs\DeliverOwnershipWebhook;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Queue;

final class QueueOwnershipWebhook
{
    public function handle(OwnershipReleasePending|OwnershipTransferred $event): void
    {
        if ($event->callbackUrl === null) {
            Log::info('Built for Cloud ownership webhook skipped: no callback configured.', [
                'event' => $event->event,
            ]);

            return;
        }

        Queue::push(new DeliverOwnershipWebhook(
            callbackUrl: $event->callbackUrl,
            secret: $event->secret,
            event: $event->event,
            payload: $event->payload,
        ));
    }
}
