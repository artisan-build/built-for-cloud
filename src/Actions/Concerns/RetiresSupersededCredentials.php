<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Actions\Concerns;

use ArtisanBuild\BuiltForCloud\Actions\RotateCredential;
use ArtisanBuild\BuiltForCloud\Credential;

/**
 * The cutover retirement shared by the verbs that end a superseded row's
 * life (PRD 1.7 phase 2; the hmac activation cutover, PRD 1.21): the old
 * row's expiry becomes the grace end (NOW under emergency), and at grace
 * end the row dies by its own expiry — no reaper needed. The guarded
 * predicate is the never-extend rule: a row already expiring EARLIER
 * keeps its earlier death — a cutover never silently lengthens any
 * credential's life.
 */
trait RetiresSupersededCredentials
{
    private function retire(string $id, bool $emergency): void
    {
        $graceEnd = $emergency ? now() : now()->addSeconds(RotateCredential::GRACE_SECONDS);

        Credential::query()
            ->whereKey($id)
            ->where(function ($query) use ($graceEnd): void {
                $query->whereNull('expires_at')->orWhere('expires_at', '>', $graceEnd);
            })
            ->update(['expires_at' => $graceEnd]);
    }
}
