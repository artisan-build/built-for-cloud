<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

/**
 * The ONE lifecycle event vocabulary (D8 adjustment 2). Audit rows and
 * notifications are both subscribers of this single stream — two
 * vocabularies would drift into "the notification fired but the audit row
 * disagrees".
 *
 * `SensitiveRead` and `DeniedAction` are in the vocabulary now so the later
 * operator PRs emit through the same stream; no surface in this package
 * emits them yet. `Delivered` is emitted by the hmac delivery surfaces
 * (reveal-once mint, claim exchange); `Activated` is the hmac kind's
 * pending→active signing cutover — named honestly as its own event, because
 * activation is neither an exchange nor a first use (SEC-V3-01: the
 * separate operator-authorized transition).
 */
enum LifecycleEventType: string
{
    case Issued = 'issued';
    case Delivered = 'delivered';
    case Exchanged = 'exchanged';
    case FirstUsed = 'first_used';
    case Activated = 'activated';
    case Rotated = 'rotated';
    case Revoked = 'revoked';
    case Expiring = 'expiring';
    case SensitiveRead = 'sensitive_read';
    case DeniedAction = 'denied_action';
}
