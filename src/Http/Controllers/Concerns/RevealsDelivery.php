<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers\Concerns;

use ArtisanBuild\BuiltForCloud\DeliveryShape;
use ArtisanBuild\BuiltForCloud\MintedSecret;
use ArtisanBuild\BuiltForCloud\MintResult;

/**
 * The transport boundary: the ONE reveal (D7). Every HTTP surface that
 * hands a minted secret to its caller renders the delivery through this
 * one method, so the operator surface and the personal surface cannot
 * drift into two different answers about what leaves and how.
 *
 * The carrier throws on any later call ({@see MintedSecret}),
 * so a second egress of the same secret is structurally impossible however
 * many transports call this.
 */
trait RevealsDelivery
{
    /**
     * @return array<string, string>
     */
    private function deliveryPayload(MintResult $result): array
    {
        $payload = ['shape' => $result->delivery->value];

        switch ($result->delivery) {
            case DeliveryShape::Bearer:
                if ($result->secret !== null) {
                    $payload['secret'] = $result->secret->reveal();
                }
                break;
            case DeliveryShape::BasicAuth:
                $payload['username'] = (string) $result->basicUsername;

                if ($result->secret !== null) {
                    $payload['password'] = $result->secret->reveal();
                }
                break;
            case DeliveryShape::EnrollmentCode:
                if ($result->secret !== null) {
                    $payload['enrollment_code'] = $result->secret->reveal();
                }
                break;
            case DeliveryShape::SigningKey:
                // The key id rides beside the key (non-secret — the row id
                // the signature header will carry); the key itself is
                // PENDING until the activation verb cuts it over, and the
                // delivery fingerprint (also non-secret) is what the
                // receiver confirms and activation requires.
                $payload['key_id'] = $result->summary->id;

                if ($result->deliveryFingerprint !== null) {
                    $payload['delivery_fingerprint'] = $result->deliveryFingerprint;
                }

                if ($result->secret !== null) {
                    $payload['signing_key'] = $result->secret->reveal();
                }
                break;
            case DeliveryShape::SigningKeyCode:
                if ($result->secret !== null) {
                    $payload['claim_code'] = $result->secret->reveal();
                }
                break;
            case DeliveryShape::None:
                break;
        }

        return $payload;
    }
}
