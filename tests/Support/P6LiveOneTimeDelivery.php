<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Support;

use InvalidArgumentException;
use JsonException;
use RuntimeException;

final class P6LiveOneTimeDelivery
{
    public static function sanitizeRotationBody(string $body, string $expectedSecret): string
    {
        if ($expectedSecret === '') {
            throw new InvalidArgumentException('The expected one-time delivery secret cannot be empty.');
        }

        try {
            $decoded = json_decode($body, true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new RuntimeException('The rotation delivery was not a JSON object.', previous: $exception);
        }

        if (! is_array($decoded) || array_is_list($decoded)) {
            throw new RuntimeException('The rotation delivery was not a JSON object.');
        }

        $delivery = $decoded['delivery'] ?? null;
        if (! is_array($delivery) || ($delivery['secret'] ?? null) !== $expectedSecret) {
            throw new RuntimeException('The replacement secret was not in the expected one-time delivery field.');
        }

        if (substr_count($body, $expectedSecret) !== 1) {
            throw new RuntimeException('The replacement secret was not delivered exactly once.');
        }

        $delivery['secret'] = '[verified-one-time-delivery]';
        $decoded['delivery'] = $delivery;

        return json_encode($decoded, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }
}
