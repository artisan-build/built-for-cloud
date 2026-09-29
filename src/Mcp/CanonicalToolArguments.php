<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Mcp;

use Illuminate\Http\Request;
use JsonException;
use Laravel\Mcp\Transport\JsonRpcRequest;
use stdClass;
use UnexpectedValueException;

/** Deterministic JSON canonicalization for the exact HTTP tool arguments. */
final class CanonicalToolArguments
{
    private const int MAX_BYTES = 65_536;

    private const int MAX_DEPTH = 32;

    /**
     * Floats are deliberately unsupported: equivalent decimal spellings and
     * cross-runtime precision are not a safe confirmation boundary. Decoding
     * objects as stdClass preserves the otherwise ambiguous `{}` / `[]` split.
     *
     * Pinned by `tests/McpTwoPhaseTest.php` — "distinguishes empty objects from
     * empty lists in canonical arguments".
     */
    public function fromHttpRequest(Request $httpRequest, JsonRpcRequest $rpcRequest): string
    {
        try {
            $message = json_decode($httpRequest->getContent(), false, self::MAX_DEPTH, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw new UnexpectedValueException('The tool arguments cannot be canonicalized.');
        }

        if (! $message instanceof stdClass
            || ($message->id ?? null) !== $rpcRequest->id
            || ($message->method ?? null) !== 'tools/call'
            || ! isset($message->params)
            || ! $message->params instanceof stdClass
            || ($message->params->name ?? null) !== $rpcRequest->get('name')) {
            throw new UnexpectedValueException('The tool arguments cannot be canonicalized.');
        }

        $arguments = $message->params->arguments ?? new stdClass;

        if (! $arguments instanceof stdClass) {
            throw new UnexpectedValueException('The tool arguments cannot be canonicalized.');
        }

        unset($arguments->{TwoPhase::CONFIRM_ARGUMENT});

        $canonical = $this->encode($arguments, 0);

        if (strlen($canonical) > self::MAX_BYTES) {
            throw new UnexpectedValueException('The tool arguments cannot be canonicalized.');
        }

        return $canonical;
    }

    private function encode(mixed $value, int $depth): string
    {
        if ($depth > self::MAX_DEPTH) {
            throw new UnexpectedValueException('The tool arguments cannot be canonicalized.');
        }

        if ($value === null) {
            return 'null';
        }

        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }

        if (is_int($value)) {
            return (string) $value;
        }

        if (is_string($value)) {
            try {
                return json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            } catch (JsonException) {
                throw new UnexpectedValueException('The tool arguments cannot be canonicalized.');
            }
        }

        if (is_array($value) && array_is_list($value)) {
            return '['.implode(',', array_map(fn (mixed $item): string => $this->encode($item, $depth + 1), $value)).']';
        }

        if ($value instanceof stdClass) {
            $members = get_object_vars($value);
            ksort($members, SORT_STRING);
            $encoded = [];

            foreach ($members as $key => $member) {
                $encoded[] = $this->encode((string) $key, $depth + 1).':'.$this->encode($member, $depth + 1);
            }

            return '{'.implode(',', $encoded).'}';
        }

        throw new UnexpectedValueException('The tool arguments cannot be canonicalized.');
    }
}
