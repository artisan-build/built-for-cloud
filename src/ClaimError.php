<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use Illuminate\Http\JsonResponse;

/**
 * The claim contract's stable error enum (`hitch/docs/claim-contract.md`).
 * Clients branch on `error`, never on the HTTP status; `message` is human
 * prose printed VERBATIM by clients, so it may never carry a code, a token,
 * or any other secret.
 */
enum ClaimError: string
{
    case InvalidCode = 'invalid_code';
    case CodeNotFound = 'code_not_found';
    case CodeAlreadyClaimed = 'code_already_claimed';
    case CodeExpired = 'code_expired';
    case UnsupportedVersion = 'unsupported_version';
    case ServerError = 'server_error';

    /**
     * The contract's suggested status — guidance for humans reading logs;
     * the enum is the contract.
     */
    public function status(): int
    {
        return match ($this) {
            self::InvalidCode, self::UnsupportedVersion => 400,
            self::CodeNotFound => 404,
            self::CodeAlreadyClaimed => 409,
            self::CodeExpired => 410,
            self::ServerError => 500,
        };
    }

    public function respond(string $message): JsonResponse
    {
        return response()->json([
            'version' => 1,
            'error' => $this->value,
            'message' => $message,
        ], $this->status());
    }
}
