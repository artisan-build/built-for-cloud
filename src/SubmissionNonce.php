<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Exceptions\SubmissionNonceRefused;
use Illuminate\Support\Facades\DB;

/**
 * A hash-only, session- and user-bound permit for one credential mutation.
 */
final readonly class SubmissionNonce
{
    public const string FIELD = 'submission_nonce';

    private const int TTL_SECONDS = 3600;

    private function __construct(
        private string $presented,
        private string $sessionHash,
        private string $userId,
        private string $verb,
        private string $target,
    ) {}

    public static function issue(string $sessionId, string $userId, CredentialVerb $verb, string $target): string
    {
        $nonce = bin2hex(random_bytes(32));

        DB::table('bfc_submission_nonces')->insert([
            'nonce_hash' => self::hash($nonce),
            'session_hash' => self::hash($sessionId),
            'user_id' => $userId,
            'verb' => $verb->value,
            'target' => $target,
            'expires_at' => now()->addSeconds(self::TTL_SECONDS),
            'created_at' => now(),
        ]);

        return $nonce;
    }

    public static function presented(
        mixed $nonce,
        string $sessionId,
        string $userId,
        CredentialVerb $verb,
        string $target,
    ): self {
        return new self(
            is_string($nonce) ? $nonce : '',
            self::hash($sessionId),
            $userId,
            $verb->value,
            $target,
        );
    }

    /**
     * Must be called inside the credential mutation's transaction. A
     * conditional DELETE is the claim: concurrent submissions cannot both
     * observe success, and a later mutation failure restores the nonce.
     */
    public function consume(): void
    {
        $deleted = DB::table('bfc_submission_nonces')
            ->where('nonce_hash', self::hash($this->presented))
            ->where('session_hash', $this->sessionHash)
            ->where('user_id', $this->userId)
            ->where('verb', $this->verb)
            ->where('target', $this->target)
            ->where('expires_at', '>', now())
            ->delete();

        if ($deleted !== 1) {
            throw SubmissionNonceRefused::invalid();
        }
    }

    private static function hash(string $value): string
    {
        return hash('sha256', $value);
    }
}
