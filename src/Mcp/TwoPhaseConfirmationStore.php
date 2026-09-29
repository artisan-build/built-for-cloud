<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Mcp;

use ArtisanBuild\BuiltForCloud\Console\DelegatedActor;
use ArtisanBuild\BuiltForCloud\Console\RequestAssertion;
use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\CacheManager;
use Illuminate\Cache\FileStore;
use Illuminate\Cache\NullStore;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Encryption\Encrypter;
use Illuminate\Http\Request;
use JsonException;
use SensitiveParameter;
use Throwable;

/**
 * Issues and atomically burns bounded two-phase confirmations.
 *
 * The mint marker and burn lock share one configured cache repository. The
 * burn atomically acquires a nonce-specific distributed lock, retains it
 * through nonce expiry, then removes the mint marker before execution. Losing
 * either spent-state key therefore refuses a replay, while process death after
 * lock acquisition cannot make the confirmation reusable. Array, file and null
 * stores refuse: supported stores must implement Laravel's LockProvider and be
 * shared by all workers serving this deployment.
 *
 * Pinned by `tests/McpTwoPhaseTest.php` — "gives exactly one winner when phase
 * two claims interleave at the atomic lock".
 */
final class TwoPhaseConfirmationStore
{
    public const string KEY_NAMESPACE = 'bfc:mcp:two-phase:v1:';

    private const int MAX_TTL_SECONDS = 900;

    private const int MIN_TTL_SECONDS = 30;

    public function __construct(
        private readonly CacheManager $cache,
        private readonly Encrypter $encrypter,
    ) {}

    /**
     * @return array{confirmation: string, expires_at: int}
     *
     * @throws TwoPhaseConfirmationRefused
     */
    public function mint(string $tool, string $canonicalArguments, string $subject): array
    {
        try {
            $repository = $this->repository();
            $expiresAt = time() + $this->ttl();

            for ($attempt = 0; $attempt < 3; $attempt++) {
                $id = $this->base64UrlEncode(random_bytes(18));
                $binding = $this->binding($id, $expiresAt, $tool, $canonicalArguments, $subject);
                $payload = json_encode([
                    'v' => 1,
                    'id' => $id,
                    'exp' => $expiresAt,
                    'binding' => $binding,
                ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);

                if (! $repository->add($this->markerKey($id), $binding, $this->ttl())) {
                    continue;
                }

                $signature = hash_hmac('sha256', $payload, $this->signingKey(), true);

                return [
                    'confirmation' => $this->base64UrlEncode($payload).'.'.$this->base64UrlEncode($signature),
                    'expires_at' => $expiresAt,
                ];
            }
        } catch (TwoPhaseConfirmationRefused $refused) {
            throw $refused;
        } catch (Throwable) {
            throw TwoPhaseConfirmationRefused::because(TwoPhaseConfirmationRefused::UNAVAILABLE);
        }

        throw TwoPhaseConfirmationRefused::because(TwoPhaseConfirmationRefused::UNAVAILABLE);
    }

    /**
     * Atomically claims the nonce-specific lock and deliberately retains it.
     *
     * @throws TwoPhaseConfirmationRefused
     */
    public function burn(
        #[SensitiveParameter] string $confirmation,
        string $tool,
        string $canonicalArguments,
        string $subject,
    ): void {
        [$payload, $signature] = $this->parse($confirmation);
        $expectedSignature = hash_hmac('sha256', $payload['json'], $this->signingKey(), true);

        if (! hash_equals($expectedSignature, $signature)) {
            throw TwoPhaseConfirmationRefused::because(TwoPhaseConfirmationRefused::INVALID);
        }

        $now = time();

        if ($payload['exp'] <= $now) {
            throw TwoPhaseConfirmationRefused::because(TwoPhaseConfirmationRefused::EXPIRED);
        }

        $binding = $this->binding(
            $payload['id'],
            $payload['exp'],
            $tool,
            $canonicalArguments,
            $subject,
        );

        if (! hash_equals($payload['binding'], $binding)) {
            throw TwoPhaseConfirmationRefused::because(TwoPhaseConfirmationRefused::MISMATCHED);
        }

        try {
            $repository = $this->repository();
            $stored = $repository->get($this->markerKey($payload['id']));

            if (! is_string($stored) || ! hash_equals($stored, $binding)) {
                throw TwoPhaseConfirmationRefused::because(TwoPhaseConfirmationRefused::SPENT);
            }

            $store = $repository->getStore();

            if (! $store instanceof LockProvider) {
                throw TwoPhaseConfirmationRefused::because(TwoPhaseConfirmationRefused::UNAVAILABLE);
            }

            if ($store
                ->lock($this->burnKey($payload['id']), max(1, $payload['exp'] - $now))
                ->get() !== true) {
                throw TwoPhaseConfirmationRefused::because(TwoPhaseConfirmationRefused::SPENT);
            }

            if (! $repository->forget($this->markerKey($payload['id']))) {
                throw TwoPhaseConfirmationRefused::because(TwoPhaseConfirmationRefused::UNAVAILABLE);
            }
        } catch (TwoPhaseConfirmationRefused $refused) {
            throw $refused;
        } catch (Throwable) {
            throw TwoPhaseConfirmationRefused::because(TwoPhaseConfirmationRefused::UNAVAILABLE);
        }
    }

    /**
     * Type-qualifies every principal; delegated identities retain their
     * `bfc-console:` qualifier rather than collapsing to the actor row key.
     *
     * @throws TwoPhaseConfirmationRefused
     */
    public function subject(Request $request): string
    {
        $delegated = RequestAssertion::principal($request);

        if ($delegated?->delegatedActor instanceof DelegatedActor) {
            return DelegatedActor::class.'#'.$delegated->delegatedActor->getAuthIdentifier();
        }

        $principal = $request->user();

        if (! $principal instanceof Authenticatable) {
            throw TwoPhaseConfirmationRefused::because(TwoPhaseConfirmationRefused::UNAVAILABLE);
        }

        $identifier = $principal->getAuthIdentifier();

        if (! is_int($identifier) && ! is_string($identifier)) {
            throw TwoPhaseConfirmationRefused::because(TwoPhaseConfirmationRefused::UNAVAILABLE);
        }

        return $principal::class.'#'.$identifier;
    }

    /**
     * @return array{0: array{json: string, id: string, exp: int, binding: string}, 1: string}
     */
    private function parse(#[SensitiveParameter] string $confirmation): array
    {
        if (strlen($confirmation) > 512 || substr_count($confirmation, '.') !== 1) {
            throw TwoPhaseConfirmationRefused::because(TwoPhaseConfirmationRefused::INVALID);
        }

        [$encodedPayload, $encodedSignature] = explode('.', $confirmation, 2);
        $json = $this->base64UrlDecode($encodedPayload);
        $signature = $this->base64UrlDecode($encodedSignature);

        try {
            $payload = json_decode($json, true, 4, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw TwoPhaseConfirmationRefused::because(TwoPhaseConfirmationRefused::INVALID);
        }

        if (! is_array($payload)
            || array_keys($payload) !== ['v', 'id', 'exp', 'binding']
            || $payload['v'] !== 1
            || ! is_string($payload['id'])
            || preg_match('/^[A-Za-z0-9_-]{24}$/D', $payload['id']) !== 1
            || ! is_int($payload['exp'])
            || ! is_string($payload['binding'])
            || preg_match('/^[a-f0-9]{64}$/D', $payload['binding']) !== 1
            || strlen($signature) !== 32) {
            throw TwoPhaseConfirmationRefused::because(TwoPhaseConfirmationRefused::INVALID);
        }

        return [[
            'json' => $json,
            'id' => $payload['id'],
            'exp' => $payload['exp'],
            'binding' => $payload['binding'],
        ], $signature];
    }

    private function binding(
        string $id,
        int $expiresAt,
        string $tool,
        string $canonicalArguments,
        string $subject,
    ): string {
        $context = $this->context();
        $message = $this->frame([
            'bfc-mcp-two-phase-v1',
            $context['deployment'],
            $context['application'],
            $tool,
            $canonicalArguments,
            $subject,
            (string) $expiresAt,
            $id,
        ]);

        return hash_hmac('sha256', $message, $this->bindingKey());
    }

    /** @return array{deployment: string, application: string} */
    private function context(): array
    {
        $deployment = config('built-for-cloud.console.audience');
        $application = config('built-for-cloud.manifest.slug');

        if (! is_string($deployment) || $deployment === ''
            || ! is_string($application) || $application === '') {
            throw TwoPhaseConfirmationRefused::because(TwoPhaseConfirmationRefused::UNAVAILABLE);
        }

        return ['deployment' => $deployment, 'application' => $application];
    }

    private function repository(): Repository
    {
        $configured = config('built-for-cloud.mcp.two_phase.cache_store');
        $repository = $this->cache->store(is_string($configured) && $configured !== '' ? $configured : null);
        $store = $repository->getStore();

        if (! $store instanceof LockProvider
            || $store instanceof ArrayStore
            || $store instanceof FileStore
            || $store instanceof NullStore) {
            throw TwoPhaseConfirmationRefused::because(TwoPhaseConfirmationRefused::UNAVAILABLE);
        }

        return $repository;
    }

    private function ttl(): int
    {
        $ttl = config('built-for-cloud.mcp.two_phase.ttl_seconds');

        if (! is_int($ttl) || $ttl < self::MIN_TTL_SECONDS || $ttl > self::MAX_TTL_SECONDS) {
            throw TwoPhaseConfirmationRefused::because(TwoPhaseConfirmationRefused::UNAVAILABLE);
        }

        return $ttl;
    }

    private function markerKey(string $id): string
    {
        return $this->keyPrefix().'mint:'.hash('sha256', $id);
    }

    private function burnKey(string $id): string
    {
        return $this->keyPrefix().'burn:'.hash('sha256', $id);
    }

    private function keyPrefix(): string
    {
        $context = $this->context();

        return self::KEY_NAMESPACE.hash('sha256', $this->frame(array_values($context))).':';
    }

    /** @param list<string> $parts */
    private function frame(array $parts): string
    {
        return implode('', array_map(static fn (string $part): string => strlen($part).':'.$part, $parts));
    }

    private function bindingKey(): string
    {
        return hash_hmac('sha256', 'bfc:mcp:two-phase:binding:v1', $this->encrypter->getKey(), true);
    }

    private function signingKey(): string
    {
        return hash_hmac('sha256', 'bfc:mcp:two-phase:signing:v1', $this->encrypter->getKey(), true);
    }

    private function base64UrlEncode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    private function base64UrlDecode(#[SensitiveParameter] string $value): string
    {
        if ($value === '' || preg_match('/^[A-Za-z0-9_-]+$/D', $value) !== 1) {
            throw TwoPhaseConfirmationRefused::because(TwoPhaseConfirmationRefused::INVALID);
        }

        $decoded = base64_decode(strtr($value, '-_', '+/'), true);

        if ($decoded === false) {
            throw TwoPhaseConfirmationRefused::because(TwoPhaseConfirmationRefused::INVALID);
        }

        return $decoded;
    }
}
