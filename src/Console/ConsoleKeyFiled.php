<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Console;

use ArtisanBuild\BuiltForCloud\Actions\FileConsoleKey;

/**
 * What a successful countersigning-key delivery reports back
 * (Console PRD D12) — on the claim envelopes, on the re-key route, and
 * on the CLI verb, from one shape so the three transports cannot
 * describe the same outcome differently.
 *
 * It carries the filed key and EVERY key id that verifies at the moment
 * the delivery committed. That second field is not decoration: during a
 * make-before-break re-key there are two, and an operator whose whole
 * job is to confirm the old key still verifies before retiring it should
 * not have to infer that from a 201.
 *
 * No key MATERIAL is on this object. The `public_key` column is not
 * secret, but nothing on the delivery path needs to read it back, and a
 * result object that carries it is a result object that ends up in a log.
 */
final readonly class ConsoleKeyFiled
{
    /**
     * @param  list<string>  $activeKeyIds  every `kid` verifying when the delivery committed, sorted; includes {@see $key}
     */
    public function __construct(
        public ConsoleKey $key,
        public array $activeKeyIds,
    ) {}

    /**
     * The wire shape. Bounded scalars only — a `kid`
     * ({@see ConsoleKeyring::isValidKeyId}'s 64-character charset), a
     * fixed status string, and an RFC 3339 timestamp — which is what
     * lets the re-key route carry the contract's `metadata`
     * classification. Adding a free-text field here would silently
     * reclassify that endpoint.
     *
     * @return array{key_id: string, status: string, activated_at: string|null, active_key_ids: list<string>}
     */
    public function toArray(): array
    {
        return [
            'key_id' => $this->key->key_id,
            // Constant: {@see FileConsoleKey} activates in the same
            // transaction as the filing, so a delivery that returns at
            // all returns an active key.
            'status' => 'active',
            'activated_at' => $this->key->activated_at?->toRfc3339String(),
            'active_key_ids' => $this->activeKeyIds,
        ];
    }
}
