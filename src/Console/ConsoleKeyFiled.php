<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Console;

use ArtisanBuild\BuiltForCloud\Actions\FileConsoleKey;
use Carbon\CarbonInterface;

/**
 * What a successful countersigning-key delivery reports back
 * (Console PRD D12) — on the claim envelopes, on the re-key route, and
 * on the CLI verb, from one shape so the three transports cannot
 * describe the same outcome differently.
 *
 * It carries the filed key's ID and EVERY key id that verifies at the
 * moment the delivery committed. That second field is not decoration:
 * during a make-before-break re-key there are two, and an operator whose
 * whole job is to confirm the old key still verifies before retiring it
 * should not have to infer that from a 201.
 *
 * **It deliberately holds no {@see ConsoleKey} model and no key
 * material** (rework A7). An earlier revision carried the model, whose
 * `public_key` is a public property — so a docblock saying "no key
 * material is on this object" was false the moment anyone dumped, logged
 * or serialized one. Three scalars and a list of key ids cannot become
 * that mistake. Nothing on the delivery path needs to read the material
 * back.
 */
final readonly class ConsoleKeyFiled
{
    /**
     * @param  string  $keyId  the `kid` just filed
     * @param  CarbonInterface|null  $activatedAt  when it began verifying
     * @param  list<string>  $activeKeyIds  every `kid` verifying when the delivery committed, sorted; includes {@see $keyId}
     */
    public function __construct(
        public string $keyId,
        public ?CarbonInterface $activatedAt,
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
            'key_id' => $this->keyId,
            // Constant: {@see FileConsoleKey} activates in the same
            // transaction as the filing, so a delivery that returns at
            // all returns an active key.
            'status' => 'active',
            'activated_at' => $this->activatedAt?->toRfc3339String(),
            'active_key_ids' => $this->activeKeyIds,
        ];
    }
}
