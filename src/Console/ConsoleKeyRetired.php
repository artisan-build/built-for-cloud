<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Console;

use ArtisanBuild\BuiltForCloud\Actions\RetireConsoleKey;
use Carbon\CarbonInterface;

/**
 * What a countersigning-key retirement reports back (Console PRD D12) —
 * on the retire route and on the CLI verb, from one shape, the way
 * {@see ConsoleKeyFiled} is one shape for the three delivery surfaces.
 *
 * It carries the key id, the instant it stopped verifying, whether THIS
 * call is what stopped it, and every key id still verifying afterwards.
 *
 * `newlyRetired` is the field that makes an idempotent verb honest. On
 * a repeat it is false and `retiredAt` is the FIRST call's instant
 * rather than this one's — so a caller can tell "I retired it" from "it
 * was already retired" without comparing a timestamp against its own
 * clock.
 *
 * **Three of the four are fixed by the retirement and one is not, and
 * the difference is deliberate.** `keyId`, the `retired` status and
 * `retiredAt` never move again. `activeKeyIds` is read at the moment
 * each response is built, so a repeat issued after another key was filed
 * and activated reports a LONGER list than the first did. That is the
 * field doing its job: it answers "what verifies now", which is what an
 * operator retiring a key is actually looking at, and a frozen copy of a
 * ring that has since changed would be the misleading answer.
 *   Pinned by `tests/ConsoleKeyRetirementTest.php` — "reports the ring
 *   as of each response while the key id status and retired_at stay
 *   fixed".
 *
 * An empty `activeKeyIds` is the deliberate end of delegated entry
 * ({@see RetireConsoleKey} refuses to produce one by accident).
 *
 * It holds no {@see ConsoleKey} model and no key material, for the
 * reason {@see ConsoleKeyFiled} does not: that model's `public_key` is a
 * public property, and an object carrying one cannot promise anything
 * about what a dump or a log line reveals.
 */
final readonly class ConsoleKeyRetired
{
    /**
     * @param  string  $keyId  the `kid` that is now retired
     * @param  CarbonInterface|null  $retiredAt  when it stopped verifying
     * @param  bool  $newlyRetired  whether this call is what retired it
     * @param  list<string>  $activeKeyIds  every `kid` still verifying, sorted; never includes {@see $keyId}
     */
    public function __construct(
        public string $keyId,
        public ?CarbonInterface $retiredAt,
        public bool $newlyRetired,
        public array $activeKeyIds,
    ) {}

    /**
     * The wire shape. Bounded scalars only — a `kid`, a fixed status
     * string, a boolean and an RFC 3339 timestamp — which is what lets
     * the retire route carry the contract's `metadata` classification.
     * A free-text field here would silently reclassify that endpoint.
     *
     * @return array{key_id: string, status: string, retired_at: string|null, newly_retired: bool, active_key_ids: list<string>}
     */
    public function toArray(): array
    {
        return [
            'key_id' => $this->keyId,
            // Constant: this object is only ever constructed for a key
            // whose retirement has committed.
            'status' => 'retired',
            'retired_at' => $this->retiredAt?->toRfc3339String(),
            'newly_retired' => $this->newlyRetired,
            'active_key_ids' => $this->activeKeyIds,
        ];
    }
}
