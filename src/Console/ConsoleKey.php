<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Console;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;

/**
 * One per-deployment verification key: the PUBLIC half of the keypair
 * the vendor signs console assertions with (Console PRD D12). This model
 * has no private-key property, its table has no private-key column, and
 * {@see ConsoleKeyring} refuses to store anything but 32 public bytes —
 * theft of this app's whole database yields no ability to mint an
 * assertion for this deployment or any other.
 *
 * The lifecycle is three states, and the transitions are deliberately
 * separate operations:
 *
 * - PENDING (`activated_at` null) — the key is on file and verifies
 *   nothing. Receiving key material is not the same act as trusting it,
 *   exactly as the hmac kind's delivery never activates (SEC-V3-01).
 * - ACTIVE — verifies tokens. TWO keys may be active simultaneously:
 *   that overlap IS make-before-break rotation.
 * - RETIRED (`retired_at` reached) — verifies nothing again, ever.
 *
 * Retirement is a later, separate step from activating the replacement
 * (never one "rotate" call), because collapsing them is what turns a
 * rotation into an outage for every assertion minted seconds earlier.
 *
 * @property string $id
 * @property string $key_id
 * @property string $public_key
 * @property CarbonInterface|null $activated_at
 * @property CarbonInterface|null $retired_at
 * @property CarbonInterface|null $created_at
 * @property CarbonInterface|null $updated_at
 */
final class ConsoleKey extends Model
{
    use HasUuids;

    protected $table = 'bfc_console_keys';

    public $incrementing = false;

    protected $keyType = 'string';

    /**
     * @var list<string>
     */
    protected $fillable = [
        'id',
        'key_id',
        'public_key',
        'activated_at',
        'retired_at',
    ];

    /**
     * Whether this key may verify a token AT a given instant. Both
     * bounds are evaluated against the passed clock rather than "now"
     * so the caller's one reading of the clock governs the whole
     * verification — a key cannot be active for the signature check and
     * retired by the time the claims are read.
     */
    public function isActiveAt(CarbonImmutable $at): bool
    {
        return $this->isPendingAt($at) === false && $this->isRetiredAt($at) === false;
    }

    public function isPendingAt(CarbonImmutable $at): bool
    {
        return $this->activated_at === null || $this->activated_at->getTimestamp() > $at->getTimestamp();
    }

    public function isRetiredAt(CarbonImmutable $at): bool
    {
        return $this->retired_at !== null && $this->retired_at->getTimestamp() <= $at->getTimestamp();
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'activated_at' => 'immutable_datetime',
            'retired_at' => 'immutable_datetime',
        ];
    }
}
