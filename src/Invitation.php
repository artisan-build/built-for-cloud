<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Database\Factories\InvitationFactory;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

/**
 * An invitation IS a claim code (PRD 1.13, D4, D1e): hashed at rest,
 * single-use, optionally addressed, with a REQUIRED bounded ttl and an
 * `at_exchange` burn. The standalone acceptance action consumes it under a
 * conditional update gated on affected rows, never a read-then-write, and
 * creates the canonical package User.
 *
 * The standalone lifecycle creates addressed invitations only. Their role is
 * fixed by the issuing Owner/Admin and acceptance projects it directly onto
 * the canonical package User; no host composition hook or open-code path is
 * part of the supported surface.
 *
 * @property string $id
 * @property string|null $email
 * @property string $token
 * @property string|null $invited_by
 * @property string|null $used_by
 * @property string|null $role
 * @property CarbonInterface|null $accepted_at
 * @property CarbonInterface|null $cancelled_at
 * @property CarbonInterface|null $expires_at
 * @property CarbonInterface|null $created_at
 * @property CarbonInterface|null $updated_at
 *
 * @method static InvitationFactory factory($count = null, $state = [])
 */
final class Invitation extends Model
{
    /** @use HasFactory<InvitationFactory> */
    use HasFactory;

    use HasUuids;

    /**
     * The claim-code ttl bounds (PRD 1.1 + 1.3): 60 seconds to 7 days.
     */
    public const int TTL_MIN_SECONDS = 60;

    public const int TTL_MAX_SECONDS = 604800;

    public $incrementing = false;

    protected $keyType = 'string';

    /**
     * @var list<string>
     */
    protected $fillable = [
        'id',
        'email',
        'token',
        'invited_by',
        'used_by',
        'role',
        'accepted_at',
        'cancelled_at',
        'expires_at',
    ];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'accepted_at' => 'datetime',
            'cancelled_at' => 'datetime',
            'expires_at' => 'datetime',
        ];
    }

    /**
     * @param  Builder<Invitation>  $query
     * @return Builder<Invitation>
     */
    public function scopePending(Builder $query): Builder
    {
        return $query->whereNull('accepted_at')
            ->whereNull('cancelled_at')
            ->where(function (Builder $query): void {
                $query->whereNull('expires_at')
                    ->orWhere('expires_at', '>', now());
            });
    }

    /**
     * @param  Builder<Invitation>  $query
     * @return Builder<Invitation>
     */
    public function scopeAccepted(Builder $query): Builder
    {
        return $query->whereNotNull('accepted_at');
    }

    /**
     * @param  Builder<Invitation>  $query
     * @return Builder<Invitation>
     */
    public function scopeExpired(Builder $query): Builder
    {
        return $query->where('expires_at', '<', now())
            ->whereNull('accepted_at');
    }

    protected static function newFactory(): InvitationFactory
    {
        return InvitationFactory::new();
    }

    public static function hashToken(string $token): string
    {
        return hash('sha256', $token);
    }
}
