<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Database\Factories\InvitationFactory;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidInvitation;
use Carbon\CarbonInterface;
use DateTimeInterface;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;

/**
 * @property string $id
 * @property string $email
 * @property string $token
 * @property string|null $invited_by
 * @property CarbonInterface|null $accepted_at
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
        'accepted_at',
        'expires_at',
    ];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'accepted_at' => 'datetime',
            'expires_at' => 'datetime',
        ];
    }

    public static function invite(string $email, ?string $invitedBy = null, ?DateTimeInterface $expiresAt = null): self
    {
        do {
            $token = Str::random(40);
        } while (self::query()->where('token', $token)->exists());

        return self::query()->create([
            'email' => $email,
            'token' => $token,
            'invited_by' => $invitedBy,
            'expires_at' => $expiresAt ?? now()->addDays(7),
        ]);
    }

    /**
     * @param  array<string, mixed>  $attributes
     */
    public static function accept(string $token, array $attributes): Model
    {
        return DB::transaction(function () use ($token, $attributes): Model {
            $invitation = self::query()->pending()->where('token', $token)->lockForUpdate()->first();

            if (! $invitation instanceof self) {
                throw InvalidInvitation::forToken($token);
            }

            unset($attributes['is_admin']);

            if (isset($attributes['password']) && is_string($attributes['password'])) {
                $attributes['password'] = Hash::make($attributes['password']);
            }

            $userClass = self::userModelClass();
            $user = $userClass::query()->create([
                ...$attributes,
                'email' => $invitation->email,
            ]);

            if (Schema::hasColumn($user->getTable(), 'is_admin')) {
                $user->forceFill(['is_admin' => false])->save();
            }

            $invitation->forceFill(['accepted_at' => now()])->save();

            return $user;
        });
    }

    /**
     * @param  Builder<Invitation>  $query
     * @return Builder<Invitation>
     */
    public function scopePending(Builder $query): Builder
    {
        return $query->whereNull('accepted_at')
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

    /**
     * @return class-string<Model>
     */
    private static function userModelClass(): string
    {
        $configured = config('auth.providers.users.model', 'App\\Models\\User');

        return is_string($configured) && is_a($configured, Model::class, true)
            ? $configured
            : 'App\\Models\\User';
    }
}
