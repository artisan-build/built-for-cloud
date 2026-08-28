<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Contracts\ComposesInvitedUserAttributes;
use ArtisanBuild\BuiltForCloud\Database\Factories\InvitationFactory;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidInvitation;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;

/**
 * An invitation IS a claim code (PRD 1.13, D4, D1e): hashed at rest,
 * single-use, optionally addressed, with a REQUIRED bounded ttl and an
 * `at_exchange` burn — acceptance consumes it under a conditional update
 * gated on affected rows, never a read-then-write. What it buys is not a
 * secret but an account-creation ceremony: `accept()` creates the app's
 * user.
 *
 * Two consumers shape the row (D4 + D1e): a teammate invite is ADDRESSED
 * (`email` non-null, forced onto the created user); an open code is
 * UNADDRESSED (`email` null, the registrant supplies their own). `role` is
 * stored and never interpreted — the {@see ComposesInvitedUserAttributes}
 * hook is where an app projects it onto the user it creates.
 *
 * @property string $id
 * @property string|null $email
 * @property string $token
 * @property string|null $invited_by
 * @property string|null $used_by
 * @property string|null $role
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

    /**
     * The claim-code ttl bounds (PRD 1.1 + 1.3): REQUIRED on invite,
     * 60 seconds to 7 days. The old 7-day default is deliberately GONE —
     * a code's lifetime is always the issuer's explicit choice.
     */
    public const int TTL_MIN_SECONDS = 60;

    public const int TTL_MAX_SECONDS = 604800;

    private ?string $plainTextToken = null;

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

    public static function invite(?string $email, int $ttlSeconds, ?string $invitedBy = null, ?string $role = null): self
    {
        if ($ttlSeconds < self::TTL_MIN_SECONDS || $ttlSeconds > self::TTL_MAX_SECONDS) {
            throw InvalidCredentialInput::invitationTtlOutOfBounds();
        }

        do {
            $plainTextToken = Str::random(40);
            $tokenHash = self::hashToken($plainTextToken);
        } while (self::query()->where('token', $tokenHash)->exists());

        $invitation = self::query()->create([
            'email' => $email,
            'token' => $tokenHash,
            'invited_by' => $invitedBy,
            'role' => $role,
            'expires_at' => now()->addSeconds($ttlSeconds),
        ]);

        $invitation->plainTextToken = $plainTextToken;

        return $invitation;
    }

    /**
     * Exchange the invitation for a created user. Refusals speak the claim
     * contract's error enum ({@see InvalidInvitation}); the burn is
     * `at_exchange`: a conditional update gated on affected rows inside the
     * locked transaction, so of two concurrent accepts exactly one wins.
     *
     * @param  array<string, mixed>  $attributes
     */
    public static function accept(string $token, array $attributes): Model
    {
        return DB::transaction(function () use ($token, $attributes): Model {
            $invitation = self::query()->where('token', self::hashToken($token))->lockForUpdate()->first();

            if (! $invitation instanceof self) {
                throw InvalidInvitation::notFound();
            }

            if ($invitation->accepted_at !== null) {
                throw InvalidInvitation::alreadyAccepted();
            }

            if ($invitation->expires_at !== null && $invitation->expires_at->lessThanOrEqualTo(now())) {
                throw InvalidInvitation::expired();
            }

            // The at_exchange burn: zero affected rows means a concurrent
            // accept won between the read and this write.
            $consumed = self::query()
                ->whereKey($invitation->getKey())
                ->whereNull('accepted_at')
                ->update(['accepted_at' => now()]);

            if ($consumed === 0) {
                throw InvalidInvitation::alreadyAccepted();
            }

            unset($attributes['is_admin']);

            if (isset($attributes['password']) && is_string($attributes['password'])) {
                $attributes['password'] = Hash::make($attributes['password']);
            }

            // The attribute-composition hook (D4 cost 4): the app composes
            // the user's attributes at creation — capstan projects `role`,
            // crate projects key-management-only. No binding = the
            // attributes pass through untouched, exactly today's behaviour.
            // The hook is trusted app code; the is_admin strip below is a
            // guard-rail against accidental pass-through, not a privilege
            // boundary against the hook itself.
            if (app()->bound(ComposesInvitedUserAttributes::class)) {
                $attributes = app(ComposesInvitedUserAttributes::class)
                    ->composeInvitedUserAttributes($invitation, $attributes);

                unset($attributes['is_admin']);
            }

            // Addressed invitations force their address onto the user; an
            // open code lets the registrant supply their own.
            if ($invitation->email !== null) {
                $attributes['email'] = $invitation->email;
            }

            $userClass = self::userModelClass();
            $user = $userClass::query()->create($attributes);

            if (Schema::hasColumn($user->getTable(), 'is_admin')) {
                $user->forceFill(['is_admin' => false])->save();
            }

            $invitation->refresh();
            $invitation->forceFill(['used_by' => (string) $user->getKey()])->save();

            app(LifecycleEventRecorder::class)->record(
                event: LifecycleEventType::Exchanged,
                codeId: $invitation->id,
                actor: AuditActor::credentialHolder($invitation->id),
                recipient: $invitation->email,
            );

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

    public function getTokenAttribute(string $value): string
    {
        return $this->plainTextToken ?? $value;
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

    public static function hashToken(string $token): string
    {
        return hash('sha256', $token);
    }
}
