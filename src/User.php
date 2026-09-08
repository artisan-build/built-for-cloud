<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use Carbon\CarbonInterface;
use Illuminate\Auth\Authenticatable;
use Illuminate\Auth\MustVerifyEmail as MustVerifyEmailTrait;
use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Notifications\Notifiable;

/**
 * @property int $id
 * @property string $name
 * @property string $email
 * @property CarbonInterface|null $email_verified_at
 * @property string|null $password
 * @property string $role
 * @property string $status
 * @property string|null $owner_slot
 * @property string|null $scalpels_issuer
 * @property string|null $scalpels_connection_id
 * @property string|null $scalpels_id
 * @property string|null $original_contact_email
 * @property bool $email_is_generated
 * @property CarbonInterface|null $last_authenticated_at
 * @property CarbonInterface|null $membership_confirmed_at
 * @property CarbonInterface|null $membership_checked_at
 * @property CarbonInterface|null $membership_response_at
 * @property CarbonInterface|null $deactivated_at
 */
class User extends Model implements AuthenticatableContract, MustVerifyEmail
{
    use Authenticatable;
    use MustVerifyEmailTrait;
    use Notifiable;

    /** @var list<string> */
    protected $fillable = ['name', 'email', 'password'];

    /** @var list<string> */
    protected $hidden = ['password', 'remember_token', 'owner_slot'];

    /** @var array<string, mixed> */
    protected $attributes = [
        'role' => 'member',
        'status' => 'active',
        'email_is_generated' => false,
    ];

    public function roleValue(): ?UserRole
    {
        return UserRole::tryFrom($this->role);
    }

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'email_is_generated' => 'boolean',
            'last_authenticated_at' => 'datetime',
            'membership_confirmed_at' => 'datetime',
            'membership_checked_at' => 'datetime',
            'membership_response_at' => 'datetime',
            'deactivated_at' => 'datetime',
        ];
    }
}
