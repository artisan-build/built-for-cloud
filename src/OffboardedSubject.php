<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Auth\CredentialGuard;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAuthenticated;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;

/**
 * The containment registry the offboard verb writes (PRD 1.15,
 * SEC-V3-04) and the guards read: one row per offboarded subject
 * (`user_id` null), plus one row per bound user the offboard deactivated
 * (`user_id` set). The registry is the belt UNDER the credential
 * revocations — even a credential the sweep somehow missed, or one bound
 * to the offboarded user under a different subject, fails here — and it
 * is the stated compensation where session storage cannot be enumerated:
 * whatever survives in a session store, {@see CredentialGuard} and
 * {@see EnsureUserIsAuthenticated} reject the offboarded principal on
 * every request thereafter.
 *
 * @property string $id
 * @property SubjectType $subject_type
 * @property string $subject_ref
 * @property string|null $user_id
 * @property CarbonInterface $offboarded_at
 * @property CarbonInterface|null $created_at
 * @property CarbonInterface|null $updated_at
 */
final class OffboardedSubject extends Model
{
    use HasUuids;

    public $incrementing = false;

    protected $keyType = 'string';

    /**
     * @var list<string>
     */
    protected $fillable = [
        'id',
        'subject_type',
        'subject_ref',
        'user_id',
        'offboarded_at',
    ];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'subject_type' => SubjectType::class,
            'offboarded_at' => 'datetime',
        ];
    }

    /**
     * @param  Builder<self>  $query
     * @return Builder<self>
     */
    public function scopeForSubject(Builder $query, Subject $subject): Builder
    {
        return $query
            ->where('subject_type', $subject->type->value)
            ->where('subject_ref', $subject->ref);
    }

    public static function subjectIsOffboarded(Subject $subject): bool
    {
        return self::query()->forSubject($subject)->whereNull('user_id')->exists();
    }

    public static function userIsOffboarded(string $userId): bool
    {
        return self::query()->where('user_id', $userId)->exists();
    }

    /**
     * Whether the registry rejects this credential: its subject is
     * offboarded, or it is bound to a deactivated user — one query, on
     * every guard resolution.
     */
    public static function rejects(Credential $credential): bool
    {
        return self::query()
            ->where(function (Builder $query) use ($credential): void {
                $query->where(function (Builder $query) use ($credential): void {
                    $query->where('subject_type', $credential->subject_type->value)
                        ->where('subject_ref', $credential->subject_ref)
                        ->whereNull('user_id');
                });

                if ($credential->user_id !== null) {
                    $query->orWhere('user_id', $credential->user_id);
                }
            })
            ->exists();
    }
}
