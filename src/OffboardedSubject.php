<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Auth\CredentialGuard;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAuthenticated;
use Carbon\CarbonInterface;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use SensitiveParameter;

/**
 * The containment registry the offboard verb writes (PRD 1.15,
 * SEC-V3-04) and the guards read: one row per offboarded subject
 * (`user_id` = {@see self::SUBJECT_ROW}, the empty string — NOT NULL, so
 * the (subject_type, subject_ref, user_id) unique key holds and two
 * racing first offboards cannot both insert), plus one row per bound
 * user the offboard deactivated (`user_id` set). The registry is the belt UNDER the credential
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
 * @property string $user_id
 * @property CarbonInterface $offboarded_at
 * @property CarbonInterface|null $created_at
 * @property CarbonInterface|null $updated_at
 */
final class OffboardedSubject extends Model
{
    use HasUuids;

    /**
     * The `user_id` value of the subject's own containment row. A real
     * user id is never the empty string, so the two row kinds cannot
     * collide — and being NOT NULL, the empty string participates in the
     * unique key where a NULL would not.
     */
    public const string SUBJECT_ROW = '';

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
        return self::query()->forSubject($subject)->where('user_id', self::SUBJECT_ROW)->exists();
    }

    public static function userIsOffboarded(string $userId): bool
    {
        if ($userId === self::SUBJECT_ROW) {
            return false;
        }

        return self::query()->where('user_id', $userId)->exists();
    }

    /**
     * Whether either containment row for this local human exists.
     *
     * The app's declaration owns the canonical user-principal reference,
     * just as it does for the personal-credential surface. Resolve it from
     * an isolated copy of the supplied request authenticated as the local
     * user, so direct credentials cannot substitute their own identity and
     * the caller never has to reconstruct the app's Subject convention. A
     * null or non-user-principal result disables only the subject arm; the
     * exact per-user row remains enforced.
     */
    public static function userOrSubjectIsOffboarded(#[SensitiveParameter] Request $request, Authenticatable $user): bool
    {
        $userId = (string) $user->getAuthIdentifier();
        $localRequest = clone $request;
        $localRequest->setUserResolver(static fn (): Authenticatable => $user);
        $subject = app(CredentialDeclaration::class)->resolveSubject($localRequest);
        $userSubject = $subject?->type === SubjectType::UserPrincipal ? $subject : null;

        if ($userId === self::SUBJECT_ROW && $userSubject === null) {
            return false;
        }

        return self::query()
            ->where(function (Builder $query) use ($userId, $userSubject): void {
                if ($userId !== self::SUBJECT_ROW) {
                    $query->where('user_id', $userId);
                }

                if ($userSubject !== null) {
                    $subjectRow = function (Builder $query) use ($userSubject): void {
                        $query->where('subject_type', $userSubject->type->value)
                            ->where('subject_ref', $userSubject->ref)
                            ->where('user_id', self::SUBJECT_ROW);
                    };

                    $userId === self::SUBJECT_ROW
                        ? $query->where($subjectRow)
                        : $query->orWhere($subjectRow);
                }
            })
            ->exists();
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
                        ->where('user_id', self::SUBJECT_ROW);
                });

                if ($credential->user_id !== null && $credential->user_id !== self::SUBJECT_ROW) {
                    $query->orWhere('user_id', $credential->user_id);
                }
            })
            ->exists();
    }
}
