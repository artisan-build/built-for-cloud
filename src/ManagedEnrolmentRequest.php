<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * The durable idempotency ledger behind the three managed-enrolment
 * verbs (P1): enrolment, client-secret rotation and disconnect each
 * record their caller UUID, the non-secret request facts and the
 * committed outcome, so a lost-response retry replays exactly and a
 * reused UUID with different facts is a conflict, never a second
 * mutation. Rows are RETAINED across disconnect — every later
 * enrolment needs a fresh UUID, and a replayed id from an earlier
 * connection is refused.
 *
 * The row never carries secret material: `secret_retry_digest` is the
 * non-recoverable domain-separated digest
 * ({@see ManagedClientSecretStore::retryDigest()}), and
 * `committed_response` is the wire response actually sent — which by
 * contract never includes the secret.
 *
 * @property string $id
 * @property ManagedEnrolmentRequestKind $kind
 * @property string $issuer
 * @property string $connection_id
 * @property string $installation_id
 * @property string|null $organization_id
 * @property string|null $authority_base_url
 * @property int $expected_generation
 * @property int|null $expected_client_secret_generation
 * @property string|null $secret_retry_digest
 * @property array<string, mixed>|null $committed_response
 * @property Carbon|null $committed_at
 * @property string|null $managed_transition_id
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
final class ManagedEnrolmentRequest extends Model
{
    use HasUuids;

    protected $table = 'bfc_managed_enrolment_requests';

    public $incrementing = false;

    protected $keyType = 'string';

    /** @var list<string> */
    protected $guarded = [];

    /** @return array<string, mixed> */
    protected function casts(): array
    {
        return [
            'kind' => ManagedEnrolmentRequestKind::class,
            'expected_generation' => 'integer',
            'expected_client_secret_generation' => 'integer',
            'committed_response' => 'array',
            'committed_at' => 'datetime',
        ];
    }
}
