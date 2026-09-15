<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Actions;

use ArtisanBuild\BuiltForCloud\CredentialAuthorizationAuthority;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationDenialReason;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationExchange;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationFlow;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationPolicy;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationStatus;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationToken;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationTransitions;
use ArtisanBuild\BuiltForCloud\Exceptions\CredentialAuthorizationRefused;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

final readonly class PollDeviceAuthorization
{
    public function __construct(
        private CredentialAuthorizationPolicy $policy,
        private CredentialAuthorizationTransitions $transitions,
        private CredentialAuthorizationExchange $exchange,
    ) {}

    public function __invoke(Request $request, string $deviceCode): CredentialAuthorizationToken
    {
        if (preg_match('/\A[A-Za-z0-9_-]{43}\z/D', $deviceCode) !== 1) {
            throw CredentialAuthorizationRefused::invalidRequest();
        }

        $result = DB::transaction(function () use ($request, $deviceCode): CredentialAuthorizationToken|CredentialAuthorizationRefused {
            $authorization = DB::table('credential_authorizations')
                ->where('flow', CredentialAuthorizationFlow::Device->value)
                ->where('device_code_hash', hash('sha256', $deviceCode))
                ->lockForUpdate()
                ->first();

            if (! is_object($authorization) || $authorization->status === CredentialAuthorizationStatus::Consumed->value) {
                return CredentialAuthorizationRefused::invalidGrant();
            }

            if ($authorization->status === CredentialAuthorizationStatus::Denied->value) {
                return CredentialAuthorizationRefused::denied();
            }

            if (now()->greaterThanOrEqualTo($authorization->expires_at)) {
                return CredentialAuthorizationRefused::expired();
            }

            $context = $this->policy->requestForAuthorization($request, $authorization);

            try {
                [$profile, $purpose] = $this->policy->revalidate($context, $authorization);
            } catch (CredentialAuthorizationRefused) {
                $this->transitions->deny($authorization, CredentialAuthorizationDenialReason::ProfileWithdrawn);

                return CredentialAuthorizationRefused::denied();
            }

            $authority = $this->policy->authority($profile, $context, (string) $authorization->initiating_user_id);

            if ($authority === CredentialAuthorizationAuthority::Unavailable) {
                return CredentialAuthorizationRefused::temporarilyUnavailable();
            }

            if ($authority === CredentialAuthorizationAuthority::Denied) {
                $this->transitions->deny($authorization, CredentialAuthorizationDenialReason::AuthorityDenied);

                return CredentialAuthorizationRefused::denied();
            }

            $now = now();
            $effective = (int) $authorization->effective_interval;

            if ($authorization->last_polled_at !== null
                && $now->lt(now()->parse((string) $authorization->last_polled_at)->addSeconds($effective))) {
                $effective = min(30, $effective + 5);
                DB::table('credential_authorizations')->where('id', $authorization->id)->update([
                    'effective_interval' => $effective,
                    'updated_at' => $now,
                ]);

                return CredentialAuthorizationRefused::slowDown($effective);
            }

            if ($authorization->status === CredentialAuthorizationStatus::Pending->value) {
                DB::table('credential_authorizations')->where('id', $authorization->id)->update([
                    'last_polled_at' => $now,
                    'updated_at' => $now,
                ]);

                return CredentialAuthorizationRefused::pending();
            }

            if ($authorization->status !== CredentialAuthorizationStatus::Approved->value) {
                return CredentialAuthorizationRefused::invalidGrant();
            }

            return $this->exchange->exchange($context, $authorization, $profile, $purpose);
        });

        if ($result instanceof CredentialAuthorizationRefused) {
            throw $result;
        }

        return $result;
    }
}
