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
use ArtisanBuild\BuiltForCloud\LoopbackRedirectUri;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

final readonly class ExchangeLoopbackAuthorization
{
    public function __construct(
        private CredentialAuthorizationPolicy $policy,
        private CredentialAuthorizationTransitions $transitions,
        private CredentialAuthorizationExchange $exchange,
    ) {}

    public function __invoke(Request $request, string $code, string $redirectUri, string $codeVerifier): CredentialAuthorizationToken
    {
        $redirect = new LoopbackRedirectUri($redirectUri);

        if (preg_match('/\A[A-Za-z0-9_-]{43}\z/D', $code) !== 1
            || preg_match('/\A[A-Za-z0-9._~-]{43,128}\z/D', $codeVerifier) !== 1) {
            throw CredentialAuthorizationRefused::invalidRequest();
        }

        $result = DB::transaction(function () use ($request, $code, $redirect, $codeVerifier): CredentialAuthorizationToken|CredentialAuthorizationRefused {
            $authorization = DB::table('credential_authorizations')
                ->where('flow', CredentialAuthorizationFlow::Loopback->value)
                ->where('authorization_code_hash', hash('sha256', $code))
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

            if ($authorization->status !== CredentialAuthorizationStatus::Approved->value
                || ! hash_equals((string) $authorization->redirect_uri, $redirect->value)
                || ! hash_equals((string) $authorization->pkce_challenge, self::challenge($codeVerifier))) {
                return CredentialAuthorizationRefused::invalidGrant();
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

            return $this->exchange->exchange($context, $authorization, $profile, $purpose);
        });

        if ($result instanceof CredentialAuthorizationRefused) {
            throw $result;
        }

        return $result;
    }

    private static function challenge(string $verifier): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    }
}
