<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\OnboardingToken;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\TokenGenerator;
use ArtisanBuild\BuiltForCloud\TokenRegistry;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Illuminate\Validation\Rule;

final class ManageOnboarding
{
    public function __construct(
        private readonly TokenGenerator $generator,
        private readonly TokenRegistry $tokens,
    ) {}

    public function issue(Request $request): JsonResponse
    {
        /** @var array{email: string, scope?: string|null} $validated */
        $validated = $request->validate([
            'email' => ['required', 'email'],
            'scope' => ['nullable', 'string', Rule::in(Scope::values())],
        ]);

        return DB::transaction(function () use ($validated): JsonResponse {
            $email = $validated['email'];
            $scope = $validated['scope'] ?? Scope::Consume->value;

            $this->supersedePendingOnboarding($email, $scope);
            $this->revokeActiveDurable($email, $scope);

            [$swapToken, $onboardingToken] = $this->mintSwapToken();

            $onboardingToken->forceFill([
                'email' => $email,
                'scope' => $scope,
                'expires_at' => now()->addDay(),
            ])->save();

            return response()->json([
                'swap_token' => $swapToken,
                'email' => $email,
            ], 201);
        });
    }

    public function exchange(Request $request): JsonResponse
    {
        /** @var array{token: string} $validated */
        $validated = $request->validate([
            'token' => ['required', 'string'],
        ]);

        return DB::transaction(function () use ($validated): JsonResponse {
            $onboardingToken = $this->lockSwapToken($validated['token']);

            if ($onboardingToken === null) {
                abort(401);
            }

            if ($onboardingToken->durable_token_id !== null) {
                $this->revokeDurableById($onboardingToken->durable_token_id);
            }

            $generated = $this->generator->generate();
            $durableToken = $this->tokens->store(
                $onboardingToken->email,
                $generated->hash,
                abilities: [$onboardingToken->scope],
            );

            $onboardingToken->forceFill(['durable_token_id' => $durableToken->getKey()])->save();

            return response()->json([
                'durable_token' => $generated->plaintext,
                'name' => $onboardingToken->email,
            ], 201);
        });
    }

    public function verify(Request $request): JsonResponse
    {
        $bearer = $request->bearerToken();

        if ($bearer === null || $bearer === '') {
            abort(401);
        }

        $durableToken = $this->tokens->resolveModel($bearer);

        if ($durableToken === null) {
            abort(401);
        }

        return DB::transaction(function () use ($durableToken): JsonResponse {
            /** @var ApiToken $lockedToken */
            $lockedToken = ApiToken::query()
                ->whereKey($durableToken->getKey())
                ->lockForUpdate()
                ->firstOrFail();

            /** @var OnboardingToken|null $onboardingToken */
            $onboardingToken = OnboardingToken::query()
                ->where('durable_token_id', $lockedToken->getKey())
                ->lockForUpdate()
                ->first();

            if ($onboardingToken !== null && $onboardingToken->consumed_at === null) {
                $onboardingToken->forceFill(['consumed_at' => now()])->save();
            }

            return response()->json([
                'ok' => true,
                'name' => $lockedToken->name,
                'scope' => $lockedToken->abilities[0] ?? null,
            ]);
        });
    }

    private function supersedePendingOnboarding(string $email, string $scope): void
    {
        /** @var list<OnboardingToken> $tokens */
        $tokens = OnboardingToken::query()
            ->pending()
            ->where('email', $email)
            ->where('scope', $scope)
            ->lockForUpdate()
            ->get()
            ->all();

        foreach ($tokens as $token) {
            if ($token->durable_token_id !== null) {
                $this->revokeDurableById($token->durable_token_id);
            }

            $token->forceFill(['consumed_at' => now()])->save();
        }
    }

    private function revokeActiveDurable(string $email, string $scope): void
    {
        /** @var list<ApiToken> $tokens */
        $tokens = ApiToken::query()
            ->resolvable()
            ->where('name', $email)
            ->lockForUpdate()
            ->get()
            ->all();

        foreach ($tokens as $token) {
            if ($token->hasAbility($scope)) {
                $this->revokeLockedDurable($token);
            }
        }
    }

    private function revokeDurableById(string $tokenId): void
    {
        /** @var ApiToken|null $token */
        $token = ApiToken::query()
            ->whereKey($tokenId)
            ->lockForUpdate()
            ->first();

        if ($token !== null) {
            $this->revokeLockedDurable($token);
        }
    }

    private function revokeLockedDurable(ApiToken $token): void
    {
        $now = now();

        $token->forceFill([
            'expires_at' => $now,
            'revoked_at' => $now,
        ])->save();
    }

    /**
     * @return array{string, OnboardingToken}
     */
    private function mintSwapToken(): array
    {
        do {
            $plainTextToken = bin2hex(random_bytes(32));
            $tokenHash = OnboardingToken::hashToken($plainTextToken);
        } while (OnboardingToken::query()->where('token_hash', $tokenHash)->exists());

        $onboardingToken = OnboardingToken::query()->create([
            'id' => (string) Str::uuid(),
            'email' => 'pending@example.invalid',
            'scope' => Scope::Consume->value,
            'token_hash' => $tokenHash,
            'expires_at' => now()->addDay(),
        ]);

        return [$plainTextToken, $onboardingToken];
    }

    private function lockSwapToken(string $plainTextToken): ?OnboardingToken
    {
        /** @var OnboardingToken|null $onboardingToken */
        $onboardingToken = OnboardingToken::query()
            ->pending()
            ->where('token_hash', OnboardingToken::hashToken($plainTextToken))
            ->lockForUpdate()
            ->first();

        return $onboardingToken;
    }
}
