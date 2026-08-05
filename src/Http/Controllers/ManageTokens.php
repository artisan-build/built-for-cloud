<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\TokenGenerator;
use ArtisanBuild\BuiltForCloud\TokenRegistry;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpFoundation\Response;

final class ManageTokens
{
    public function __construct(
        private readonly TokenRegistry $tokens,
        private readonly TokenGenerator $generator,
    ) {}

    public function index(): JsonResponse
    {
        $tokens = ApiToken::query()
            ->orderBy('created_at')
            ->get(['name', 'last_used_at', 'expires_at', 'revoked_at', 'abilities'])
            ->map(static fn (ApiToken $token): array => [
                'name' => $token->name,
                'last_used_at' => $token->last_used_at,
                'expires_at' => $token->expires_at,
                'revoked_at' => $token->revoked_at,
                'abilities' => $token->abilities ?? [],
            ])
            ->values();

        return response()->json($tokens);
    }

    public function store(Request $request): JsonResponse
    {
        /** @var array{name: string, expires_at?: string|null, abilities?: list<string>|null} $validated */
        $validated = $request->validate([
            'name' => ['required', 'string'],
            'expires_at' => ['nullable', 'date'],
            'abilities' => ['nullable', 'array'],
            'abilities.*' => ['string'],
        ]);

        $name = trim($validated['name']);

        if ($name === '' || $name === TokenRegistry::FALLBACK) {
            throw ValidationException::withMessages([
                'name' => ['The token name is invalid.'],
            ]);
        }

        $generated = $this->generator->generate();
        $expiresAt = isset($validated['expires_at'])
            ? Carbon::parse($validated['expires_at'])
            : null;
        $abilities = array_values($validated['abilities'] ?? []);

        $this->tokens->store($name, $generated->hash, $expiresAt, $abilities);

        return response()->json([
            'name' => $name,
            'plaintext' => $generated->plaintext,
            'expires_at' => $expiresAt,
            'abilities' => $abilities,
        ], 201);
    }

    public function destroy(string $name): Response
    {
        $this->tokens->revoke($name);

        return response()->noContent();
    }
}
