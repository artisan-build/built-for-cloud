<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\Contracts\AuthorizesCredentialVerbs;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresPresentationCadence;
use ArtisanBuild\BuiltForCloud\CredentialVerb;
use ArtisanBuild\BuiltForCloud\Exceptions\RotationCutoverIncomplete;
use ArtisanBuild\BuiltForCloud\Exceptions\RotationRefused;
use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\TokenGenerator;
use ArtisanBuild\BuiltForCloud\TokenRegistry;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\Rule;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpFoundation\Response;

/**
 * The credential API over the `api_tokens` store. Every route sits behind
 * the admin-token gate (`bfc.token.admin`), and every verb is ALSO run
 * through the declaration's per-verb authority matrix (PRD 1.4) — which can
 * only narrow what the gate allows, never widen it. The target subject the
 * matrix sees is always what the ROW declares; nothing a caller supplies in
 * any input can substitute for it (SEC-V3-07: possession proves nothing).
 */
final class ManageTokens
{
    /**
     * The response header carrying the provider's declared presentation
     * cadence once per listing. A header rather than a body envelope,
     * deliberately: the listing body has always been a bare JSON array,
     * and wrapping it would break every existing consumer. Omitted when
     * the declaration declares no cadence.
     */
    public const CADENCE_HEADER = 'BFC-Presentation-Cadence';

    public function __construct(
        private readonly TokenRegistry $tokens,
        private readonly TokenGenerator $generator,
    ) {}

    public function index(Request $request): JsonResponse
    {
        $cadence = $this->declaredCadence();

        // `list_metadata` granularity is PER ROW: each row the declaration
        // denies is filtered out, so a blanket deny yields an empty listing
        // (200 []), not a 403 — "may see that it exists" is a per-credential
        // question and a partial answer is still an honest one.
        $tokens = ApiToken::query()
            ->orderBy('created_at')
            ->get([
                'id',
                'name',
                'last_used_at',
                'request_count',
                'expires_at',
                'revoked_at',
                'abilities',
                'subject_type',
                'subject_ref',
                'client_identity',
                'client_identity_last_seen_at',
            ])
            ->filter(fn (ApiToken $token): bool => $this->verbAllowed(CredentialVerb::ListMetadata, $token->subject(), $request))
            ->map(static fn (ApiToken $token): array => [
                'name' => $token->name,
                'last_used_at' => $token->last_used_at,
                'expires_at' => $token->expires_at,
                'revoked_at' => $token->revoked_at,
                'abilities' => $token->abilities ?? [],
                // null is meaningful here: no client has ever presented this token. Unlike
                // abilities above, it is deliberately NOT coerced to an empty value.
                'client_identity' => $token->client_identity,
                'client_identity_last_seen_at' => $token->client_identity_last_seen_at,
                'id' => $token->id,
                'request_count' => $token->request_count,
                // Nullable, meaning "this row predates subjects" — never guessed.
                'subject_type' => $token->subject_type?->value,
                'subject_ref' => $token->subject_ref,
                'status' => $token->reportedStatus()->value,
                // Per provider, so identical on every row; repeated per row
                // because a row is the unit a fleet screen renders.
                'presentation_cadence_seconds' => $cadence,
            ])
            ->values();

        $response = response()->json($tokens);

        if ($cadence !== null) {
            $response->header(self::CADENCE_HEADER, (string) $cadence);
        }

        return $response;
    }

    public function store(Request $request): JsonResponse
    {
        // The issue verb against the legacy store has no single target row,
        // so the matrix sees a null subject.
        if (! $this->verbAllowed(CredentialVerb::Issue, null, $request)) {
            abort(403);
        }

        /** @var array{name: string, expires_at?: string|null, abilities?: list<string>|null} $validated */
        $validated = $request->validate([
            'name' => ['required', 'string'],
            'expires_at' => ['nullable', 'date'],
            'abilities' => ['nullable', 'array'],
            'abilities.*' => ['string', Rule::in(Scope::values())],
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

        // The store plus its `issued` audit event, one transaction —
        // closing the legacy mint path's gap in the lifecycle stream.
        DB::transaction(function () use ($request, $name, $generated, $expiresAt, $abilities): void {
            $token = $this->tokens->store($name, $generated->hash, $expiresAt, $abilities);

            app(LifecycleEventRecorder::class)->record(
                event: LifecycleEventType::Issued,
                credentialId: (string) $token->getKey(),
                actor: $this->actor($request),
                credentialExpiresAt: $expiresAt,
            );
        });

        return response()->json([
            'name' => $name,
            'plaintext' => $generated->plaintext,
            'expires_at' => $expiresAt,
            'abilities' => $abilities,
        ], 201);
    }

    /**
     * Revoke by NAME — the CLI-compatibility verb. It revokes EVERY
     * resolvable row of the name (existing semantics); the by-id route
     * below is the precise verb. FAIL CLOSED against the matrix: if the
     * declaration denies `revoke` for ANY resolvable row of the name, the
     * whole request 403s and nothing is revoked — a name is not a licence
     * to kill whichever subset happens to be permitted.
     *
     * The rows are selected UNDER the revocation's own transaction, locked,
     * authorized as an id set, and the write is keyed on exactly that set —
     * never re-queried by name — so what dies is precisely what was
     * authorized. A same-named row created after the locked select is not
     * in this revocation; the response body reports the ids that actually
     * died so the caller is never guessing.
     */
    public function destroy(Request $request, string $name): JsonResponse
    {
        $actor = $this->actor($request);

        /** @var list<string> $revokedIds */
        $revokedIds = DB::transaction(function () use ($request, $name, $actor): array {
            /** @var list<array{id: string, subject: ?Subject}> $targets */
            $targets = ApiToken::query()
                ->where('name', $name)
                ->resolvable()
                ->lockForUpdate()
                ->get(['id', 'subject_type', 'subject_ref'])
                ->map(static fn (ApiToken $token): array => ['id' => $token->id, 'subject' => $token->subject()])
                ->all();

            foreach ($targets as $target) {
                if (! $this->verbAllowed(CredentialVerb::Revoke, $target['subject'], $request)) {
                    abort(403);
                }
            }

            $ids = array_column($targets, 'id');

            $this->tokens->revokeIds($ids, $actor);

            return $ids;
        });

        return response()->json(['revoked_ids' => $revokedIds]);
    }

    /**
     * Revoke by ID — the precise verb (D2 consequence 1): exactly this row
     * dies; a same-named sibling survives. 404 for an id that never
     * existed; idempotently 204 for a row already dead.
     */
    public function destroyById(Request $request, string $id): Response
    {
        /** @var ApiToken|null $target */
        $target = ApiToken::query()->find($id);

        if ($target === null) {
            abort(404);
        }

        // The matrix consults the subject the ROW declares — never anything
        // the request supplies (SEC-V3-07).
        if (! $this->verbAllowed(CredentialVerb::Revoke, $target->subject(), $request)) {
            abort(403);
        }

        $this->tokens->revokeById($id, $this->actor($request));

        return response()->noContent();
    }

    /**
     * Rotate by ID — the primary rotation verb on the legacy store
     * (PRD 1.7, D6), riding the same two-segment `/id/{id}` path as the
     * precise revoke so it can never collide with a name route. The
     * replacement inherits the source row's exact abilities, subject
     * binding and remaining expiry; the old row stays resolvable through
     * its one-hour grace window (`emergency: true` collapses it) and then
     * dies by its own expiry.
     *
     * The plaintext is generated server-side and appears exactly once, in
     * this response — the legacy store's established single reveal (the
     * mint route's own convention). A 409 names a source that no longer
     * resolves; a 500 is failure path B, naming the still-live old row
     * that revoke-by-id can always kill.
     */
    public function rotateById(Request $request, string $id): JsonResponse
    {
        /** @var ApiToken|null $target */
        $target = ApiToken::query()->find($id);

        if ($target === null) {
            abort(404);
        }

        // The matrix consults the subject the ROW declares — never anything
        // the request supplies (SEC-V3-07).
        if (! $this->verbAllowed(CredentialVerb::Rotate, $target->subject(), $request)) {
            abort(403);
        }

        $generated = $this->generator->generate();

        try {
            $result = $this->tokens->rotateById(
                $id,
                $generated->hash,
                $request->boolean('emergency'),
                $this->actor($request),
            );
        } catch (RotationRefused $refused) {
            return response()->json(['message' => $refused->getMessage()], 409);
        } catch (RotationCutoverIncomplete $incomplete) {
            return response()->json(['message' => $incomplete->getMessage()], 500);
        }

        $replacement = $result->token;

        // The completion path minted NOTHING (the standing successor was
        // already live), so the pre-generated plaintext corresponds to no
        // stored credential and must never be presented as one: a 200
        // (nothing created) without a plaintext field, naming the
        // successor and the retired row.
        if ($result->completedCutover) {
            return response()->json([
                'id' => $replacement->id,
                'name' => $replacement->name,
                'expires_at' => $replacement->expires_at,
                'abilities' => $replacement->abilities ?? [],
                'superseded_id' => $id,
                'completed_cutover' => true,
            ]);
        }

        return response()->json([
            'id' => $replacement->id,
            'name' => $replacement->name,
            'plaintext' => $generated->plaintext,
            'expires_at' => $replacement->expires_at,
            'abilities' => $replacement->abilities ?? [],
            'superseded_id' => $id,
        ], 201);
    }

    /**
     * The verb-aware authority matrix (PRD 1.4). A declaration that does
     * not implement the opt-in contract allows every verb — the admin gate
     * in front of this controller already enforces operator scope, and the
     * matrix exists to NARROW that, never to widen it.
     */
    private function verbAllowed(CredentialVerb $verb, ?Subject $subject, Request $request): bool
    {
        $declaration = $this->declaration();

        if (! $declaration instanceof AuthorizesCredentialVerbs) {
            return true;
        }

        return $declaration->authorizeVerb($verb, $subject, $request);
    }

    private function declaredCadence(): ?int
    {
        $declaration = $this->declaration();

        if (! $declaration instanceof DeclaresPresentationCadence) {
            return null;
        }

        return $declaration->presentationCadenceSeconds();
    }

    /**
     * Resolved per call rather than via the constructor: the router caches
     * controller instances per route, so an injected declaration would
     * outlive a rebinding (and pin one instance for a long-lived worker's
     * whole life). The guard resolves its declaration the same way.
     */
    private function declaration(): CredentialDeclaration
    {
        return app(CredentialDeclaration::class);
    }

    /**
     * D8's actor on the HTTP path: the admin token the gate authenticated,
     * stashed by the middleware. The id, never the credential.
     */
    private function actor(Request $request): ?AuditActor
    {
        $actorId = $request->attributes->get('bfc.actor_token_id');

        return is_string($actorId) && $actorId !== '' ? AuditActor::adminToken($actorId) : null;
    }
}
