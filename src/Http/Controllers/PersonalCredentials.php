<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\CredentialSummary;
use ArtisanBuild\BuiltForCloud\Exceptions\CredentialVerbRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use ArtisanBuild\BuiltForCloud\Exceptions\RewrapInProgress;
use ArtisanBuild\BuiltForCloud\Exceptions\SelfServiceUnavailable;
use ArtisanBuild\BuiltForCloud\Http\Controllers\Concerns\RevealsDelivery;
use ArtisanBuild\BuiltForCloud\MintOptions;
use ArtisanBuild\BuiltForCloud\PersonalCredentialSurface;
use ArtisanBuild\BuiltForCloud\RevokeOutcome;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The personal-credentials surface's HTTP transport (PRD 1.17): the
 * SESSION-authenticated half of the same PR6 verbs {@see ManageCredentials}
 * serves to operators. One store, one set of actions, two front doors —
 * and the difference between them is exactly one thing, the thing that
 * makes this surface safe to hand a logged-in human:
 *
 * **The subject is derived server-side from the authenticated session**
 * (SEC-V3-07), by the app's own declaration. The operator route takes
 * `subject_type`/`subject_ref` as validated INPUT; this one reads neither,
 * on any verb. A crafted `subject_ref`, `user_id` or `subject_type` in a
 * request body is not rejected with a message — it is never looked at, and
 * the mint binds to the session's subject and the session's user whatever
 * the body said.
 *
 * The routes carry no operator ability and no admin token: they sit behind
 * the session gate (`bfc.auth`) the consuming app's authenticated human
 * already passes, which is also where an offboarded user's surviving
 * session dies (PRD 1.15).
 *
 * Part of the versioned public contract (docs/http-contract.md).
 */
final class PersonalCredentials
{
    use RevealsDelivery;

    /**
     * List MINE. Only the derived subject's rows — another subject's rows
     * are not filtered out of a rendered answer, they are never fetched.
     *
     * The `fields` block is the declaration-driven rendering contract
     * (PRD 1.17 + 1.6): `supported` is what a front end draws, and
     * `unsupported` names what this app's store structurally cannot
     * express — the same discrimination each row carries in its own
     * `unsupported` list, hoisted once so a UI can decide its columns
     * before it has a single row. A thinner declaration renders less.
     */
    public function index(Request $request, PersonalCredentialSurface $surface): JsonResponse
    {
        // Deliberately NOT a `sensitive_read` audit event. GATE-3.7 audits
        // the OPERATOR listing because an operator reading the whole
        // instance is an act worth a record; a person reading their own
        // three rows on their own settings screen is not, and writing one
        // per page view would bury the operator signal it exists to make
        // findable.
        try {
            $summaries = $surface->mine($request);
        } catch (SelfServiceUnavailable $unavailable) {
            return $this->unavailable($unavailable);
        }

        return response()->json([
            'credentials' => array_map(
                static fn (CredentialSummary $summary): array => $summary->toArray(),
                $summaries,
            ),
            'fields' => [
                'supported' => $surface->renderableFields(),
                'unsupported' => $surface->unsupportedFields(),
            ],
        ]);
    }

    /**
     * Mint MINE. The options a caller may choose are the same ones the
     * operator transport normalizes through the SHARED input object, MINUS
     * the two that decide whose credential this is: `subject_type` /
     * `subject_ref` (the session's) and `user_id` (the session user's).
     * They are absent from the whitelist below, so no validation message
     * can be probed for their handling either.
     */
    public function store(Request $request, PersonalCredentialSurface $surface): JsonResponse
    {
        try {
            $result = $surface->mintMine($request, MintOptions::fromInput($request->only([
                'kind', 'name', 'abilities', 'expires_at', 'code_ttl_seconds',
            ])));
        } catch (SelfServiceUnavailable $unavailable) {
            return $this->unavailable($unavailable);
        } catch (InvalidCredentialInput $invalid) {
            return response()->json(['message' => $invalid->getMessage()], 422);
        } catch (CredentialVerbRefused $refused) {
            return response()->json(['message' => $refused->getMessage()], 403);
        } catch (RewrapInProgress $refused) {
            return response()->json(['message' => $refused->getMessage()], 409);
        }

        return response()->json([
            'credential' => $result->summary->toArray(),
            // The transport boundary: the ONE reveal (D7), the same
            // carrier rule as the operator mint route.
            'delivery' => $this->deliveryPayload($result),
        ], 201);
    }

    /**
     * Revoke MINE. An id outside the caller's own subject answers 404 —
     * the SAME answer an id that never existed gets, deliberately: on a
     * self-service surface a 403 would confirm that someone else's
     * credential exists, which is a disclosure a 404 does not make.
     */
    public function destroy(Request $request, PersonalCredentialSurface $surface, string $id): Response
    {
        try {
            $outcome = $surface->revokeMine($request, $id);
        } catch (SelfServiceUnavailable $unavailable) {
            return $this->unavailable($unavailable);
        } catch (CredentialVerbRefused $refused) {
            return response()->json(['message' => $refused->getMessage()], 403);
        }

        return match ($outcome) {
            RevokeOutcome::NotFound => abort(404),
            // Idempotently 204 for a row already dead, matching the
            // operator verb's semantics.
            RevokeOutcome::Revoked, RevokeOutcome::AlreadyDead => response()->noContent(),
        };
    }

    /**
     * Fail-closed (PRD 1.17): the app declares no personal-credential
     * subject for this session, so there is nothing to act on. A 403 and
     * not an empty 200, because "you hold none" is a claim this surface
     * cannot honestly make when it does not know whose credentials to
     * look for.
     */
    private function unavailable(SelfServiceUnavailable $unavailable): JsonResponse
    {
        return response()->json(['message' => $unavailable->getMessage()], 403);
    }
}
