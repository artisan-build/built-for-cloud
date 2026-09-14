<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialSummary;
use ArtisanBuild\BuiltForCloud\Exceptions\CredentialVerbRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use ArtisanBuild\BuiltForCloud\Exceptions\RewrapInProgress;
use ArtisanBuild\BuiltForCloud\Exceptions\RotationCutoverIncomplete;
use ArtisanBuild\BuiltForCloud\Exceptions\RotationRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\SelfServiceUnavailable;
use ArtisanBuild\BuiltForCloud\Exceptions\SigningRootRefused;
use ArtisanBuild\BuiltForCloud\Http\Controllers\Concerns\RevealsDelivery;
use ArtisanBuild\BuiltForCloud\MintOptions;
use ArtisanBuild\BuiltForCloud\PersonalCredentialSurface;
use ArtisanBuild\BuiltForCloud\RevokeOutcome;
use ArtisanBuild\BuiltForCloud\RotateOptions;
use ArtisanBuild\BuiltForCloud\UiCredentialPurposes;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\View\View;

final class UiPersonalCredentials
{
    use RevealsDelivery;

    public function index(
        Request $request,
        PersonalCredentialSurface $surface,
        UiCredentialPurposes $purposes,
    ): View {
        return view('bfc::credentials.personal', $this->page($request, $surface, $purposes));
    }

    public function store(
        Request $request,
        PersonalCredentialSurface $surface,
        UiCredentialPurposes $purposes,
    ): Response {
        try {
            $appPurpose = $request->input('app_purpose');

            if (! is_string($appPurpose)) {
                throw InvalidCredentialInput::invalidAppPurposeMapping();
            }

            $result = $surface->mintMineForPurpose(
                $request,
                $purposes->purposeForSubmission($appPurpose),
                MintOptions::fromInput($request->only([
                    'kind', 'name', 'expires_at', 'code_ttl_seconds',
                ])),
            );
        } catch (SelfServiceUnavailable|CredentialVerbRefused $refused) {
            return $this->error($refused->getMessage(), 403);
        } catch (InvalidCredentialInput $invalid) {
            return $this->error($invalid->getMessage(), 422);
        } catch (RewrapInProgress $refused) {
            return $this->error($refused->getMessage(), 409);
        }

        return response()->view('bfc::credentials.personal', $this->page(
            $request,
            $surface,
            $purposes,
            $this->deliveryPayload($result),
        ), 201);
    }

    public function rotate(
        Request $request,
        PersonalCredentialSurface $surface,
        UiCredentialPurposes $purposes,
        string $id,
    ): Response {
        try {
            $result = $surface->rotateMine(
                $request,
                $id,
                RotateOptions::fromInput($request->only(['code_ttl_seconds'])),
            );
        } catch (SelfServiceUnavailable|CredentialVerbRefused $refused) {
            return $this->error($refused->getMessage(), 403);
        } catch (InvalidCredentialInput $invalid) {
            return $this->error($invalid->getMessage(), 422);
        } catch (RotationRefused|RewrapInProgress|SigningRootRefused $refused) {
            return $this->error($refused->getMessage(), 409);
        } catch (RotationCutoverIncomplete $incomplete) {
            return $this->error($incomplete->getMessage(), 500);
        }

        if ($result === null) {
            abort(404);
        }

        return response()->view('bfc::credentials.personal', $this->page(
            $request,
            $surface,
            $purposes,
            $this->deliveryPayload($result->mint),
        ), $result->completedCutover ? 200 : 201);
    }

    public function destroy(
        Request $request,
        PersonalCredentialSurface $surface,
        string $id,
    ): RedirectResponse|Response {
        try {
            $outcome = $surface->revokeMine($request, $id);
        } catch (SelfServiceUnavailable|CredentialVerbRefused $refused) {
            return $this->error($refused->getMessage(), 403);
        }

        if ($outcome === RevokeOutcome::NotFound) {
            abort(404);
        }

        return redirect()->route('bfc.ui.personal-credentials.index', status: 303);
    }

    /**
     * @param  array<string, string>|null  $delivery
     * @return array<string, mixed>
     */
    private function page(
        Request $request,
        PersonalCredentialSurface $surface,
        UiCredentialPurposes $purposes,
        ?array $delivery = null,
    ): array {
        $subject = $surface->subject($request);
        $kinds = $surface->admittedKinds($request);
        $choices = [];

        if ($subject !== null) {
            foreach ($purposes->displayed() as $appPurpose) {
                $purpose = $purposes->purposeForSubmission($appPurpose);

                foreach ($kinds as $kind) {
                    if ($purpose->allowedFor($kind, $subject->type)) {
                        $choices[] = ['appPurpose' => $appPurpose, 'kind' => $kind];
                    }
                }
            }
        }

        return [
            'credentials' => $surface->mine($request),
            'choices' => $choices,
            'delivery' => $delivery,
            'fields' => $surface->renderableFields(),
        ];
    }

    private function error(string $message, int $status): Response
    {
        return response()->view('bfc::credentials.personal', [
            'credentials' => [],
            'choices' => [],
            'delivery' => null,
            'fields' => [],
            'error' => $message,
        ], $status);
    }
}
