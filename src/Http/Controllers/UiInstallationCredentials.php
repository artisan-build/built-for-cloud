<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\Actions\ListCredentials;
use ArtisanBuild\BuiltForCloud\Actions\MintCredential;
use ArtisanBuild\BuiltForCloud\Actions\RevokeCredential;
use ArtisanBuild\BuiltForCloud\Actions\RotateCredential;
use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialManagementScope;
use ArtisanBuild\BuiltForCloud\Exceptions\CredentialVerbRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use ArtisanBuild\BuiltForCloud\Exceptions\RewrapInProgress;
use ArtisanBuild\BuiltForCloud\Exceptions\RotationCutoverIncomplete;
use ArtisanBuild\BuiltForCloud\Exceptions\RotationRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\SigningRootRefused;
use ArtisanBuild\BuiltForCloud\Http\Controllers\Concerns\RevealsDelivery;
use ArtisanBuild\BuiltForCloud\MintOptions;
use ArtisanBuild\BuiltForCloud\RevokeOutcome;
use ArtisanBuild\BuiltForCloud\RolePolicy;
use ArtisanBuild\BuiltForCloud\RotateOptions;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\UiCredentialPurposes;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\View\View;

final class UiInstallationCredentials
{
    use RevealsDelivery;

    private const string DELIVERY_SESSION_KEY = 'bfc.ui.installation-credentials.delivery';

    public function index(
        Request $request,
        ListCredentials $list,
        UiCredentialPurposes $purposes,
    ): View {
        $this->actor($request);

        /** @var array<string, string>|null $delivery */
        $delivery = $request->session()->get(self::DELIVERY_SESSION_KEY);

        return view('bfc::credentials.installation', $this->page($list, $purposes, $delivery));
    }

    public function store(
        Request $request,
        MintCredential $mint,
        UiCredentialPurposes $purposes,
    ): RedirectResponse|Response {
        try {
            $actor = $this->actor($request);
            $appPurpose = $request->input('app_purpose');

            if (! is_string($appPurpose)) {
                throw InvalidCredentialInput::invalidAppPurposeMapping();
            }

            $scope = CredentialManagementScope::memberInstallation();
            $subject = $this->subject($request, $scope);
            $submitted = MintOptions::fromInput($request->only([
                'kind', 'name', 'expires_at', 'code_ttl_seconds',
            ]));
            $result = $mint($subject, new MintOptions(
                kind: $submitted->kind,
                purpose: $purposes->purposeForSubmission($appPurpose),
                name: $submitted->name,
                expiresAt: $submitted->expiresAt,
                codeTtlSeconds: $submitted->codeTtlSeconds,
            ), $actor);
        } catch (CredentialVerbRefused $refused) {
            return $this->error($refused->getMessage(), 403);
        } catch (InvalidCredentialInput $invalid) {
            return $this->error($invalid->getMessage(), 422);
        } catch (RewrapInProgress $refused) {
            return $this->error($refused->getMessage(), 409);
        }

        return redirect()->route('bfc.ui.installation-credentials.index', status: 303)
            ->with(self::DELIVERY_SESSION_KEY, $this->deliveryPayload($result));
    }

    public function rotate(
        Request $request,
        RotateCredential $rotate,
        string $id,
    ): RedirectResponse|Response {
        try {
            $result = $rotate(
                $id,
                RotateOptions::fromInput($request->only(['code_ttl_seconds'])),
                $this->actor($request),
                CredentialManagementScope::memberInstallation(),
            );
        } catch (CredentialVerbRefused $refused) {
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

        return redirect()->route('bfc.ui.installation-credentials.index', status: 303)
            ->with(self::DELIVERY_SESSION_KEY, $this->deliveryPayload($result->mint));
    }

    public function destroy(
        Request $request,
        RevokeCredential $revoke,
        string $id,
    ): RedirectResponse|Response {
        try {
            $outcome = $revoke(
                $id,
                $this->actor($request),
                managementScope: CredentialManagementScope::memberInstallation(),
            );
        } catch (CredentialVerbRefused $refused) {
            return $this->error($refused->getMessage(), 403);
        }

        if ($outcome === RevokeOutcome::NotFound) {
            abort(404);
        }

        return redirect()->route('bfc.ui.installation-credentials.index', status: 303);
    }

    /**
     * @param  array<string, string>|null  $delivery
     * @return array<string, mixed>
     */
    private function page(
        ListCredentials $list,
        UiCredentialPurposes $purposes,
        ?array $delivery = null,
    ): array {
        $scope = CredentialManagementScope::memberInstallation();
        $choices = [];

        foreach ($purposes->displayed() as $appPurpose) {
            $purpose = $purposes->purposeForSubmission($appPurpose);

            foreach (CredentialKind::cases() as $kind) {
                $subjectTypes = array_values(array_filter(
                    $scope->subjectTypes(),
                    static fn (string $subjectType): bool => $purpose->allowedFor($kind, SubjectType::from($subjectType)),
                ));

                if ($subjectTypes !== []) {
                    $choices[] = [
                        'appPurpose' => $appPurpose,
                        'kind' => $kind,
                        'subjectTypes' => $subjectTypes,
                    ];
                }
            }
        }

        return [
            'credentials' => $list(managementScope: $scope),
            'choices' => $choices,
            'delivery' => $delivery,
        ];
    }

    private function subject(Request $request, CredentialManagementScope $scope): Subject
    {
        $subjectType = $request->input('subject_type');
        $subjectRef = $request->input('subject_ref');

        if (! is_string($subjectType) || ! in_array($subjectType, $scope->subjectTypes(), true)) {
            throw InvalidCredentialInput::unknownSubjectType(is_scalar($subjectType) ? (string) $subjectType : gettype($subjectType));
        }

        if (! is_string($subjectRef) || $subjectRef === '') {
            throw InvalidCredentialInput::missingSubjectRef();
        }

        return new Subject(SubjectType::from($subjectType), $subjectRef);
    }

    private function actor(Request $request): AuditActor
    {
        $user = $request->user();

        if (! $user instanceof User || ! RolePolicy::canManageInstallationCredentials($user->role)) {
            abort(403);
        }

        return AuditActor::boundUser((string) $user->getAuthIdentifier());
    }

    private function error(string $message, int $status): Response
    {
        return response()->view('bfc::credentials.installation', [
            'credentials' => [],
            'choices' => [],
            'delivery' => null,
            'error' => $message,
        ], $status);
    }
}
