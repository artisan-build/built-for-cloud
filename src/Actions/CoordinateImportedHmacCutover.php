<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Actions;

use ArtisanBuild\BuiltForCloud\BoundCredentialScope;
use ArtisanBuild\BuiltForCloud\Contracts\HmacCredentialIssuerClient;
use ArtisanBuild\BuiltForCloud\CutOverImportedHmacResult;
use ArtisanBuild\BuiltForCloud\Exceptions\CrossStoreCutoverIncomplete;
use Throwable;

/** Preserves the install-source-receiver ordering without claiming distributed atomicity. */
final class CoordinateImportedHmacCutover
{
    public function __construct(private readonly CutOverImportedHmacCredential $cutOver) {}

    public function activate(
        BoundCredentialScope $scope,
        HmacCredentialIssuerClient $trustedIssuer,
        string $predecessorId,
        string $replacementId,
        string $deliveryFingerprint,
    ): CutOverImportedHmacResult {
        $receipt = $trustedIssuer->activate($scope, $predecessorId, $replacementId, $deliveryFingerprint);

        return $this->applyOrReportIncomplete($scope, $receipt);
    }

    public function recover(
        BoundCredentialScope $scope,
        HmacCredentialIssuerClient $trustedIssuer,
        string $predecessorId,
        string $replacementId,
    ): CutOverImportedHmacResult {
        $receipt = $trustedIssuer->cutoverStatus($scope, $predecessorId, $replacementId);

        return $this->applyOrReportIncomplete($scope, $receipt);
    }

    private function applyOrReportIncomplete(
        BoundCredentialScope $scope,
        \ArtisanBuild\BuiltForCloud\IssuerHmacCutoverReceipt $receipt,
    ): CutOverImportedHmacResult {
        try {
            return ($this->cutOver)($scope, $receipt);
        } catch (Throwable $failure) {
            if ($receipt->predecessorCredentialId === null || $receipt->predecessorExpiresAt === null) {
                throw $failure;
            }

            throw new CrossStoreCutoverIncomplete(
                $receipt->predecessorCredentialId,
                $receipt->replacementCredentialId,
                $receipt->predecessorExpiresAt,
                $failure,
            );
        }
    }
}
