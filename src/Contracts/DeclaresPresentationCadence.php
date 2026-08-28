<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Contracts;

/**
 * Opt-in extension of {@see CredentialDeclaration} (the DeclaresBurnMode
 * pattern): the provider's declared presentation cadence — how often a
 * HEALTHY holder of this app's credentials is expected to present one
 * (FLT-R2, PRD 1.5). One declaration per provider, replacing any global
 * healthy-within window: a build-time Composer credential is presented per
 * deploy, a telemetry token per request, and only the app knows which it is.
 *
 * Return null to declare NO cadence: the consuming control plane falls back
 * to its own default, exactly as it does today against an instance that
 * reports nothing. Null is "undeclared", never "unhealthy" — a signal that
 * structurally cannot move must not be read as one that stopped (D2:
 * `unknown` never escalates).
 */
interface DeclaresPresentationCadence
{
    public function presentationCadenceSeconds(): ?int;
}
