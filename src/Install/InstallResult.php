<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Install;

final readonly class InstallResult
{
    public function __construct(
        public InstallTargetState $environment,
        public InstallTargetState $composer,
    ) {}

    public function succeeded(): bool
    {
        return $this->environment !== InstallTargetState::Failed
            && $this->composer !== InstallTargetState::Failed;
    }

    /** @return array{environment: 'unchanged'|'replaced'|'failed', composer: 'unchanged'|'replaced'|'failed'} */
    public function stages(): array
    {
        return [
            'environment' => $this->environment->value,
            'composer' => $this->composer->value,
        ];
    }
}
