<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use Livewire\Component;

final class PersistentMiddlewareComponent extends Component
{
    public int $count = 0;

    public function increment(): void
    {
        $this->count++;
    }

    public function render(): string
    {
        return '<div data-testid="persistent-middleware-count">{{ $count }}</div>';
    }
}
