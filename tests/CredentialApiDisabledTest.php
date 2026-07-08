<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('does not register credential api routes by default', function (): void {
    $this->postJson('/api/credentials', ['name' => 'ci'])->assertNotFound();
    $this->getJson('/api/credentials')->assertNotFound();
});
