<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;

Route::get('/domain', static fn (): array => ['domain' => true]);
