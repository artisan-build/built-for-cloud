<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\LandingManifest;
use Illuminate\Contracts\View\View;

final readonly class LandingPage
{
    public function __invoke(LandingManifest $manifest): View
    {
        return view('bfc::landing', ['manifest' => $manifest]);
    }
}
