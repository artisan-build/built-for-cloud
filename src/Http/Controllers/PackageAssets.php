<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use Symfony\Component\HttpFoundation\BinaryFileResponse;

/**
 * Serves the default layout's compiled stylesheet, fonts and images straight from
 * the installed package, so an app picks up a package update's styles
 * without rebuilding or republishing anything of its own.
 */
final class PackageAssets
{
    /** The route admits only these names, so nothing outside resources/dist is reachable. */
    public const string PATTERN = 'bfc\.css|fonts/[a-z0-9-]+\.woff2|img/[a-z0-9-]+\.webp';

    /** The media type served for each admitted extension. */
    protected const array CONTENT_TYPES = [
        'css' => 'text/css; charset=utf-8',
        'woff2' => 'font/woff2',
        'webp' => 'image/webp',
    ];

    /** Stream one bundled asset with a year-long immutable cache; the layout's ?v= query busts it. */
    public function __invoke(string $path): BinaryFileResponse
    {
        $file = dirname(__DIR__, 3)."/resources/dist/{$path}";

        abort_unless(is_file($file), 404);

        return new BinaryFileResponse($file, 200, [
            'Content-Type' => self::CONTENT_TYPES[pathinfo($path, PATHINFO_EXTENSION)],
            'Cache-Control' => 'public, max-age=31536000, immutable',
        ]);
    }
}
