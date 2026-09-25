<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\View;

use ArtisanBuild\BuiltForCloud\LandingManifest;
use Illuminate\Contracts\View\View as ViewContract;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\View;
use Illuminate\View\Component;
use InvalidArgumentException;

/**
 * The default Built for Cloud page shell, rendered for `<x-bfc-layout>` and
 * for every full-page Livewire component. An app replaces it by naming its
 * own Component class in BUILT_FOR_CLOUD_LAYOUT; extending this class keeps
 * the same props. A replacement's render() must return a View instance,
 * which Livewire requires of a full-page layout.
 */
class Layout extends Component
{
    /** Where the Scalpels wordmark in the header takes the user: the dashboard every app is launched from. */
    public const string SCALPELS_URL = 'https://scalpels.app/dashboard';

    /** The app this page belongs to, when it has declared a manifest. */
    public ?LandingManifest $manifest;

    /** The package stylesheet, versioned by content, or null when the package's routes are switched off. */
    public ?string $stylesheetUrl;

    /** The Scalpels wordmark the header carries, or null when the package's routes are switched off. */
    public ?string $wordmarkUrl;

    /** Default an untitled page to the app's name and gather what the header shows. */
    public function __construct(public ?string $title = null)
    {
        $this->title ??= Config::string('app.name');
        $this->manifest = App::make(LandingManifest::class);
        $this->stylesheetUrl = Route::has('bfc.assets')
            ? route('bfc.assets', 'bfc.css').'?v='.substr((string) md5_file(dirname(__DIR__, 2).'/resources/dist/bfc.css'), 0, 12)
            : null;
        $this->wordmarkUrl = Route::has('bfc.assets') ? route('bfc.assets', 'img/scalpels-wordmark.webp') : null;
    }

    /**
     * Build the configured layout rather than this one. Blade compiles
     * `<x-bfc-layout>` against this class and caches the result, so choosing
     * the layout here, at render time, keeps a changed BUILT_FOR_CLOUD_LAYOUT
     * from being ignored by views compiled before the change.
     *
     * @param  array<string, mixed>  $data
     * @return Component
     */
    public static function resolve($data)
    {
        $layout = Config::string('built-for-cloud.layout', self::class);

        if (static::class !== self::class || $layout === self::class) {
            return parent::resolve($data);
        }

        if (! is_subclass_of($layout, Component::class)) {
            throw new InvalidArgumentException("BUILT_FOR_CLOUD_LAYOUT [{$layout}] must name a class extending ".Component::class.'.');
        }

        return $layout::resolve($data);
    }

    /** Render the package's default shell view. */
    public function render(): ViewContract
    {
        return View::make('bfc::layout');
    }
}
