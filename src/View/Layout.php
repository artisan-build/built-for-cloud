<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\View;

use Illuminate\Contracts\View\View as ViewContract;
use Illuminate\Support\Facades\Config;
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
    /** Default an untitled page to the app's name. */
    public function __construct(public ?string $title = null)
    {
        $this->title ??= Config::string('app.name');
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
