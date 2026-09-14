<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use RuntimeException;

final readonly class LandingManifest
{
    public function __construct(
        public string $name,
        public string $slug,
        public string $description,
        public string $icon,
        public string $productUrl,
    ) {}

    public static function fromConfiguration(): self
    {
        $manifest = config('built-for-cloud.manifest');

        if (! is_array($manifest)) {
            throw new RuntimeException('The built-for-cloud landing manifest must contain five strings.');
        }

        $values = [];

        foreach (['name', 'slug', 'description', 'icon', 'product_url'] as $key) {
            $value = $manifest[$key] ?? null;

            if (! is_string($value) || trim($value) === '') {
                throw new RuntimeException("The built-for-cloud landing manifest [{$key}] must be a non-empty string.");
            }

            $values[$key] = $value;
        }

        /** @var array{name: string, slug: string, description: string, icon: string, product_url: string} $values */

        if (preg_match('/^[a-z0-9]+(?:-[a-z0-9]+)*$/D', $values['slug']) !== 1) {
            throw new RuntimeException('The built-for-cloud landing manifest [slug] must be lower-kebab-case.');
        }

        if (! self::isAbsoluteHttpsUrl($values['icon'])) {
            throw new RuntimeException('The built-for-cloud landing manifest [icon] must be an absolute HTTPS URL.');
        }

        if (! self::isAbsoluteHttpsUrl($values['product_url'])
            || strtolower((string) parse_url($values['product_url'], PHP_URL_HOST)) !== 'scalpels.app') {
            throw new RuntimeException('The built-for-cloud landing manifest [product_url] must be an absolute HTTPS URL on scalpels.app.');
        }

        return new self(
            name: $values['name'],
            slug: $values['slug'],
            description: $values['description'],
            icon: $values['icon'],
            productUrl: $values['product_url'],
        );
    }

    private static function isAbsoluteHttpsUrl(string $value): bool
    {
        return filter_var($value, FILTER_VALIDATE_URL) !== false
            && strtolower((string) parse_url($value, PHP_URL_SCHEME)) === 'https'
            && is_string(parse_url($value, PHP_URL_HOST));
    }
}
