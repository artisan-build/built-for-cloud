<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Mcp;

use Closure;
use Illuminate\Http\Request;

/**
 * The typed effect ceiling published only on the current HTTP request.
 * Missing or invalid values clear prior state rather than inheriting it.
 *
 * Pinned by `tests/McpEffectCeilingTest.php` — "fails closed for missing
 * invalid stale and cross request ceiling state".
 */
final class RequestEffectCeiling
{
    private const string ATTRIBUTE = 'bfc.mcp_effect_ceiling';

    public const int REFUSAL_CODE = -32000;

    public const string REFUSAL_MESSAGE = 'effect_above_ceiling';

    public static function publish(Request $request, ?string $ceiling): void
    {
        $request->attributes->remove(self::ATTRIBUTE);

        if ($ceiling !== null && ($effect = Effect::tryFrom($ceiling)) !== null) {
            $request->attributes->set(self::ATTRIBUTE, $effect);
        }
    }

    public static function current(Request $request): ?Effect
    {
        $ceiling = $request->attributes->get(self::ATTRIBUTE);

        return $ceiling instanceof Effect ? $ceiling : null;
    }

    /**
     * @template T
     *
     * @param  Closure(): T  $callback
     * @return T
     */
    public static function run(Request $request, Effect $ceiling, Closure $callback): mixed
    {
        $hadPrevious = $request->attributes->has(self::ATTRIBUTE);
        $previous = $request->attributes->get(self::ATTRIBUTE);

        $request->attributes->set(self::ATTRIBUTE, $ceiling);

        try {
            return $callback();
        } finally {
            if ($hadPrevious) {
                $request->attributes->set(self::ATTRIBUTE, $previous);
            } else {
                $request->attributes->remove(self::ATTRIBUTE);
            }
        }
    }
}
