<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Console;

use Illuminate\Contracts\Config\Repository;
use RuntimeException;

/**
 * The `bfc-console` guard and provider entries the PACKAGE injects
 * (fleet finding FLEET-C-14): a consuming app adds NOTHING to its
 * `auth.php` to run the Console. The Console is framework machinery, not
 * an app-level auth decision, and a guard every app hand-copies is a
 * guard some app copies wrong — with a `users` provider behind it, which
 * is precisely the principal-type crossing the type-qualified identifier
 * exists to prevent.
 *
 * NOTHING HAPPENS UNLESS THE CONSOLE IS ENABLED. `console.enabled` is
 * off by default and gates every line below. This runs at boot on every
 * request — HTTP and artisan alike, in apps that have the package's
 * routes and migrations switched off — so an unconditional hard failure
 * here is a deploy-time denial of service: a customer who happens to
 * have an auth provider named `bfc-console-actors` would find that
 * upgrading the package stopped their application booting at all, over a
 * feature they never asked for. A deployment that has not opted into the
 * Console cannot be broken by it.
 *
 * TWO RULES, and they point in opposite directions on purpose.
 *
 * **An app's own `bfc-console` guard is never overwritten.** Config an
 * app authored is that app's decision, and silently replacing it at boot
 * would be a package deciding who a deployment's operators are.
 *
 * **A hijacked provider NAME is a hard boot failure.** `bfc-console-actors`
 * is fleet-reserved. If an app has defined it as something else — an
 * Eloquent `users` provider, say — and has NOT defined its own guard,
 * then injecting the guard would build the reserved DELEGATED guard on
 * top of the app's user table: `auth('bfc-console')` would resolve real
 * application users as delegated console operators, and every `role`
 * check downstream would read a claim that never came from an assertion.
 * There is no safe way to proceed and no honest way to guess, so it
 * throws. Loudly at boot beats quietly at runtime, and an app that
 * genuinely wants its own delegated guard has the first rule available:
 * define `auth.guards.bfc-console` and the package steps aside entirely.
 */
final class ConsoleGuardConfiguration
{
    /** The delegated guard's name (Console PRD D10), fleet-reserved. */
    public const string GUARD = 'bfc-console';

    /** The reserved provider name, and the driver it must name. */
    public const string PROVIDER = 'bfc-console-actors';

    /** The guard driver this package registers on the AuthManager. */
    public const string DRIVER = 'bfc-console-session';

    /**
     * Whether this deployment runs the Console. Read with the same
     * `(bool)` coercion the surface-selection flags use, so one flag
     * family behaves one way.
     */
    public static function enabled(?Repository $config = null): bool
    {
        return (bool) ($config?->get('built-for-cloud.console.enabled', false)
            ?? config('built-for-cloud.console.enabled', false));
    }

    /**
     * Whether this deployment serves DELEGATED ENTRY — the condition
     * `POST /bfc/console/enter` is mounted under, and the condition the
     * `console-enter` capability reports.
     *
     * It is deliberately stricter than {@see enabled()}. The enter
     * endpoint hands signed bytes to {@see ConsoleGuard::redeem()}, so
     * it needs the reserved guard name to resolve to THIS package's
     * driver. An app that took the first rule above — defining its own
     * `bfc-console` guard, which the package then never overwrites —
     * has a delegated guard of its own design, and mounting a package
     * endpoint that assumes ours would be the package deciding how
     * somebody else's guard works. So the route is not mounted, the
     * capability is not advertised, and the app owns entry as it owns
     * the guard.
     *
     * Read off the RESOLVED config rather than off a flag, so it
     * answers for what `auth.guards.bfc-console` actually says at boot
     * — including the case where {@see apply()} stepped aside.
     */
    public static function servesDelegatedEntry(?Repository $config = null): bool
    {
        if (! self::enabled($config)) {
            return false;
        }

        $guard = $config?->get('auth.guards.'.self::GUARD) ?? config('auth.guards.'.self::GUARD);

        return is_array($guard) && ($guard['driver'] ?? null) === self::DRIVER;
    }

    /**
     * @throws RuntimeException when the Console is enabled and the reserved provider name is taken
     */
    public static function apply(Repository $config): void
    {
        if (! self::enabled($config)) {
            return;
        }

        $guardKey = 'auth.guards.'.self::GUARD;

        if (is_array($config->get($guardKey))) {
            // The app defined its own delegated guard. It owns the whole
            // arrangement, including whatever provider it points at.
            return;
        }

        $providerKey = 'auth.providers.'.self::PROVIDER;
        $provider = $config->get($providerKey);

        if ($provider === null) {
            $config->set($providerKey, ['driver' => self::PROVIDER]);
        } elseif (! is_array($provider) || ($provider['driver'] ?? null) !== self::PROVIDER) {
            throw new RuntimeException(
                'The auth provider name "'.self::PROVIDER.'" is reserved by built-for-cloud for the '
                .'bfc-console delegated guard, and this application has defined it as something else. '
                .'Building the delegated guard on that provider would resolve application users as '
                .'delegated console operators. Rename your provider, or define your own '
                .'"'.self::GUARD.'" guard to take ownership of it.',
            );
        }

        $config->set($guardKey, ['driver' => self::DRIVER, 'provider' => self::PROVIDER]);
    }
}
