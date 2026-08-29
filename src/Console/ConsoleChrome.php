<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Console;

use ArtisanBuild\BuiltForCloud\Http\Controllers\ConsoleChromeScript;
use Illuminate\Support\Facades\Route;

/**
 * WHAT THE ONE LAYOUT RENDERS (Console PRD D11 / D4): the delegated
 * chrome's display values, already bounded, or the fact that there is no
 * chrome to render at all.
 *
 * **IT IS BUILT FROM THE RESOLVED {@see ActingPrincipal} AND FROM
 * NOTHING ELSE.** {@see from()} is the only constructor and it takes
 * that one value; there is no path here that asks a guard, `Auth::` or
 * `$request->user()` a second time. D14's rule is that the principal a
 * request acts as and the chrome it wears are the same decision, and a
 * layout that re-asked would be the failure mode D14 exists to forbid.
 *   Pinned by `tests/ConsoleChromeTest.php` — "follows the resolved
 *   acting principal, not the delegated guard the route does not name".
 *
 * **A NON-DELEGATED RESOLUTION CARRIES NOTHING.** Every display field is
 * null and {@see $delegated} is false, so the layout's branch has
 * nothing it could render even if it were written wrong: a local login
 * sees zero chrome because there is no chrome value, not because a
 * template remembered to check.
 *   Pinned by `tests/ConsoleChromeTest.php` — "renders zero console
 *   chrome for a local authenticated session".
 *
 * **THE DISPLAY CLAIMS ARE BOUNDED AGAIN HERE, AND REFUSED RATHER THAN
 * TRUNCATED.** {@see AssertionVerifier} already bounds `display_name`
 * and `on_behalf_of` to {@see AssertionVerifier::MAX_DISPLAY_LENGTH}
 * characters and rejects control characters — at the door, deliberately,
 * "rather than truncated later by whoever renders it". This class is
 * "whoever renders it", and it applies the SAME bound for a reason the
 * verifier cannot cover: the claims a request acts under are read from
 * the SESSION, and anything that can write the session store can write
 * a claim that never passed a verifier (`ConsoleSession` states that
 * boundary). So an over-long, control-bearing or invalid-UTF-8 value is
 * treated as no value at all and the operator renders as
 * {@see UNNAMED_OPERATOR} — never as a trimmed version of itself, which
 * would be this class inventing a display name.
 *   Pinned by `tests/ConsoleChromeTest.php` — "refuses a display claim
 *   that is over-long, control-bearing or invalid UTF-8 rather than
 *   truncating it".
 *
 * **BOUNDED IS NOT SANITIZED, AND THIS CLASS ESCAPES NOTHING.** A
 * hostile value that is short and printable — `<img src=x
 * onerror=alert(1)>`, a quote that would break out of an attribute — is
 * a legal display claim and passes every check here, exactly as it
 * passes every check the verifier makes. What renders it inert is that
 * every sink in the two templates is a Blade `{{ }}` echo, escaped with
 * `ENT_QUOTES`, in an element body or a double-quoted attribute and
 * never in a script, a style, a URL or an unquoted attribute.
 *   Pinned by `tests/ConsoleChromeTest.php` — "renders a hostile display
 *   name, agency and issuer inert" and "proves the escaping assertion
 *   can fail against an unescaped sink".
 *
 * **THE RESIDUE, named rather than left to be found.** The bound is on
 * SHAPE and the escaping is on SYNTAX; neither is a statement about
 * TRUTH. A well-formed 40-character name that is simply not this
 * operator's renders exactly as a correct one would — the chrome says
 * what this session's handoff claimed, and what makes that claim
 * trustworthy is the vendor's signature at the door, not anything here.
 */
final readonly class ConsoleChrome
{
    /**
     * The id of the chrome's own element. The re-entry interceptor looks
     * for it by this exact string when it has to report a re-entry it
     * cannot perform, so the two are pinned together rather than left to
     * drift.
     *   Pinned by `tests/ConsoleChromeTest.php` — "keeps the chrome
     *   element id the interceptor script looks for".
     */
    public const string ELEMENT_ID = 'bfc-console-chrome';

    /** The name of the route serving {@see ConsoleChromeScript}. */
    public const string SCRIPT_ROUTE = 'bfc.console.chrome-script';

    /**
     * What the chrome calls a delegated operator whose display claim it
     * will not render. It says the true thing that is left — this is a
     * delegated session — and invents no name.
     */
    public const string UNNAMED_OPERATOR = 'Delegated operator';

    private function __construct(
        /** Whether this request's ONE resolution is a delegated one (D14). */
        public bool $delegated,
        /** The operator's display claim, bounded, or null when it will not render. */
        public ?string $operator,
        /** The agency the operator acts for (D4), bounded, or null. */
        public ?string $agency,
        /** This session's delegated role (D8) — an enum, so bounded by construction. */
        public ?ConsoleRole $role,
        /** The trusted issuer's host, from this deployment's OWN config, or null. */
        public ?string $issuer,
        /** Where the re-entry interceptor is served from, or null when it is not mounted. */
        public ?string $scriptUrl,
    ) {}

    /**
     * The chrome for ONE resolved acting principal.
     */
    public static function from(ActingPrincipal $acting): self
    {
        if (! $acting->delegated) {
            return new self(false, null, null, null, null, null);
        }

        return new self(
            delegated: true,
            operator: self::renderable($acting->displayName),
            agency: self::renderable($acting->onBehalfOf),
            role: $acting->role,
            issuer: self::issuerHost(),
            scriptUrl: self::scriptUrl(),
        );
    }

    /**
     * What the chrome calls the operator: their display claim, or the
     * neutral constant when there is none this class will render.
     */
    public function operatorLabel(): string
    {
        return $this->operator ?? self::UNNAMED_OPERATOR;
    }

    /**
     * A display value this class is willing to render, or null.
     *
     * The rules are the verifier's, restated on the render side because
     * the value arrives from the session rather than from the verifier:
     * non-empty, valid UTF-8, no more than
     * {@see AssertionVerifier::MAX_DISPLAY_LENGTH} characters, and no
     * control, line- or paragraph-separator character. Refused, never
     * repaired.
     */
    private static function renderable(?string $value): ?string
    {
        if ($value === null || $value === '') {
            return null;
        }

        if (! mb_check_encoding($value, 'UTF-8')) {
            return null;
        }

        if (mb_strlen($value) > AssertionVerifier::MAX_DISPLAY_LENGTH) {
            return null;
        }

        // Non-zero covers a match (1) and a preg failure (false) alike;
        // a value this check cannot read is one this class will not
        // render.
        return preg_match('/[\p{C}\p{Zl}\p{Zp}]/u', $value) === 0 ? $value : null;
    }

    /**
     * The host of the ONE issuer this deployment trusts (D18), for the
     * "via …" half of D4's attribution.
     *
     * It comes from this app's OWN config rather than from the actor row
     * or the session, and that is the point: the operator and the agency
     * are things an issuer said, while WHICH issuer this deployment
     * answers to is something the deployment decided. It is bounded and
     * escaped anyway, because a config value is not a promise about
     * shape.
     */
    private static function issuerHost(): ?string
    {
        $issuer = config('built-for-cloud.console.issuer');

        if (! is_string($issuer) || $issuer === '') {
            return null;
        }

        $host = parse_url($issuer, PHP_URL_HOST);

        return is_string($host) ? self::renderable($host) : null;
    }

    /**
     * The interceptor's URL as a ROOT-RELATIVE path, or null when the
     * route is not mounted.
     *
     * Null is the honest answer rather than a guessed path: a deployment
     * whose Console is off, or whose `bfc-console` guard is its own,
     * mounts no chrome route, and a `<script src>` pointing at a 404
     * would be this class inventing a destination — the same mistake the
     * structured 401 refuses to make with `reentry_url`.
     */
    private static function scriptUrl(): ?string
    {
        return Route::has(self::SCRIPT_ROUTE) ? route(self::SCRIPT_ROUTE, absolute: false) : null;
    }
}
