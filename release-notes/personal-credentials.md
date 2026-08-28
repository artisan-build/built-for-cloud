# The personal-credentials surface (PRD 1.17)

The shared component for **"an authenticated human manages their OWN machine credentials"**:
list mine, mint (revealed once), revoke mine. Three routes, one UI-agnostic surface object, and
underneath them the *same* store and the *same* PR6 action classes the operator surface runs.
No new store, no new verbs, no new credential kind.

| | operator surface | personal surface |
|---|---|---|
| routes | `/bfc/credentials` | `/bfc/me/credentials` |
| gate | admin token or an operator credential holding the verb-family ability | the app's **session** (`bfc.auth`) + the browser stack, CSRF on mutations |
| subject | `subject_type` + `subject_ref`, validated request **input** | derived **server-side** from the authenticated session |
| abilities | chosen by an authenticated **admin** | the app's **self-service mint policy** — never the requesting user |
| kind | any | `bearer` only, until the policy opts one in |
| scope | the whole instance | the caller's own rows, only |

## The one property everything else follows from

**The subject is derived server-side from the authenticated session** (SEC-V3-07), by the app's
own `CredentialDeclaration::resolveSubject()` hook — the hook shipped in 1.18 and reserved for
exactly this consumer. On these routes a `subject_type`, `subject_ref` or `user_id` in the
request body is **not read at all**. It is not validated and rejected with a message an attacker
could probe; it never reaches the store. The mint binds to the session's subject and the session
user's id whatever the body said.

From that:

- the listing returns only the caller's rows — a foreign row is never fetched, not filtered out
  of a rendered answer;
- a revoke acts only inside the caller's subject, and an id belonging to someone else answers
  **404** — the same answer an id that never existed gets. A `403` there would confirm that
  another user's credential exists; a `404` discloses nothing. The ownership check runs inside
  the revoke verb's own locked transaction, not in a check-then-act window in the caller.

Both are named negative tests (`it denies every cross-user path by any crafted input`).

## Authority fails closed — the self-service mint is not the operator mint

The two mint paths derive authority from different places, and conflating them would be a
privilege-escalation hole: the operator mint takes abilities from an authenticated **admin** who
chose them, and the declaration's optional ceilings only *narrow* that choice. A logged-in human
asking the personal route for `["mcp:admin"]` is making a **request, not an authorization**.

So the self-service mint reads none of it. `abilities` is not a field on this route — not
validated and refused, **not read** — and a self-service credential's abilities come only from
an explicit policy the app's declaration provides:

```php
final class Declaration implements CredentialDeclaration, DeclaresSelfServiceMintPolicy
{
    /** @return list<string> */
    public function selfServiceAbilities(Subject $subject): array
    {
        return ['mcp:read'];   // the WHOLE grant, not a ceiling to filter input against
    }

    /** @return list<CredentialKind> */
    public function selfServiceKinds(Subject $subject): array
    {
        return [CredentialKind::Bearer];
    }
}
```

**Absent that contract, a self-service credential is minted with no abilities at all** and in the
`bearer` kind only: it authenticates as its holder and holds no operator, MCP or signing power.
A `kind` the policy does not offer is a `403` naming it — `hmac` delivers signing key material
and `asymmetric` an enrollment code, and neither is reachable by asking.

The grant is *rebuilt*, not filtered, so the guarantee is structural rather than a
request-whitelist rule: a front end calling `PersonalCredentialSurface::mintMine()` directly with
a `MintOptions` full of abilities gets the policy's grant just the same.

**Lifetime deliberately does not fail closed.** A durable's expiry stays caller-chosen with no
default (PRD 1.3 / D1b — TTL defaults on durables are a DO-NOT-BUILD). Abilities are the
escalation vector; abilities are what closes. An app that wants a lifetime ceiling declares one
through `ConstrainsMintedCredentials`, which the mint verb applies to both paths alike.

## Browser routes, and the only ones the package mounts

Every other `/bfc/*` surface is a token API that wants no session. These three are a screen, so
they ride the full browser session stack — cookie encryption, `StartSession`, CSRF validation —
mounted in the **host app's own `web` middleware group** when one is registered, and on the
equivalent concrete stack when it is not. Riding the host's group is the point: the app's session
driver, cookie handling, CSRF customization and anything else it added (locale, tenancy,
impersonation) apply to its own settings screen rather than to a second, divergent copy.

Two consequences: cookie sessions actually start (without `StartSession` every request would
401), and `POST`/`DELETE` require a valid CSRF token — without which a session-riding forgery on
a logged-in user's browser could mint or revoke their credentials. `GET` is not CSRF-checked; it
is where a client picks up the `XSRF-TOKEN` cookie it sends back. No other package route gains
the session stack, which is its own assertion.

## Declaration-driven rendering

`GET /bfc/me/credentials` returns a `fields` block beside the rows:

```json
"fields": { "supported": ["name", "last_used_at"], "unsupported": ["abilities", "expires_at"] }
```

Same discrimination each row already carries in its own `unsupported` list (PRD 1.6: **declared
unsupported, not null**), hoisted once so a UI can choose its columns and its mint form before it
has a single row. **A thinner declaration renders less.** A mint that sets a declared-unsupported
field is still refused, so the surface can never make the declaration a lie.

## Fail-closed when no subject resolves

The package's shipped default declaration returns `null` from `resolveSubject()`. On this surface
that is a **403**, not an empty `200`: "you hold no credentials" is a claim the surface cannot
honestly make when it does not know whose credentials to look for.

## What stays per-app: the meaning, not a branch

The screen is identical for every app. A capstan user-bound credential inherits its user's
authority — the declaration's `authorize()` hook is what says so — and dies with the user, because
offboarding (PRD 1.15) revokes every credential under the subject *and* every credential bound to
the user, and `bfc.auth` then closes the screen to the surviving session. A crate key carries its
own authority, because crate's `authorize()` reads the credential's own abilities and never the
holder's role. Same routes, same store; different declaration.

## Riding along

- `RevealsDelivery` — the single-reveal payload (D7) now lives in one trait both HTTP mint
  surfaces use, so the operator and personal transports cannot drift about what leaves and how.
- `bfc.auth` on an app with **no auth guard configured at all** (the headless shape
  `HeadlessThrottleTest` describes) now answers `401` instead of erroring out of the AuthManager.
  Structural absence of a guard means "nobody is authenticated" — the same stance `CredentialGuard`
  already takes; a *configured* guard that throws during resolution still propagates.
- `ListCredentials` and `RevokeCredential` gained an optional subject **argument** (never anything
  read off a request) so "mine" needs no second verb.

## Consumers

crate's Phase-2.3 screen is the first consumer and the proving ground; capstan's
`/settings/tokens` converges onto it afterwards. Neither app is in this release — this ships the
shared component only.
