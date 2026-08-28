# The personal-credentials surface (PRD 1.17)

The shared component for **"an authenticated human manages their OWN machine credentials"**:
list mine, mint (revealed once), revoke mine. Three routes, one UI-agnostic surface object, and
underneath them the *same* store and the *same* PR6 action classes the operator surface runs.
No new store, no new verbs, no new credential kind.

| | operator surface | personal surface |
|---|---|---|
| routes | `/bfc/credentials` | `/bfc/me/credentials` |
| gate | admin token or an operator credential holding the verb-family ability | the app's **session** (`bfc.auth`) |
| subject | `subject_type` + `subject_ref`, validated request **input** | derived **server-side** from the authenticated session |
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
