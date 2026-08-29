# The Console enter endpoint (Console PRD D12 / D13)

`POST /bfc/console/enter` — the door. The vendor auto-submits a form carrying a signed assertion
and its signed handoff state; this deployment verifies it, spends the mint, opens a delegated
session and lands the operator on the path the state named. Until this release nothing could
start a delegated session over HTTP: PR3 shipped the machinery such a session runs on, and this
is what creates one.

`api_version` stays **2**. Every change is additive; no documented request or response shape
moves.

---

## What ships

- **`POST /bfc/console/enter`**, classified `content`, at a fixed `/bfc/console/*` path like
  every other package surface. Mounted only when the routes surface family is on, the Console is
  enabled, AND the reserved `bfc-console` guard resolves to this package's own driver.
- **`GET /bfc/meta` `capabilities` gains `console-enter`** under exactly that predicate, so the
  advertisement and the route can never disagree. `/bfc/console/enter` leaves the contract's
  RESERVED list.
- **`bfc_console_assertion_burns`** — one row per redeemed mint, keyed on a unique digest of
  issuer + `jti`. It holds no secret and it is the one table in this package that is pruned.
- **A per-IP `bfc-console-enter` limiter**, 30/minute, outside everything else on the route.
- **`built-for-cloud.console.return_path_allowlist`** — an optional narrowing of where an entry
  may land. Empty by default, which means any in-app path.

## The three decisions worth reading

### 1. POST, and GET is not routed

Not "GET is refused" — not routed at all, so the answer is `405`. A GET assertion is a live
credential in the customer's own server and CDN logs, in browser history, and in the `Referer`
of the very next request the entered page makes. A verb that does not exist cannot leak one.

The same reasoning marks the bytes themselves: every frame in the package that holds a console
assertion carries `#[SensitiveParameter]`, so a failure below it cannot write a live credential
into a logged stack trace. The vendor `ParagonIE\Paseto` frames are the residue and cannot be
annotated by this package — a refusal decided inside the library still carries the token in the
*previous* exception's trace, which never reaches a response.

*Pinned by* `tests/ConsoleEnterTest.php` ("does not route GET at the enter path, so an assertion
can never ride a query string") and `tests/AssertionSecrecyTest.php` ("marks every frame in this
package that holds console assertion bytes" and "names an unmarked assertion frame when the walk
meets one").

### 2. The signed state, and what it is not

D13 asks for a return URL "relative, allowlisted, and bound by a signed state parameter". The
classic anti-CSRF state is one the relying party planted in the caller's session and compares on
the way back. **This app cannot plant one**: the handoff is a cross-site POST from the issuer's
page, and a `SameSite=Lax` session cookie — Laravel's default — is not sent with a cross-site
POST, so at the moment the entry arrives there is no session with that browser at all. Nor can
the app verify a MAC the issuer computed: it holds only PUBLIC keys, by design, so the one thing
it can verify the issuer produced is an Ed25519 signature.

So the state is bound to the mint by the mint's own signature. The state travels as an opaque
field; its sha256 travels **inside** the assertion, in a new optional `state` claim; and the
endpoint accepts a state only when the two agree — checked before a single byte is decoded.

**That closes** open redirect (the return path is not a request field, and it must still be a
same-origin relative path in every percent-decoded form) and moving a state between mints.

A `.` or `..` **path segment** is refused outright in every decoded form, and the allowlist is
matched against the fully **decoded** path. That rule is about who normalizes: `/admin/../billing`
is legitimately relative, passes every other check, matches an `/admin` prefix — and the browser
resolves it to `/billing` before the app sees it. `/admin/%2e%2e/billing` and
`/admin/%252e%252e/billing` are the same defect one and two layers down. A dot *inside* a
segment is untouched; `/reports..csv` is an ordinary path.

*Pinned by* `tests/ConsoleEnterTest.php` ("refuses a return path that is not a safe same-origin
relative path, whatever the mint signed", "refuses a return path carrying a traversal segment in
any decoded form, allowlist or no allowlist", "leaves a dot inside a segment alone, because that
is an ordinary path" and "matches the allowlist against the fully decoded path, not the raw
one").

**It does not close forced login**, and the contract says so plainly. An attacker holding a
legitimately-minted assertion for their **own** issuer identity can auto-submit it in a victim's
browser, leaving that browser entered as the attacker. No state parameter closes that here,
because every state such an attacker needs is one the issuer minted for them. What bounds it is
the 60–120 second TTL and the single-use burn: the window is short, the token is spent, and the
delegated session carries the **attacker's** audited identity, so nothing done under it is
attributed to the victim. The residue is that a victim may act inside an app under an identity
they did not choose.

*Pinned by* `tests/ConsoleEnterTest.php` ("refuses an entry whose state was tampered with after
the mint signed it", "refuses an entry that presents no state at all", "refuses a mint that
signed no state, whatever state is presented" and "refuses a state lifted from a different
mint").

### 3. The burn is an INSERT, not a read-then-write

`jti` is spent by inserting against a unique index, inside the SAME transaction that opens the
session. A check-then-insert would leave exactly the window single-use exists to close: two
presentations arriving together would both read "not spent" and both mint. With the index, one
insert survives and every other raises a uniqueness violation — **a replay is refused because
the mint is spent, not because something later noticed.** Both directions hold: a redemption
that fails does not spend the mint, and a burn that loses the race takes the redemption with it.

**What the suite does not exercise: a genuine CONCURRENT double presentation.** sqlite
serializes writers in-process, so the tests drive the sequential replay and the
shared-transaction property the race rests on, not the interleaving itself. A mutation-debt row
records it; a two-connection race on a driver with real row locking is what would close it.

*Pinned by* `tests/ConsoleEnterTest.php` ("refuses a genuine second presentation of the same
assertion, because the mint id is spent", "rolls the burn back with the redemption, so the two
commit or fail together", "leaves no spent mint and no session behind a redemption that failed",
"keys the burn on a unique index, which is what makes it atomic", "prunes burn rows whose
assertions expired long enough ago to change no answer" and "keeps a burn row while its
assertion could still be presented").

---

## SOURCE-ADDITIVE CHANGE

`ArtisanBuild\BuiltForCloud\Console\Assertion` gains a nullable `stateDigest` property, and
`Assertion::fromVerifiedClaims()` gains a matching trailing `?string $stateDigest = null`
parameter. Existing callers — positional or named — are unaffected. Nothing in the HTTP contract
changes.

The verifier shape-checks the claim (present means exactly 64 lower-case hex characters; a
malformed one is `invalid_claims`, never a silent absence) and does **not** require it. Requiring
one is the enter endpoint's rule, because entry is the flow D13 governs.

---

## For an issuer

A mint that will be redeemed at `/bfc/console/enter` must carry a `state` claim holding the
lower-case hex sha256 of the exact state bytes it posts. A mint without one verifies fine and
cannot enter (`state_unsigned` in the audit).

## For an operator

Nothing to configure. Optionally narrow where entries may land:

```php
// config/built-for-cloud.php
'console' => [
    // ...
    'return_path_allowlist' => ['/admin', '/orders'],
],
```

Matching ignores the query string and happens at a segment boundary, so `/admin` covers
`/admin/users` and never `/admin-secrets`. An entry that is not an in-app path matches nothing
rather than acting as a wildcard.

## Auditing

Every refused entry lands a `denied_action` lifecycle event with the actor typed
(`credential_holder`) and a bounded reason code in the note — one of the thirteen assertion
refusal reasons or one of the eight entry refusal reasons. The mint id rides as the actor ref
**only** when the token verified far enough for the server to have read one; a verifier refusal
names no actor ref rather than guessing one from bytes it did not trust. The response is
identical for all of them.

**It fails closed.** If the audit write cannot commit, the request answers `500` rather than the
ordinary `403`. An earlier revision swallowed audit failures and served the refusal anyway,
which meant an attacker probing during an audit-store outage left no evidence at all while this
document promised every refusal was recorded. The availability trade is stated rather than
hidden: a deployment whose database is unwritable cannot refuse an entry with a `403` — it also
cannot complete one, and no caller can reach that branch on purpose.

**The responses are byte-identical; the timing is not.** A refusal decided before the signature
check returns sooner than one decided after it, and a **replay** is measurably *slower* than a
bad signature, a wrong audience or an expired token, because it is the only refusal that reaches
the state binding, the shadow-actor upsert and a contended unique insert. A holder of a stolen
assertion can infer whether it has already been redeemed. Neither channel is padded, and that is
a decision: padding a page-load path buys little against facts a prober largely supplies itself.

*Pinned by* `tests/ConsoleEnterTest.php` ("answers a replayed, a wrong-deployment and an expired
assertion with byte-identical responses", "types the actor on every refusal, and names the mint
only when it verified", "records every refusal it serves, one row per refused entry" and "does
not serve a refusal it could not record").

A **successful** entry writes no event to this stream. The credential lifecycle stream is
credential-scoped, and PRD D17 gives actor-typed app-action events their own new stream, which is
a later deliverable. What a successful entry leaves is the shadow-actor row's refreshed
`last_handoff_*` copy and its `updated_at`.
