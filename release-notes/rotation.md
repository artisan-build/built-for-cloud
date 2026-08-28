# Rotation, correctly ordered (PRD 1.7 / D6)

Rotate-by-id becomes the primary rotation verb on BOTH stores, the two verified D6 defects are
fixed, and every make-before-break failure path is specified, tested, and carries a stated
cleanup.

## The D6 fix — a behaviour change for legacy rotation

`TokenRegistry::rotate()` used to store its replacement with **no abilities and no expiry**.
Because `hasAbility()` fails closed, every rotation of a scoped token minted a replacement that
could not pass a single ability check — rotation was unusable for any scoped caller, and
`--emergency` made the outage immediate.

**Now:** the replacement inherits the **exact ability set, the subject binding
(`subject_type`/`subject_ref`), and the remaining expiry** of the row it replaces. If your
tooling relied on rotation minting an unscoped, non-expiring token, that reliance was the
defect — the replacement now authenticates exactly as far as the original did.

Grace-window mechanics are unchanged: the old row keeps its `rotated_at` stamp and stays
resolvable for one hour (`--emergency` = dead immediately), then dies by its own expiry — with
one tightening: rotation never *extends* a lifetime, so an old row already expiring sooner than
grace end keeps its earlier death.

## Refuse-on-ambiguity (both stores' name paths)

Token names are not unique — rotation itself depends on that during grace. So name-based
rotation (`token:rotate <name>`, `bfc:credential:rotate --name=<name>`) now **refuses whenever
more than one resolvable row shares the name**, naming the count; it never picks one, because
nothing says which lifetime or ability set the replacement should inherit (SEC-5). It also
refuses a name with no resolvable row: rotation replaces, the mint verbs create. Rotate by id.

## The rotate verb, two transports (unified store)

`bfc:credential:rotate <id> --local` and `POST /bfc/credentials/{id}/rotate` run the ONE
`RotateCredential` action: shared input normalization, the verb matrix consulted (`rotate`),
identical refusals, and the transport-parity suite extended with like-for-like rotate legs.
The legacy store gains its own by-id entry points: `TokenRegistry::rotateById()` and
`POST /api/credentials/id/{id}/rotate`.

## Override semantics — opt-in, fail closed

Default rotation preserves everything exactly. **Any** provided change to abilities or expiry
— widening or narrowing alike; predictability beats cleverness — requires the explicit
`--override` flag (HTTP `override: true`) and is a **separately authorized operation that
fails closed**: the declaration must opt in by implementing `AuthorizesRotationOverrides`
(which receives the requested delta), and a declaration that has not opted in denies every
override. Routine, preserving rotation is unaffected. An authorized override must also fit the
same ceilings the mint verb enforces (`ConstrainsMintedCredentials`), checked on the
replacement's effective shape — an override can never produce a credential a mint could not
have been authorized for. Every override is audited with the `override` reason code plus the
delta in the note.

**Presence is the override signal, so "explicitly none" is expressible on both transports:**
`{"override": true, "expires_at": null}` (CLI `--override --clear-expiry`) turns a finite
expiry into NO expiry, and `{"override": true, "abilities": []}` (CLI `--override
--clear-abilities`) narrows to NO abilities. Absent fields always mean "preserve the
source's". **The CLI's explicitly empty values carry the HTTP meaning**: `--abilities=` and
`--expires=` are present-and-none — byte-identical to the HTTP transport's `""` — not
absence; they flow through the one shared normalization, so both transports accept and refuse
the identical inputs with the identical messages.

## The lineage never forks — and a stamped row's rotation can be COMPLETED

A row already superseded by rotation (`rotated_at` set) never mints again on either store: a
second rotation of one source would fork the lineage (A→B and A→C) and supersession that
forks answers nothing. But re-invoking the rotate verb on a stamped row whose
lineage-recorded successor is still live performs the narrowly-scoped **cutover completion**:
retirement of the old row only (immediate under `emergency` — the compromised-old-secret
case), audited as a `rotated` event with reason `cutover_completion`, nothing minted, no
secret. That makes a failed phase-B cutover recoverable under the rotate verb's own authority
— a declaration allowing `rotate` but denying `revoke` is no longer stuck — without becoming
a revoke bypass: an unstamped row always gets the full make-before-break, and a stamped row
whose chain is dead refuses (mint a fresh credential). HTTP reports a completion as `200`
with `completed_cutover: true` and a `none` delivery (legacy: no `plaintext` field); the CLI
prints "Cutover completed" and reveals nothing.

## The exchange sweep respects rotation grace on the unified store — honestly

The onboarding exchange's name+scope sweep spares unified-store rows in rotation grace,
exactly as it always has on `api_tokens` — a sweep that killed a grace row would break the
make-before-break window rotation exists to provide. The exemption requires the SHAPE the
rotate verb actually leaves — the `rotated_at` stamp **and** an expiry bounded by the grace
horizon — so a stamped-but-unbounded row (an incomplete cutover, or anything else) is swept
like an ordinary collision rather than exempted forever. And the marker cannot be forged:
`rotated_at` is no longer mass-assignable on the unified store — only the rotate verb's own
explicit write asserts it.

## Names are byte-exact

Name-based rotation (and the name verbs generally) match the exact stored bytes: no trimming,
no case normalization — `CI` and `ci` are different names. A case-insensitive database
collation can only *widen* a name's match set, which trips refuse-on-ambiguity rather than
touching an unintended row.

## Per-kind semantics (D6 point 6)

- **bearer / basic** — a fresh secret, delivered once through the sealed carrier
  (`MintedSecret`), TTY print or HTTP response field.
- **asymmetric** — a fresh **enrollment code** against a new `pending` row; the client
  generates the new keypair itself and no key material ever travels. The old public key keeps
  verifying through the grace window, both rows listed side by side. The enrollment-completing
  exchange ships with the Phase-2 reel rebuild.
- **hmac** — an **explicit not-implemented refusal** naming the pending→active cutover that
  ships with the kind (D9). Nothing falls through to bearer semantics.

## The failure-path contract

- **Follow-up write fails after the mint** (stamp, lineage, audit): one transaction — all of it
  rolls back, no orphan credential, retry works.
- **Old-row retirement fails at cutover**: the committed replacement stands; the old row stays
  visible in the listing with its `rotated_at` stamp and revoke-by-id can always kill it; the
  error names both ids; **no secret was delivered**, so the unused replacement is simply
  revocable. Retry works.
- **Elsewhere-hosted / manual**: the verb mints, reveals once, and holds the grace window while
  a human installs the secret; the listing shows old-in-grace beside new-active with lineage in
  the audit stream — nothing is ever live and untracked.

## Additive surface changes

- Unified-store summary rows (CLI `--json` and HTTP alike) gained the nullable `rotated_at`
  field: rotation provenance, non-null on a row living out its grace window.
- `credentials` table gained a `rotated_at` column; the audit vocabulary gained the `override`
  reason code.
