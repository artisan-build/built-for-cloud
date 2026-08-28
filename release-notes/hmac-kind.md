# The `hmac` credential kind (PRD 1.21 / D9, SEC-V3-01/07/08)

Per-subject symmetric signing secrets become a first-class credential kind: minted, delivered,
activated, rotated, revoked, audited and offboarded like everything else in the unified store —
with a key id in every signature header, which is what makes rotation make-before-break. This is
what moves matte's webhook secret and capstan's postmaster signing key out of un-rotatable env
values (their conversions land with the Phase 2 rebuilds that consume this kind).

## The honest at-rest statement (D9.1)

An hmac signing key is stored **encrypted, not hashed** — you cannot sign with a hash; both
sides need the key. Stated plainly: **hmac is the one credential kind whose secret a
database-plus-APP_KEY compromise yields.** That is intrinsic to symmetric signing and
industry-normal for webhook secrets (compare any provider's "signing secret"). If a future case
cannot accept it, the `asymmetric` kind is the upgrade path. The model enforces the shape: no
hashes and no public keys on hmac rows, no ciphertexts on any other kind, and every ciphertext
carries the version of the encryption key that produced it.

## The `pending → active` contract

The store's `pending` status is used in earnest by this kind, because the SENDER decides when a
new hmac key starts signing — signing with a key the receiver has not installed breaks every
message in the gap. The contract:

- **A pending key signs nothing and verifies nothing.** Not a phrase: the signer refuses a
  subject whose only keys are pending (naming why), and the verifier's selection admits
  active-or-in-grace rows only.
- **Activation is its own verb** — `bfc:credential:activate <id> --fingerprint=<fp> --local`
  / `POST /bfc/credentials/{id}/activate` — behind its own matrix verb (`activate`), so a
  declaration can allow rotation while reserving the cutover. It refuses an undelivered key
  (premature activation), a dead key, and a key already active (**duplicate activation is
  deliberately not idempotent** — a second activation means two operators disagree about
  cutover state, and a loud refusal makes the second one look).
- **Activation binds to the confirmed delivery generation.** Every delivery of a signing key
  — the reveal-once mint/rotate response and every claim exchange — carries a
  **delivery fingerprint**: a non-recoverable hash naming that delivery of that key (never
  the key itself; it survives an APP_KEY rewrap). The receiver quotes it back when confirming
  installation out-of-band, and the activation verb **requires it and refuses unless it
  matches the row's current delivery**. This closes the stale-confirmation gap: an
  interceptor who re-claims the link after the receiver confirmed — re-keying the pending row
  under the same key id — changes the fingerprint, so the operator's stale confirmation
  refuses instead of cutting signing over to the attacker's key. On activation success the
  claim code is consumed in the same transaction, so no further redelivery of that code is
  possible.

## Exchange delivers. Exchange NEVER activates (SEC-V3-01)

The standard delivery to an outside counterparty is a claim link (the claim-code primitive);
reveal-once delivery serves counterparties the operator controls (mint or rotate with no
`code_ttl_seconds`). The exchange of an hmac claim code returns the **pending** key material —
`{"signing_key", "key_id", "kind": "hmac", "status": "pending", "delivery_fingerprint"}` —
audits `exchanged` + `delivered` (ids and fingerprints only), and **changes nothing about
signing state**. An inbox interceptor who
redeems the link learns a key that signs nothing and verifies nothing, and cannot cut the
legitimate receiver off — the reversal of the v3 draft where exchange activated.

Burn mode works exactly as on the bearer exchange: under `at_exchange` the legitimate receiver
behind an interceptor gets the loud `code_already_claimed` failure; under `first_use` (the
default) **activation is this kind's first observable use** and consumes the code, and a
re-claim before activation (the dropped-response case) **re-keys the pending row in place** —
fresh key, same `key_id`, a fresh delivery fingerprint, every previously delivered plaintext
dead — so at most one live pending delivery per code ever exists, and only a confirmation of
the CURRENT delivery can activate.

## The rotation dance (D6 point 6)

`bfc:credential:rotate <id>` on an hmac credential mints the replacement **pending** (encrypted,
delivered reveal-once or by claim code) **while the old key keeps signing** — no grace clock
starts at rotate. Deliver, let the receiver install and confirm the delivery fingerprint
out-of-band, then `bfc:credential:activate <new id> --fingerprint=<confirmed fp>`: signing
cuts over, and the old key keeps **verifying**
through a one-hour grace window (the key id in the header says which key checks each message),
then dies by its own expiry. `--emergency` at rotate kills the old key immediately instead —
a compromised key must not keep signing — at the stated price of a signing outage until
activation. Re-rotating the stamped old row while its replacement is still pending refuses and
points at the activate verb; with an active successor, the rotate verb's cutover completion
retires a stamped row whose grace-bounding write was lost, exactly as on every other kind.

## The canonical envelope (SEC-V3-07)

The package ships both halves: an `HmacSigner` service and the `bfc.hmac` verify middleware
(plus the `HmacVerifier` service under it). The signature covers a canonical envelope —
algorithm, key id, event type, timestamp, nonce, audience, and the body's sha256 — in the
`BFC-Signature` header. The verifier:

- selects the key on **(server-derived subject, key id, active-or-in-grace)** — the subject
  comes from the app's declaration (`ResolvesHmacSubjects`), never from the header, so a
  crafted header cannot reach another subject's keys;
- pins `hmac-sha256` — no algorithm negotiation of any kind;
- rejects the wrong audience, timestamps outside ±300 seconds (configurable:
  `built-for-cloud.hmac.timestamp_tolerance_seconds`; the wire form is injective — a
  leading-zero timestamp is malformed), unknown/pending/dead key ids with one indistinct
  answer, and replayed nonces — consumed only after the signature verifies;
- bounds the nonce store on **both axes**: TTL — every entry lives one replay window,
  2×tolerance + 60s of margin, strictly outliving the inclusive acceptance window, so a nonce
  accepted once cannot be accepted again anywhere in its valid window, boundary included —
  and **cardinality** — at most `built-for-cloud.hmac.verification_rate_ceiling` (default
  1000) accepted verifications per key per window, checked after the signature verifies (only
  the key's holder can spend its budget) and before any nonce is stored, so no single
  credential can fill the shared cache. **Replays spend no budget**: a replayed nonce is
  rejected before the counter, so replaying one captured envelope can never rate-limit the
  legitimate holder. The nonce cache is only as fleet-wide as the default
  cache store: instance-local stores (array, file) bound replays per instance;
- answers every middleware failure — key-STATE failures like an unreadable ring key or a
  corrupted ciphertext included — with one uniform 401, never a framework 500: nothing on the
  surface is an oracle, and the ops signal survives as a class-only log line.

## The APP_KEY rewrap runbook (SEC-V3-08)

Encrypted rows must never brick or fossilize under key rotation, so the keyring rides Laravel's
own staged APP_KEY rotation — no new env vars. Rotating the APP_KEY of an app with hmac rows:

1. **Deploy the read-keyring everywhere:** put the current key into `APP_PREVIOUS_KEYS` (comma
   separated, newest first) on every instance. Old ciphertexts stay readable on every app
   version; mixed deploys are tolerated.
2. **Switch the write-primary:** set the new `APP_KEY` — on EVERY instance; do not let a
   mixed-primary fleet linger. From this moment the hmac store is **mid-cutover**: signing,
   verification, first delivery and revocation keep working (the keyring reads every version),
   but **every ciphertext-producing path — hmac minting, rotation, and exchange redelivery —
   refuses with a retry-later error** until the cutover completes. The barrier is
   **check-through-commit**: writers and the rewrap share one lock (`bfc:hmac:rewrap`) — each
   writer holds it across its version check, its write, and its transaction commit, and the
   sweep holds it from its first re-encryption through its final zero-verification — so no
   write can pass the check before the sweep and commit after the verified zero-count. That is
   what makes the completion gate trustworthy.
3. **Run `bfc:hmac:rewrap`** (locked — one run at a time, the lease renewed every batch so a
   long sweep never outlives it, and a run that LOSES the lease aborts immediately rather than
   ever letting two sweeps overlap; restartable — a killed or aborted run resumes by
   re-running). It
   re-encrypts every hmac ciphertext under the new key and **succeeds only when it verifies
   zero old-version rows**. A row whose key-version names no ring key fails the run by id:
   restore that key to `APP_PREVIOUS_KEYS` and re-run — never drop ciphertexts. The lock is
   only as exclusive as the cache store is shared: in a multi-instance deployment the default
   cache must be a shared store (redis, memcached, database) — the command warns loudly when
   it sees an instance-local one (array, file).
4. **Drop the old key** from `APP_PREVIOUS_KEYS` once the rewrap has verified zero old rows.

Delivery fingerprints survive the rewrap: they name the delivered key, not its ciphertext, so
a confirmation made before the rotation still activates after it.

Ciphertext key-versions are content-addressed fingerprints (first 16 hex of the key's sha256),
so reordering `APP_PREVIOUS_KEYS` can never silently re-address a row.

## The event stream

The lifecycle stream gains `activated` — activation is neither an exchange nor a first use, so
it gets its own honest name — and the hmac surfaces emit `delivered` (reveal-once mint and
rotate, and each claim exchange; a re-keying redelivery is noted as such). Everything rides the
transactional audit + outbox stream, ids only, never values.
