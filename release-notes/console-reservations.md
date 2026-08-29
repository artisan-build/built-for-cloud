# Console reservations (documentation only)

Five reservations feed the decided Console fast-follow into the shipped HTTP contract before
Phase 2 consumes it, so the Console can land later without reopening a shipped, decided
artifact. Documentation only — this change implements NO Console behavior: no routes, no
guard code, no migrations, no ability issuance, no key material.

1. **Endpoint classification.** Every endpoint in `docs/http-contract.md` now carries a
   `classification`: `metadata` (bounded scalars/enums only, no free-text strings — safe for
   vendor-side reads) or `content` (application data — never transits the vendor), chosen from
   each endpoint's documented success-path response shape. `GET /bfc/meta` is `content` for now
   — its `product` field is an unbounded config-declared string — until a future behavioral
   revision bounds it so the version-discovery endpoint can honestly become `metadata`.
2. **Reserved Console names.** The `bfc-console` guard name, the `/bfc/console/*` endpoint
   namespace (first known member `/bfc/console/enter`), and the `bfc_delegated_actors` table
   name are documented as RESERVED — explicitly reserved-for-fast-follow, not implemented.
3. **Claim-handshake extensibility.** The contract now states explicitly that the
   claim-surface response envelopes may grow additive fields without an `api_version` bump,
   reserving two named slots: a countersigning-key exchange at claim time, and a re-key verb
   for already-claimed apps. No crypto, no new fields.
4. **Reserved dual-session precedence row.** The session/token precedence matrix (the `bfc`
   guard's docblock, `release-notes/unified-store-guard.md`, and the contract doc's reserved
   section) records the decided rule for the future `bfc-console` delegated-session guard: on
   a request carrying both a local `web` session and a delegated session, the delegated guard
   wins — for the acting principal and for any UI/attribution branching — never a union.
5. **Reserved `metadata:read` ability family** in the ability vocabulary — least-privilege,
   read-audited, for future vendor-side reads of `metadata`-classified endpoints. No issuance,
   no enforcement.

Source: the Ed-approved amendment
`brain/projects/scalpels_app/research/prd-review-console/05-token-train-feed-in.md` (feeding
the Console PRD adversarial review's theme B3 into the unified-token-management train).
Everything else Console-related remains held behind the Console PRD's decision D6.

---

## Disposition as of bfc 0.6.0 — all five are IMPLEMENTED

Recorded here rather than by editing the list above. The list is what was RESERVED; a reservation
that quietly acquires the shape of whatever shipped is a record of nothing, and the two rows where
the two differ are the rows worth reading.

**None of these is a reserved name any more.** Checked against what shipped, one at a time:

1. **Endpoint classification — as reserved.** The column is live and covers every endpoint the
   package mounts, the Console's own included. That sentence is now MECHANICAL rather than
   maintained by hand: `tests/HttpContractDocTest.php` enumerates the document's route headings and
   requires each to carry a classification row, in both directions, driven over a fixture so it is
   proven able to fail. `GET /bfc/meta` is still `content`, for exactly the reason reserved —
   `product` is still an unbounded config-declared string.

2. **Reserved Console names — implemented, and the namespace's first member was NOT the one
   predicted.** The `bfc-console` guard exists and the package registers it itself; the
   `bfc_delegated_actors` table exists. The reservation said the first known member of
   `/bfc/console/*` would be `/bfc/console/enter`. **It was not.** `POST /bfc/console/re-key` landed
   first (Console PRD D12), then `GET /bfc/console/vitals`, and `POST /bfc/console/enter` last. The
   namespace reservation is what mattered and it held; the prediction inside it did not, and nothing
   ever depended on the prediction.

3. **Claim-handshake extensibility — both slots implemented as reserved, plus one field the
   reservation did not name.** The claim-time countersigning-key exchange is the optional
   `console_key` object on `POST /bfc/ownership/claim` and `POST /bfc/onboarding/exchange`; the
   re-key verb is `POST /bfc/console/re-key`. Both additive, `api_version` unmoved, and a request
   carrying no `console_key` gets a response identical to the one it got before — response keys
   included. **Beyond the reservation:** `POST /bfc/onboarding/issue` gained an optional
   `console_key_authority` boolean, because the exchange slot needed an authority to spend and the
   reservation had not said where one would come from.

4. **Dual-session precedence — implemented, and NOT as the additive row the reservation
   described.** The reservation records "a reserved row" in the precedence matrix. What shipped is
   an **AMENDMENT to the v3.1 matrix invariant SEC-V3-10**: that invariant was a token-vs-session
   rule over a single `built-for-cloud.credentials.session_guard` name, and the matrix is now
   session-vs-session with two session guards in it. The decided RULE is unchanged — the delegated
   guard wins for the acting principal and for all UI/attribution branching, never a union — but it
   arrives through the route's own `auth:bfc-console` scoping rather than through anything this
   package repoints, which is not what a reader of the reserved row would have assumed.
   `release-notes/unified-store-guard.md` carries the amendment cell by cell;
   `tests/CredentialPrecedenceTest.php` runs the whole matrix with both session guards configured.

5. **`metadata:read` — implemented, and deliberately not what the reservation implied about
   break-glass.** It is enforced by `GET /bfc/console/vitals`, which requires an operator subject
   and an abilities list EXACTLY equal to `{metadata:read}`. The reservation placed it "in the
   ability vocabulary alongside `admin` and `credential:admin`", which reads as an ordinary member
   of the admin-equivalent family; it is in fact **the one name in the vocabulary `credential:admin`
   cannot reach** (Console PRD D16). The PHP constant changed name in the process —
   `OperatorAbility::RESERVED_METADATA_READ` became the `MetadataRead` case — a source-breaking
   change with no wire effect, documented with its migration in `release-notes/console-vitals.md`.

What is still reserved after this release is named in the contract's own
[Console — what has landed](../docs/http-contract.md#console--what-has-landed-and-what-is-still-reserved)
section, and it is not any of the five above.
