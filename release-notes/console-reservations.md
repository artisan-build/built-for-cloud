# Console reservations (documentation only)

Five reservations feed the decided Console fast-follow into the shipped HTTP contract before
Phase 2 consumes it, so the Console can land later without reopening a shipped, decided
artifact. Documentation only — this change implements NO Console behavior: no routes, no
guard code, no migrations, no ability issuance, no key material.

1. **Endpoint classification.** Every endpoint in `docs/http-contract.md` now carries a
   `classification`: `metadata` (bounded scalars/enums only, no free-text strings — safe for
   vendor-side reads) or `content` (application data — never transits the vendor), chosen from
   each endpoint's documented success-path response shape.
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
