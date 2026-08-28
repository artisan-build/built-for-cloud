# Full account containment — the offboard verb (PRD 1.15, SEC-V3-04)

One two-transport verb (`bfc:subject:offboard --local` / `POST /bfc/subjects/offboard`, both
running the same `OffboardSubject` action) deactivates a subject and, in one action:

- revokes **every bound credential in every lifecycle state** — active, rotation-grace, and
  pending (unexchanged enrollments and pending hmac signing keys included), in both the
  unified `credentials` store and subject-stamped `api_tokens` rows, consuming each one's
  linked claim codes;
- consumes the principal's outstanding **claim codes** (revoking their never-used
  make-before-break durables) and cancels the principal's pending **invitations**;
- deletes the principal's **password-reset tokens**;
- invalidates **sessions** — see the compensation below;
- writes the **containment registry** (`offboarded_subjects`): one row for the subject, one
  per bound user it deactivated. The `bfc` guard rejects any credential of an offboarded
  subject — and any credential bound to a deactivated user, whatever subject it belongs to —
  and the auth-foundation middleware (`bfc.auth`) rejects a deactivated user's session and
  invalidates it on its first appearance.

**Session compensation, stated (the PRD requires the statement):** only a database session
store on the default connection can share the credential transaction — those rows delete
atomically with the revocations. A database store on another connection deletes after commit;
every other driver's storage cannot be enumerated per user. In all compensated cases the
registry row commits WITH the revocations, so the containment holds whatever survives in
session storage.

**Idempotent:** a second offboard is a no-op — same response shape, zero counts, no new audit
rows. **One audit shape (D8):** a single `offboarded` lifecycle event carrying the acting
principal and the contained subject (ids only), plus one `revoked` event per credential death
with reason `offboarding`.

**Integration-driven offboards ride PR8's shared version gate:** `event_kind: offboard` in the
same `integration_events` / `integration_entitlements` tables the invite verb uses. One
monotonic entitlement version per (namespace, external subject) orders invites and offboards
together — an offboard event not newer than the latest accepted version is transactionally
acknowledged-and-ignored, a replayed event id answers idempotently, and an applying offboard
also cancels the pending invitations its own namespace+subject history issued. The
acknowledgement is uniform (`202 {"accepted": true}`) whatever the gate decided.

**Authority:** the verb has its own operator ability (`subject:offboard`) and its own
declaration-matrix verb (`offboard`) — the widest verb, deliberately not implied by mint or
revoke authority; `credential:admin` (break-glass) and admin tokens hold it.
