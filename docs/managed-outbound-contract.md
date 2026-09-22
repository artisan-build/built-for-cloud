# The Built for Cloud managed outbound contract

This document specifies the HTTPS requests a managed Built for Cloud installation sends to its
authority. It complements [`http-contract.md`](http-contract.md), which specifies the HTTP surface
the package serves. The authority implements the endpoints below; the package is the client.

There are two frozen contract identifiers:

- `managed-auth-v1` covers browser handoff creation, code exchange, and membership confirmation.
- `managed-transition-v1` covers ownership reconciliation and authority-mode transitions.

Unknown response fields are ignored. Fields listed as required below must be present with the stated
type. Timestamps are RFC 3339 strings with an explicit `Z` or numeric offset. Counters are unsigned
integers; transition counters must also be JavaScript-safe integers (at most
`9007199254740991`).

## Trust and transport

Every request is `POST` over the connection's enrolled HTTPS authority origin, accepts JSON, carries
JSON, and sends both of these headers:

```http
Authorization: Bearer <current managed client secret>
Bfc-Contract-Version: <managed-auth-v1 or managed-transition-v1>
```

The secret and authority origin come from the persisted connection established by managed
enrolment. Browser request data cannot replace them. A configured CA bundle is used when present.
The client requires a JSON response carrying the same `contract_version` as the request and accepts
only HTTP `200` as success. A missing, malformed, wrongly versioned, or non-`200` response is a
refusal.

The threat boundary is an attacker who does not hold the current owner token but may replay or forge
enrolment input. Deliberately hostile host configuration is outside the boundary.

## Response binding

Except for handoff creation, every successful response carries a binding block. The client compares
the five connection fields exactly with enrolled state before applying the response:

| Field | Requirement |
| --- | --- |
| `contract_version` | Contract identifier selected by the request |
| `issuer` | Exact enrolled issuer |
| `connection_id` | Exact enrolled connection id |
| `organization_id` | Exact enrolled organization id |
| `installation_id` | Exact enrolled installation id |
| `authority_generation` | Enrolled generation required for this leg |
| `roster_version` | Unsigned authority roster counter |
| `response_sequence` | Unsigned response counter |
| `responded_at` | RFC 3339 authority timestamp |

Membership and connection high-water marks are independent. At the same generation a response is
new only when its `roster_version` is not lower and its `response_sequence` is higher. A higher
generation is new; a lower generation is stale. Stale dimensions do not overwrite newer stored
facts.

## managed-auth-v1

### POST /managed-auth/v1/handoffs

Creates a one-time browser authorization handoff. The package creates an opaque 43-character
`request_id`; the same value becomes browser `state`, while only hashes of it and the browser nonce
are stored locally.

#### Request fields

| Field | Requirement |
| --- | --- |
| `connection_id` | Exact enrolled connection id |
| `installation_id` | Exact enrolled installation id |
| `request_id` | Package-created opaque request id |

#### Response fields

| Field | Requirement |
| --- | --- |
| `contract_version` | `managed-auth-v1` |
| `request_id` | Exact request id from the request |
| `authorization_url` | Enrolled authority origin plus `/managed-auth/v1/authorize`, with no query, fragment, or userinfo |
| `expires_at` | RFC 3339 expiry |

The local correlation expires at the earlier of `expires_at` and 300 seconds after creation. The
browser redirect adds exactly one query field, `state=<request_id>`.

### POST /managed-auth/v1/handoffs/{request_id}/exchange

Exchanges the callback code after the initiating browser has claimed the local correlation once.
`request_id` is URL-encoded as one path segment.

#### Request fields

| Field | Requirement |
| --- | --- |
| `connection_id` | Exact enrolled connection id |
| `installation_id` | Exact enrolled installation id |
| `code` | Non-empty authority-issued callback code |

#### Response fields

| Field | Requirement |
| --- | --- |
| `contract_version` | `managed-auth-v1` |
| `issuer` | Exact enrolled issuer |
| `connection_id` | Exact enrolled connection id |
| `organization_id` | Exact enrolled organization id |
| `installation_id` | Exact enrolled installation id |
| `authority_generation` | Exact enrolled generation |
| `roster_version` | Unsigned membership/connection high-water mark |
| `response_sequence` | Unsigned membership/connection high-water mark |
| `responded_at` | RFC 3339 authority timestamp |
| `scalpels_id` | Non-empty authority subject id |
| `membership_id` | Non-empty membership id |
| `membership_status` | `active`, `removed`, or `disabled` |
| `connection_status` | `active` or `inactive` |
| `role` | `owner`, `admin`, or `member` |
| `display_name` | String |
| `contact_email` | Non-empty string |
| `contact_email_verified` | Boolean |

Only an `active` membership on an `active` connection can establish a session. An unverified
contact email is refused before identity creation. A new identity is keyed by issuer, connection,
and subject; email is not an identity key.

### POST /managed-auth/v1/memberships/confirm

Refreshes one already-bound local subject. The request sends the last accepted membership marks, or
zero counters and the Unix epoch before any authority response has been accepted.

#### Request fields

| Field | Requirement |
| --- | --- |
| `contract_version` | `managed-auth-v1` |
| `issuer` | Exact enrolled issuer |
| `connection_id` | Exact enrolled connection id |
| `organization_id` | Exact enrolled organization id |
| `installation_id` | Exact enrolled installation id |
| `authority_generation` | Exact enrolled generation |
| `roster_version` | Last accepted membership roster version, or `0` |
| `response_sequence` | Last accepted membership response sequence, or `0` |
| `responded_at` | Last accepted authority timestamp, or `1970-01-01T00:00:00+00:00` |
| `scalpels_id` | Exact bound authority subject id |

#### Response fields

| Field | Requirement |
| --- | --- |
| `contract_version` | `managed-auth-v1` |
| `issuer` | Exact enrolled issuer |
| `connection_id` | Exact enrolled connection id |
| `organization_id` | Exact enrolled organization id |
| `installation_id` | Exact enrolled installation id |
| `authority_generation` | Exact enrolled generation |
| `roster_version` | Unsigned membership/connection high-water mark |
| `response_sequence` | Unsigned membership/connection high-water mark |
| `responded_at` | RFC 3339 authority timestamp |
| `scalpels_id` | Exact requested subject id |
| `membership_status` | `active`, `removed`, or `disabled` |
| `connection_status` | `active` or `inactive` |
| `role` | `owner`, `admin`, or `member` |

### Freshness and denial clocks

An accepted active membership on an active connection is fresh for 300 seconds. During that window
the package authorizes from stored state without an authority call. At 300 seconds it attempts
membership confirmation under a per-subject lock.

If confirmation is unavailable or refused, the last accepted active state is a bounded grace only:
it remains usable until its confirmation age reaches 1,800 seconds. At 1,800 seconds it fails
closed. `removed` and `disabled` deny that subject immediately; `inactive` denies the whole
connection immediately. A newly accepted subject denial invalidates that subject's sessions and
user-bound credentials. A newly accepted connection denial invalidates account-bound state for all
subjects on the connection and contains connection-authorized credentials.

A numeric `Retry-After` on a refusal suppresses another confirmation attempt for at least 30 and at
most 300 seconds. Missing, malformed, or shorter values use 30 seconds; longer values are capped at
300. Retry suppression never extends the 1,800-second authorization grace.

### managed-auth-v1 refusals

The client refuses every non-`200` response. The authority's closed refusal vocabulary is:

| Status | `error` |
| ---: | --- |
| 400 | `invalid_grant`, `unsupported_contract_version` |
| 401 | `invalid_client` |
| 429 | `rate_limited` |
| 500 | `server_error` |
| 503 | `server_error` |

The client also refuses transport failure; malformed JSON; an absent or wrong contract version;
missing, null, mistyped, empty, out-of-range, or invalid-enum required fields; invalid timestamps;
binding mismatches; a mismatched handoff request id; and an authorization URL outside the exact
enrolled origin and frozen path. Unknown status/error pairs are refused rather than interpreted as
success.

## managed-transition-v1

Ownership reconciliation and all seven transition legs use `Bfc-Contract-Version:
managed-transition-v1`. Ownership uses ordinary JSON. Prepare, stage, acknowledgement, and abandon
also send:

```http
Bfc-Body-Digest: <lowercase SHA-256 of the exact JSON request bytes>
```

Those four keyed legs persist the exact body and digest before transmission. Repeating a key with
the same bytes returns the recorded outcome and must not execute twice; repeating it with different
bytes is `409 idempotency_conflict`. Roster, state, and request recovery are reads and carry no body
digest.

### POST /managed-transition/v1/ownership

Reconciles the authority's Owner when a managed-auth response would acquire, transfer, or vacate the
single local Owner slot.

#### Request fields

| Field | Requirement |
| --- | --- |
| `connection_id` | Exact enrolled connection id |
| `installation_id` | Exact enrolled installation id |
| `seated_owner_scalpels_id` | Current local Owner's authority subject id, or `null` |

#### Response fields

| Field | Requirement |
| --- | --- |
| `contract_version` | `managed-transition-v1` |
| `issuer` | Exact enrolled issuer |
| `connection_id` | Exact enrolled connection id |
| `organization_id` | Exact enrolled organization id |
| `installation_id` | Exact enrolled installation id |
| `authority_generation` | Exact enrolled generation |
| `roster_version` | Unsigned ownership high-water mark |
| `response_sequence` | Unsigned ownership high-water mark |
| `responded_at` | RFC 3339 authority timestamp |
| `owner` | Required Owner subject object |
| `seated_owner` | Subject object matching the requested incumbent, or `null` |

#### Owner subject fields

| Field | Requirement |
| --- | --- |
| `scalpels_id` | Non-empty authority subject id, at most 255 bytes |
| `membership_status` | `active`, `removed`, or `disabled` |
| `role` | `owner`, `admin`, or `member` |

`owner` must be active with role `owner`. A null requested incumbent requires a null
`seated_owner`. A named incumbent requires the same subject in `seated_owner`; reaffirmation requires
both subject objects to be identical, while transfer requires the incumbent's new role not to be
`owner`.

### POST /managed-transition/v1/transitions

T1 prepares an `adopt` or `exit` transition and freezes its authority roster snapshot.

#### Request fields

| Field | Requirement |
| --- | --- |
| `connection_id` | Exact enrolled connection id |
| `installation_id` | Exact enrolled installation id |
| `direction` | `adopt` or `exit` |
| `transition_request_id` | Package-created 43-character idempotency key |

#### Response fields

| Field | Requirement |
| --- | --- |
| `contract_version` | `managed-transition-v1` |
| `issuer` | Exact enrolled issuer |
| `connection_id` | Exact enrolled connection id |
| `organization_id` | Exact enrolled organization id |
| `installation_id` | Exact enrolled installation id |
| `authority_generation` | `generation_before` |
| `roster_version` | Frozen roster version |
| `response_sequence` | Unsigned response counter |
| `responded_at` | RFC 3339 authority timestamp |
| `transition_request_id` | Exact request id |
| `transition_id` | Non-empty authority transition id |
| `direction` | Exact requested direction |
| `status` | `prepared` |
| `roster_cutoff_at` | Frozen RFC 3339 roster cutoff |
| `roster_total` | Unsigned total, at most 50,000 |

### POST /managed-transition/v1/transitions/{transition_id}/roster

T2 pages the roster frozen by T1. `transition_id` is URL-encoded as one path segment.

#### Request fields

| Field | Requirement |
| --- | --- |
| `connection_id` | Exact enrolled connection id |
| `installation_id` | Exact enrolled installation id |
| `roster_version` | Exact T1 roster version |
| `roster_cutoff_at` | Exact T1 cutoff |
| `cursor` | Authority cursor from the previous page, or `null` |

#### Response fields

| Field | Requirement |
| --- | --- |
| `contract_version` | `managed-transition-v1` |
| `issuer` | Exact enrolled issuer |
| `connection_id` | Exact enrolled connection id |
| `organization_id` | Exact enrolled organization id |
| `installation_id` | Exact enrolled installation id |
| `authority_generation` | `generation_before` |
| `roster_version` | Exact T1 roster version |
| `response_sequence` | Unsigned response counter |
| `responded_at` | RFC 3339 authority timestamp |
| `transition_id` | Exact transition id |
| `roster_cutoff_at` | Exact T1 cutoff |
| `members` | List of roster member objects, at most 500 |
| `next_cursor` | Next cursor string (empty is allowed), or `null` |
| `page_total` | Exact member count for this page, at most 500 |

#### Roster member fields

| Field | Requirement |
| --- | --- |
| `scalpels_id` | Non-empty authority subject id, at most 255 bytes |
| `membership_status` | `active`, `removed`, or `disabled` |
| `role` | `owner`, `admin`, or `member` |
| `display_name` | String, at most 255 bytes |
| `contact_email` | Valid email, at most 255 bytes |
| `contact_email_verified` | Boolean |

Roster responses must be identity encoded and at most 1 MiB. The client accepts at most 200 pages,
refuses repeated cursors or subjects, and requires the accumulated member count to equal T1's
`roster_total`.

### POST /managed-transition/v1/transitions/{transition_id}/stage

T3 submits the complete local mapping against the exact frozen roster. The authority must not stage
against a different roster version or cutoff.

#### Request fields

| Field | Requirement |
| --- | --- |
| `connection_id` | Exact enrolled connection id |
| `installation_id` | Exact enrolled installation id |
| `idempotency_key` | Package-created 43-character key |
| `roster_version` | Exact T1 roster version |
| `roster_cutoff_at` | Exact T1 cutoff |
| `mapping` | Complete ordered mapping list |

#### Mapping fields

| Field | Requirement |
| --- | --- |
| `scalpels_id` | Authority subject id or `null` |
| `local_kind` | `user`, `invitation`, or `null` |
| `local_id` | Local id or `null` |
| `role` | `owner`, `admin`, `member`, or `null` |
| `disposition` | Direction-appropriate mapping disposition |
| `final_email` | Final email or `null` |

#### Response fields

| Field | Requirement |
| --- | --- |
| `contract_version` | `managed-transition-v1` |
| `issuer` | Exact enrolled issuer |
| `connection_id` | Exact enrolled connection id |
| `organization_id` | Exact enrolled organization id |
| `installation_id` | Exact enrolled installation id |
| `authority_generation` | `generation_before` |
| `roster_version` | Exact T1 roster version |
| `response_sequence` | Unsigned response counter |
| `responded_at` | RFC 3339 authority timestamp |
| `transition_id` | Exact transition id |
| `status` | `staged` |
| `roster_cutoff_at` | Exact T1 cutoff |

`409 roster_changed` means the frozen snapshot no longer applies. The client refuses the stage; it
does not silently fetch a new roster into the existing proposal.

### POST /managed-transition/v1/transitions/{transition_id}

T5 reads the authority's durable transition state for recovery and before abandonment.

#### Request fields

| Field | Requirement |
| --- | --- |
| `connection_id` | Exact enrolled connection id |
| `installation_id` | Exact enrolled installation id |

#### Response fields

| Field | Requirement |
| --- | --- |
| `contract_version` | `managed-transition-v1` |
| `issuer` | Exact enrolled issuer |
| `connection_id` | Exact enrolled connection id |
| `organization_id` | Exact enrolled organization id |
| `installation_id` | Exact enrolled installation id |
| `authority_generation` | `generation_before`, or `generation_after` when acknowledged |
| `roster_version` | Exact T1 roster version |
| `response_sequence` | Unsigned response counter |
| `responded_at` | RFC 3339 authority timestamp |
| `transition_id` | Exact transition id |
| `direction` | Exact transition direction |
| `status` | `prepared`, `staged`, `acknowledged`, or `abandoned` |
| `roster_cutoff_at` | Exact T1 cutoff |
| `local_commit_receipt` | Exact receipt when acknowledged, otherwise `null` |
| `acknowledged_at` | RFC 3339 timestamp when acknowledged, otherwise `null` |

### POST /managed-transition/v1/transition-requests/{transition_request_id}

T6 recovers a T1 whose outcome is unknown. `transition_request_id` is URL-encoded as one path
segment. If the request exists as `prepared`, the package replays the exact recorded T1 bytes and
requires both answers to identify the same transition.

#### Request fields

| Field | Requirement |
| --- | --- |
| `connection_id` | Exact enrolled connection id |
| `installation_id` | Exact enrolled installation id |

#### Response fields

| Field | Requirement |
| --- | --- |
| `contract_version` | `managed-transition-v1` |
| `issuer` | Exact enrolled issuer |
| `connection_id` | Exact enrolled connection id |
| `organization_id` | Exact enrolled organization id |
| `installation_id` | Exact enrolled installation id |
| `authority_generation` | `generation_before`, or `generation_after` when acknowledged |
| `roster_version` | Unsigned roster version |
| `response_sequence` | Unsigned response counter |
| `responded_at` | RFC 3339 authority timestamp |
| `transition_request_id` | Exact request id from the path |
| `transition_id` | Authority transition id, or `null` |
| `status` | `prepared`, `staged`, `acknowledged`, `abandoned`, or `null` |

`status` and `transition_id` are either both null or both non-null.

### POST /managed-transition/v1/transitions/{transition_id}/abandon

T7 abandons a pre-commit transition. The package first reads T5 and only abandons an authority state
compatible with its local pre-commit state.

#### Request fields

| Field | Requirement |
| --- | --- |
| `connection_id` | Exact enrolled connection id |
| `installation_id` | Exact enrolled installation id |
| `idempotency_key` | Package-created 43-character key |

#### Response fields

| Field | Requirement |
| --- | --- |
| `contract_version` | `managed-transition-v1` |
| `issuer` | Exact enrolled issuer |
| `connection_id` | Exact enrolled connection id |
| `organization_id` | Exact enrolled organization id |
| `installation_id` | Exact enrolled installation id |
| `authority_generation` | `generation_before` |
| `roster_version` | Exact T1 roster version |
| `response_sequence` | Unsigned response counter |
| `responded_at` | RFC 3339 authority timestamp |
| `transition_id` | Exact transition id |
| `status` | `abandoned` |

### POST /managed-transition/v1/transitions/{transition_id}/ack

T4 acknowledges that the local mode change committed. Local commit happens first and creates the
receipt; an unknown acknowledgement outcome is recovered through T5 and retried with the exact
recorded T4 bytes.

#### Request fields

| Field | Requirement |
| --- | --- |
| `connection_id` | Exact enrolled connection id |
| `installation_id` | Exact enrolled installation id |
| `idempotency_key` | Package-created 43-character key |
| `local_commit_receipt` | Package-created receipt from local commit |
| `mode_after` | `managed` for adopt, `standalone` for exit |
| `generation_after` | Exact `generation_before + 1` |

#### Response fields

| Field | Requirement |
| --- | --- |
| `contract_version` | `managed-transition-v1` |
| `issuer` | Exact enrolled issuer |
| `connection_id` | Exact enrolled connection id |
| `organization_id` | Exact enrolled organization id |
| `installation_id` | Exact enrolled installation id |
| `authority_generation` | Exact `generation_after` |
| `roster_version` | Exact T1 roster version |
| `response_sequence` | Unsigned response counter |
| `responded_at` | RFC 3339 authority timestamp |
| `transition_id` | Exact transition id |
| `status` | `acknowledged` |
| `generation_after` | Exact requested generation |
| `local_commit_receipt` | Exact requested receipt |
| `acknowledged_at` | RFC 3339 authority timestamp |

### Frozen roster and generation rules

T1 freezes one tuple: `transition_id`, `roster_version`, `roster_cutoff_at`, and `roster_total`. Every
T2 page and T3 request is bound to that tuple. The package refuses changed versions, cutoffs,
transition ids, duplicate subjects/cursors, page totals that disagree with the member list, or a
final count that disagrees with `roster_total`. There is no in-place refresh of a proposal onto a
different roster.

For either direction, `generation_after` is exactly `generation_before + 1`. Every response before
local commit and every abandoned response is bound to `generation_before`. T4 and an acknowledged
T5/T6 response are bound to `generation_after`. Adopt changes `standalone/N` to `managed/N+1`; exit
changes `managed/N` to `standalone/N+1`. Acknowledgement cannot invent a generation or receipt: both
must equal the locally committed values.

### managed-transition-v1 refusals

The transition client recognizes these status/error pairs; all are refusals:

| Status | `error` |
| ---: | --- |
| 400 | `invalid_grant`, `unsupported_contract_version`, `invalid_transition` |
| 401 | `invalid_client` |
| 409 | `idempotency_conflict`, `roster_changed`, `transition_state_conflict`, `transition_in_progress` |
| 429 | `rate_limited` |
| 500 | `server_error` |
| 503 | `server_error` |

A decimal `Retry-After` is retained but capped at 300 seconds. Unknown status/error pairs, transport
failure, malformed JSON, wrong contract versions, invalid field shapes, binding mismatches, wrong
state transitions, digest mismatches, and snapshot or generation mismatches are also refusals.

## End-to-end lifecycle

1. **Provisioned:** the pristine app is standalone and claimed. The authority holds the current
   owner credential; an attacker without that credential cannot invoke the inbound enrolment routes.
2. **Enrolled:** the authority calls `POST /bfc/managed/enrolment` from
   [`http-contract.md`](http-contract.md#post-bfcmanagedenrolment), supplying the immutable binding and
   first managed client secret. The package locks and validates pristine state, encrypts the secret,
   and changes `standalone/N` to `managed/N+1`.
3. **Signed in:** `GET /bfc/managed/login` makes the outbound handoff request. The browser authorizes
   at the authority and returns once; the package exchanges the code server-to-server, validates the
   binding and active statuses, and creates the local session. Membership confirmation then applies
   the 300-second fresh and 1,800-second grace clocks.
4. **Exited:** the authority calls `POST /bfc/managed/enrolment/disconnect`. The package drives the
   outbound exit sequence prepare, frozen roster, stage, local commit, and acknowledgement. Only
   after acknowledgement does it clear the persisted connection and secret, ending at
   `standalone/N+1` relative to the managed generation at exit start.

Client-secret rotation between enrolment and exit uses
`POST /bfc/managed/enrolment/client-secret`: the authority keeps the old bearer valid until the app
commits the replacement, then activates the new one. Rotation does not change authority generation.
