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

### Executable transport profiles

These structured tables are the normative representation consumed by
`ManagedOutboundContractDocTest`. Endpoint field tables define required keys. The field rules below
define their types and common value constraints; contextual rules narrow them where production does.

| Protocol | Method | Path | Accept | Content-Type | Authorization | Version header | Success status |
| --- | --- | --- | --- | --- | --- | --- | ---: |
| `managed-auth-v1` | `POST` | `/managed-auth/v1/handoffs` | `application/json` | `application/json` | `Bearer enrolled-secret` | `Bfc-Contract-Version: managed-auth-v1` | 200 |
| `managed-auth-v1` | `POST` | `/managed-auth/v1/handoffs/{request_id}/exchange` | `application/json` | `application/json` | `Bearer enrolled-secret` | `Bfc-Contract-Version: managed-auth-v1` | 200 |
| `managed-auth-v1` | `POST` | `/managed-auth/v1/memberships/confirm` | `application/json` | `application/json` | `Bearer enrolled-secret` | `Bfc-Contract-Version: managed-auth-v1` | 200 |
| `managed-transition-v1` | `POST` | `/managed-transition/v1/ownership` | `application/json` | `application/json` | `Bearer enrolled-secret` | `Bfc-Contract-Version: managed-transition-v1` | 200 |
| `managed-transition-v1` | `POST` | `/managed-transition/v1/transitions` | `application/json` | `application/json` | `Bearer enrolled-secret` | `Bfc-Contract-Version: managed-transition-v1` | 200 |
| `managed-transition-v1` | `POST` | `/managed-transition/v1/transitions/{transition_id}/roster` | `application/json` | `application/json` | `Bearer enrolled-secret` | `Bfc-Contract-Version: managed-transition-v1` | 200 |
| `managed-transition-v1` | `POST` | `/managed-transition/v1/transitions/{transition_id}/stage` | `application/json` | `application/json` | `Bearer enrolled-secret` | `Bfc-Contract-Version: managed-transition-v1` | 200 |
| `managed-transition-v1` | `POST` | `/managed-transition/v1/transitions/{transition_id}` | `application/json` | `application/json` | `Bearer enrolled-secret` | `Bfc-Contract-Version: managed-transition-v1` | 200 |
| `managed-transition-v1` | `POST` | `/managed-transition/v1/transition-requests/{transition_request_id}` | `application/json` | `application/json` | `Bearer enrolled-secret` | `Bfc-Contract-Version: managed-transition-v1` | 200 |
| `managed-transition-v1` | `POST` | `/managed-transition/v1/transitions/{transition_id}/abandon` | `application/json` | `application/json` | `Bearer enrolled-secret` | `Bfc-Contract-Version: managed-transition-v1` | 200 |
| `managed-transition-v1` | `POST` | `/managed-transition/v1/transitions/{transition_id}/ack` | `application/json` | `application/json` | `Bearer enrolled-secret` | `Bfc-Contract-Version: managed-transition-v1` | 200 |

### Executable field rules

Every field is a required key wherever an endpoint or nested-object table lists it. Rules are
semicolon-delimited. `uint` means a non-negative integer and `rfc3339` means the strict timestamp
form stated above.

#### Common rules

| Field | Type | Rules |
| --- | --- | --- |
| `contract_version` | `string` | `enum=managed-auth-v1,managed-transition-v1` |
| `issuer` | `string` | `non-empty` |
| `connection_id` | `string` | `non-empty` |
| `organization_id` | `string` | `non-empty` |
| `installation_id` | `string` | `non-empty` |
| `authority_generation` | `integer` | `uint` |
| `roster_version` | `integer` | `uint` |
| `response_sequence` | `integer` | `uint` |
| `responded_at` | `string` | `non-empty;rfc3339` |
| `request_id` | `string` | `non-empty` |
| `authorization_url` | `string` | `non-empty;https-url` |
| `expires_at` | `string` | `non-empty;rfc3339` |
| `code` | `string` | `non-empty` |
| `scalpels_id` | `string` | `non-empty` |
| `membership_id` | `string` | `non-empty` |
| `membership_status` | `string` | `enum=active,removed,disabled` |
| `connection_status` | `string` | `enum=active,inactive` |
| `role` | `string` | `enum=owner,admin,member` |
| `display_name` | `string` | `string` |
| `contact_email` | `string` | `non-empty` |
| `contact_email_verified` | `boolean` | `boolean` |
| `seated_owner_scalpels_id` | `string` | `non-empty` |
| `owner` | `object` | `object` |
| `seated_owner` | `object` | `object` |
| `direction` | `string` | `enum=adopt,exit` |
| `transition_request_id` | `string` | `non-empty;max-bytes=255` |
| `transition_id` | `string` | `non-empty;max-bytes=255` |
| `status` | `string` | `non-empty` |
| `roster_cutoff_at` | `string` | `non-empty;max-bytes=64;rfc3339` |
| `roster_total` | `integer` | `uint;max=50000` |
| `cursor` | `string` | `max-bytes=4096` |
| `members` | `list` | `max-count=500` |
| `next_cursor` | `string` | `max-bytes=4096` |
| `page_total` | `integer` | `uint;max=500` |
| `mapping` | `list` | `list` |
| `idempotency_key` | `string` | `non-empty;bytes=43` |
| `local_commit_receipt` | `string` | `non-empty;max-bytes=255` |
| `mode_after` | `string` | `enum=managed,standalone` |
| `generation_after` | `integer` | `uint;max=9007199254740991` |
| `acknowledged_at` | `string` | `non-empty;max-bytes=64;rfc3339` |

#### Contextual rules

The following contextual rules are additional to the common field rules:

| Context | Field | Rules |
| --- | --- | --- |
| `managed-transition-v1 binding` | `authority_generation` | `max=9007199254740991` |
| `managed-transition-v1 binding` | `roster_version` | `max=9007199254740991` |
| `managed-transition-v1 binding` | `response_sequence` | `max=9007199254740991` |
| `handoff request` | `request_id` | `bytes=43` |
| `T1 request` | `transition_request_id` | `bytes=43` |
| `owner subject` | `scalpels_id` | `max-bytes=255` |
| `roster member` | `scalpels_id` | `max-bytes=255` |
| `roster member` | `display_name` | `max-bytes=255` |
| `roster member` | `contact_email` | `max-bytes=255;valid-email` |

#### Nullable locations

These are the only endpoint-table locations whose values may be null. A listed field remains a
required key.

| Method and path | Table | Field |
| --- | --- | --- |
| `POST /managed-transition/v1/ownership` | `Request fields` | `seated_owner_scalpels_id` |
| `POST /managed-transition/v1/ownership` | `Response fields` | `seated_owner` |
| `POST /managed-transition/v1/transitions/{transition_id}/roster` | `Request fields` | `cursor` |
| `POST /managed-transition/v1/transitions/{transition_id}/roster` | `Response fields` | `next_cursor` |
| `POST /managed-transition/v1/transitions/{transition_id}` | `Response fields` | `local_commit_receipt` |
| `POST /managed-transition/v1/transitions/{transition_id}` | `Response fields` | `acknowledged_at` |
| `POST /managed-transition/v1/transition-requests/{transition_request_id}` | `Response fields` | `transition_id` |
| `POST /managed-transition/v1/transition-requests/{transition_request_id}` | `Response fields` | `status` |

#### Response enums

Endpoint-specific response enums narrow the field rules:

| Method and path | Field | Values |
| --- | --- | --- |
| `POST /managed-transition/v1/transitions` | `status` | `prepared` |
| `POST /managed-transition/v1/transitions/{transition_id}/stage` | `status` | `staged` |
| `POST /managed-transition/v1/transitions/{transition_id}` | `status` | `prepared,staged,acknowledged,abandoned` |
| `POST /managed-transition/v1/transition-requests/{transition_request_id}` | `status` | `prepared,staged,acknowledged,abandoned` |
| `POST /managed-transition/v1/transitions/{transition_id}/abandon` | `status` | `abandoned` |
| `POST /managed-transition/v1/transitions/{transition_id}/ack` | `status` | `acknowledged` |

### Executable refusal response shape

Every HTTP refusal body requires these fields. Unknown response fields are ignored as stated above;
`Retry-After`, when present, is a response header rather than a body field.

| Field | Type | Required | Rules |
| --- | --- | --- | --- |
| `contract_version` | `string` | `yes` | `request protocol` |
| `error` | `string` | `yes` | `status-paired vocabulary below` |

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

| Status | `error` | Classification | `Retry-After` |
| ---: | --- | --- | --- |
| 400 | `invalid_grant` | `refusal` | `optional-decimal;cap=300` |
| 400 | `unsupported_contract_version` | `refusal` | `optional-decimal;cap=300` |
| 401 | `invalid_client` | `refusal` | `optional-decimal;cap=300` |
| 429 | `rate_limited` | `retryable-refusal` | `optional-decimal;cap=300` |
| 500 | `server_error` | `retryable-refusal` | `optional-decimal;cap=300` |
| 503 | `server_error` | `retryable-refusal` | `optional-decimal;cap=300` |

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

Every element has exactly these six required keys:

| Field | Type | Nullability | Rules |
| --- | --- | --- | --- |
| `scalpels_id` | `string` | `nullable` | `non-empty;max-bytes=255` |
| `local_kind` | `string` | `nullable` | `enum=user,invitation` |
| `local_id` | `string` | `nullable` | `non-empty;max-bytes=64` |
| `role` | `string` | `nullable` | `enum=owner,admin,member` |
| `disposition` | `string` | `required` | `enum=link,create,retain_local,retain_deactivated,exclude,defer_to_managed_jit` |
| `final_email` | `string` | `nullable` | `non-empty;max-bytes=255;valid-email` |

`required` means a non-empty string and `null` means JSON null. These rows are the complete shape
matrix, not examples:

##### Shape matrix

| Shape | Disposition | `local_kind` | `scalpels_id` | `local_id` | `role` | `final_email` | Adopt | Exit |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `link-user` | `link` | `user` | `required` | `required` | `required` | `required` | `allowed` | `allowed` |
| `link-invitation` | `link` | `invitation` | `required` | `required` | `required` | `required` | `allowed` | `allowed` |
| `create` | `create` | `null` | `required` | `null` | `required` | `required` | `allowed` | `forbidden` |
| `retain-user` | `retain_local` | `user` | `null` | `required` | `required` | `required` | `forbidden` | `allowed` |
| `retain-deactivated-user` | `retain_deactivated` | `user` | `null` | `required` | `null` | `null` | `forbidden` | `allowed` |
| `retain-invitation` | `retain_local` | `invitation` | `null` | `required` | `null` | `null` | `forbidden` | `allowed` |
| `exclude-user` | `exclude` | `user` | `null` | `required` | `null` | `null` | `allowed` | `allowed` |
| `exclude-invitation` | `exclude` | `invitation` | `null` | `required` | `null` | `null` | `allowed` | `allowed` |
| `defer-to-managed-jit` | `defer_to_managed_jit` | `null` | `required` | `null` | `null` | `null` | `allowed` | `forbidden` |

##### Complete-list constraints

The complete-list constraints are also normative:

| Constraint | Rule |
| --- | --- |
| `known-subject` | Every non-null `scalpels_id` exists in the frozen roster. |
| `unique-subject` | A non-null `scalpels_id` appears at most once. |
| `known-local` | Every non-null (`local_kind`, `local_id`) identifies a current local user or pending invitation. |
| `managed-user-binding` | An existing managed local user's issuer and connection equal this transition's issuer and connection; when `scalpels_id` is non-null, it also equals the user's existing subject. |
| `retain-deactivated-eligibility` | `retain_deactivated` requires an exit user with no roster subject whose freshness state is exactly `managed_membership_status=removed`, `status=inactive`, non-null `deactivated_at`, and null password. |
| `unique-local` | A (`local_kind`, `local_id`) pair appears at most once. |
| `all-locals` | Every current local user and pending invitation appears exactly once. |
| `all-adopt-subjects` | In adopt, every frozen-roster subject appears exactly once. |
| `adopt-role-match` | In adopt, every `link` and `create` role equals the frozen-roster role. |
| `unique-projected-email` | The case-insensitive collision set is exactly: `final_email` for linked users, linked invitations, retained users, and created subjects; the stored database email for excluded users and retained invitations. Every address in the set is unique. |

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

| Status | `error` | Classification | `Retry-After` |
| ---: | --- | --- | --- |
| 400 | `invalid_grant` | `refusal` | `optional-decimal;cap=300` |
| 400 | `unsupported_contract_version` | `refusal` | `optional-decimal;cap=300` |
| 400 | `invalid_transition` | `refusal` | `optional-decimal;cap=300` |
| 401 | `invalid_client` | `refusal` | `optional-decimal;cap=300` |
| 409 | `idempotency_conflict` | `conflict-refusal` | `optional-decimal;cap=300` |
| 409 | `roster_changed` | `conflict-refusal` | `optional-decimal;cap=300` |
| 409 | `transition_state_conflict` | `conflict-refusal` | `optional-decimal;cap=300` |
| 409 | `transition_in_progress` | `conflict-refusal` | `optional-decimal;cap=300` |
| 429 | `rate_limited` | `retryable-refusal` | `optional-decimal;cap=300` |
| 500 | `server_error` | `retryable-refusal` | `optional-decimal;cap=300` |
| 503 | `server_error` | `retryable-refusal` | `optional-decimal;cap=300` |

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
