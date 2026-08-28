# The claim-code primitive and the burn

`onboarding_tokens` is now the package's short-lived-claim-code primitive (the table name does not
change): a bounded-lifetime, optionally addressed, single-use code exchanged for a durable
credential, speaking the hitch claim contract's vocabulary and error enum on the onboarding claim
surfaces.

## Breaking changes

- **`ttl_seconds` is required on `POST /bfc/onboarding/issue`**, package-enforced bounds 60–604800
  seconds (60s–7d). The hard-coded 24-hour expiry is gone and there is no default, so the deletion
  cannot leave a no-expiry hole. This is a small break with no known callers. The bound binds the
  **code only** — durable-credential TTL stays caller-chosen and unbounded, with no default, ever.
- **Response key renames** (the `swap_token` collision is retired from both sides):
  - `POST /bfc/onboarding/issue` returns **`claim_code`** (was `swap_token`).
  - `POST /bfc/ownership/release` returns **`ownership_claim_code`** (was `swap_token`). That is
    the whole ownership change — ownership claims share the vocabulary, not the primitive.
- **The claim surfaces speak the claim contract's error enum** — `invalid_code`, `code_not_found`,
  `code_already_claimed`, `code_expired`, `unsupported_version`, `server_error` — as
  `{"version": 1, "error": <enum>, "message": <prose>}`, replacing the bare 401s on
  `/bfc/onboarding/exchange` and `/bfc/onboarding/verify`. Statuses follow the contract's guidance
  (400/404/409/410); clients branch on the enum, never the status. `message` is printed verbatim by
  clients and never carries a code, a token, or any other secret. An absent or non-string `token`
  field is still a Laravel validation error (422); the enum covers presented codes. The shipped
  `ContractAssertions` suite asserts the new shapes, so consuming apps pick the change up with the
  package upgrade.
- **`CredentialDeclaration` gains an opt-in companion**: implement `DeclaresBurnMode` to declare
  when your claim codes burn. Declarations that do not implement it get `first_use` — nothing
  existing breaks.

## Behaviour changes

- **`issue` no longer revokes the live durable credential.** A claim code sitting in an inbox no
  longer breaks a working integration on the day it is sent. **Exchange now performs both
  revocations** — by the code's own durable link and by name+scope — so after exchange at most one
  live durable exists per name+scope, including when the code carried no link.
- **`email` is optional on issue.** A claim code may be addressed to nobody; an unaddressed code's
  durable is named `claim-<code id>`.
- **Make-before-break re-claim:** redemption alone does not burn the code. A re-claim before the
  durable's first use returns a fresh usable token and invalidates the pending one (hashed storage
  cannot return the same token — this is the contract's other conforming behaviour). At most one
  live token per code, ever. After first use, further claims return `code_already_claimed`.

## The burn rule, honestly stated

For `first_use` providers the code's exposure window **closes at the durable's first successful
use, not at exchange**. First-use detection and code consumption are one atomic database
transaction, entered by a conditional update gated on affected rows, and the burn fires for
whatever presents the durable's secret and resolves it — bearer and HTTP Basic alike. Until that
first use (or the code's TTL, whichever comes first) the code remains exchangeable; keep the TTL
short — it is the only knob.

Providers with no observable first use declare `at_exchange` via `DeclaresBurnMode`: the code is
consumed at redemption, under lock. A provider declaring `at_exchange` does not implement the hitch
claim contract and must not advertise it.

**If an attacker claims first, the behaviour is designed, not accidental:** the code is burnt, the
legitimate recipient sees `code_already_claimed`, and the issuer revokes the attacker's credential
and re-issues. Note that a flaky network looks exactly the same from the recipient's side — treat
every `code_already_claimed` as a revoke-and-re-issue, not automatically as an incident.

## For integrators

Exchange mints durables through the `DurableCredentialMinter` seam (default: `api_tokens` via
`ApiTokenMinter`); a later release redirects it to the unified credential store without changing
the primitive. Every plaintext the primitive produces travels internally in `MintedSecret` and
egresses exactly once, at the documented response field.
