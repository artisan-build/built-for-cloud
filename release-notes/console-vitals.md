# Console ops-vitals read (Console PRD D9 / D15 / D16)

`GET /bfc/console/vitals` — a `metadata`-classified surface the vendor's fleet dashboard reads:
health, contract and app versions, deploy recency, queue backlog, and one app-declared headline
stat. `api_version` stays **2**; the route and its fields are additive.

The `metadata:read` ability moves from RESERVED to **enforced**, and the route is gated on it
exclusively — an operator subject whose abilities are exactly `{metadata:read}`, nothing more.
D16 forbids the ownership/admin credential on any dashboard read path, so `credential:admin`
does not reach this route, a legacy admin `api_tokens` secret does not authenticate on it, and a
credential that *also* holds another ability is refused rather than admitted.

`GET /bfc/meta` `capabilities` gains `console-vitals`.

---

## SOURCE-BREAKING CHANGES

Two, both in 0.5.x, both loud rather than silent. Neither changes any HTTP request or response
shape, so no consumer's wire integration breaks — these affect PHP code that references package
symbols.

### 1. `OperatorAbility::RESERVED_METADATA_READ` is removed

The constant shipped in **v0.5.0** as a reserved name. `metadata:read` is now a real enum case,
so a constant literally named `RESERVED_` beside an enforced case would have been a false name
in the vocabulary that exists to be read literally.

**Migrate:** replace `OperatorAbility::RESERVED_METADATA_READ` with
`OperatorAbility::MetadataRead->value` (identical string, `'metadata:read'`). A reference to the
old constant is an `Error: Undefined constant` at the point of use — loud, and it names the
symbol.

### 2. `DeclaresHeadlineStat` is a new interface, and its vocabulary is a CONSTANT

This interface is new in this release, so nothing implemented an earlier version of it in a
tagged release. It is called out because the shape is unusual and an implementer will hit it:

```php
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresHeadlineStat;
use ArtisanBuild\BuiltForCloud\Vitals\{HeadlineLabel, HeadlineStat, HeadlineUnit};

enum SinkHeadlineLabel: string implements HeadlineLabel
{
    case ActiveSessions = 'active-sessions';
    case OpenCases = 'open-cases';
}

final class SinkDeclaration implements CredentialDeclaration, DeclaresHeadlineStat
{
    public const ?string HEADLINE_VOCABULARY = SinkHeadlineLabel::class;

    public function headlineStat(): ?HeadlineStat
    {
        return new HeadlineStat(Session::active()->count(), SinkHeadlineLabel::ActiveSessions, HeadlineUnit::Count);
    }
}
```

**The vocabulary is a class constant, not a method, and that is load-bearing.** A constant must
be a constant expression, so which vocabulary applies is fixed when the file is parsed; the enum
it names has a case set fixed at compile time. Between them, neither *which* labels are
permitted nor *what* they are can be assembled from runtime data — which is exactly what D15
requires, and what a `list<string>` returned by a method could not deliver.

A declaration that implements the interface without defining the constant inherits `null`, which
means "no vocabulary": the payload reports `"headline": null`. Reporting a stat *anyway* is a
contradiction in the declaration and degrades the payload — deliberately visible rather than
silently dropped.

Failures here are fatal at the point of use (a missing `headlineStat()` method, or a `TypeError`
from passing a string where a `HeadlineLabel` case belongs), never a silently wrong payload.

---

## WITHDRAWN in this release: the general conformance instrument

An app-extensible metadata-conformance instrument was prototyped here and **removed before
release**. It is called out because it briefly existed in this branch's history and because the
reason it went is worth carrying forward.

It let a consuming app describe its own `metadata` endpoint with a schema and claimed to certify
"no free text" for it. It could not. **If the app supplies the schema, the app decides what
counts as free text** — it names the fields and the permitted `enum` members, so a runtime value
like `note: pending` can be declared a bounded identifier or a permitted member and pass. Four
rounds of narrowing the schema language closed four escapes and never touched that one, because
closing a type-name set does not establish value *provenance*.

What ships instead is enumeration: `ContractAssertions` writes out the expected 2xx shape of
every `metadata`-classified route **this package** serves, and
`assertBuiltForCloudMetadataEndpoint($response, 'METHOD /uri')` checks one of them. There is no
parameter through which a caller supplies a shape, and a route name it has not enumerated fails.

**If you are converting an app:** write explicit expected-shape assertions for your own metadata
endpoints, the way this package does for its own. A general instrument is deferred as its own
decision.

---

## Deployment identity is required for vitals caching

`GET /bfc/console/vitals` caches its queue snapshot, and the cache key is a digest of a
deployment identifier plus the complete resolved queue connection config. Set
`BUILT_FOR_CLOUD_DEPLOYMENT_ID` (or rely on `built-for-cloud.cloud.application`).

**With neither set the snapshot is not cached at all** — every poll reads the queue directly.
That is the intended behaviour, not a regression: without an identifier, two apps sharing a
cache prefix would compute the same key and be served each other's backlog as honest local data.
Slower vitals is the honest failure; silently mixed vitals is not.

---

## Apps that do nothing

An app that upgrades and changes nothing gets the route mounted, refusing every request with
`401`/`403` because no credential holds `metadata:read`. It reports no headline, and its
`app_version` and `deployed_at` are `null` until it sets `BUILT_FOR_CLOUD_APP_VERSION` and
`BUILT_FOR_CLOUD_DEPLOYED_AT`. The `routes` surface flag (PRD 1.14) unmounts it with every other
package route.
