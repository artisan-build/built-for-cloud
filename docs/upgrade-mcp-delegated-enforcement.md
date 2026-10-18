# Upgrade delegated MCP conformance

A product that advertises `mcp-delegated` must now run the behavioral enforcement helper in the same test that runs fleet conformance. The older `McpDelegatedTools` helper remains available for declaration checks. `McpDelegatedEnforcement::assertHonors()` also runs those checks, then registers and invokes every expected tool under a signed assertion that passes the package verifier.

## Resolve the caller through Built for Cloud

Use `ActingPrincipalResolver` as the only identity source in MCP tools. Do not read `auth()->user()`, `Auth::id()`, `$request->user()`, or `RequestAssertion` directly. Those paths either miss a relayed caller or repeat the three-shape resolution rule that the package owns.

Call `require()` near the start of every tool handler, before returning application errors:

```php
use ArtisanBuild\BuiltForCloud\Console\ActingPrincipalResolver;

$principal = app(ActingPrincipalResolver::class)->require(request());
```

The result may hold a delegated actor, a direct MCP credential, or a local session principal. Authorize the returned principal for the operation. `localUser()` is a projection helper and is not an authorization decision. It always returns `null` for delegated actors, so never strip `bfc-console:` from an identifier or map a delegated actor onto a local `users` row.

If a credential declaration participates in local-human containment, `resolveSubject()` must derive its answer from the supplied request's user. It must not use the ambient guard or client input when that request already has a user. The hook runs on authenticated request paths, so keep it free of side effects and extra I/O.

## Add the enforcement assertion

Declare the complete tool class list. An empty list fails, and the discovered list must match it exactly.

```php
use App\Mcp\ProductMcpServer;
use App\Mcp\Tools\ListItems;
use App\Mcp\Tools\ShowItem;
use ArtisanBuild\BuiltForCloud\Testing\McpDelegatedEnforcement;

McpDelegatedEnforcement::assertHonors(
    ProductMcpServer::class,
    [ListItems::class, ShowItem::class],
);

$this->assertBuiltForCloudFleetConformance($spec);
```

Run `assertHonors()` before fleet conformance. This order matters. The successful assertion records the server and exact tool list in the current test application, which lets the later fleet check distinguish a behavioral probe that ran in this test process from a capability flag and server class that were merely declared. A `ConsumerConformance` spec that advertises `mcp-delegated` fails with `mcp-delegated-enforcement-not-run` until that record exists.

The probe builds minimum values from each tool's JSON schema. Defaults and enum values win. It handles required and closed objects, array item bounds, booleans, bounded numbers and numeric multiples, common string formats, and string length bounds. A pattern, unknown format, or multi-item uniqueness constraint is not guessed. The tool appears in `unreached`, and `assertHonors()` fails instead of skipping it. Reviewed overrides are checked against the same schema before invocation. Supply arguments for that tool:

```php
McpDelegatedEnforcement::assertHonors(
    ProductMcpServer::class,
    [ListItems::class, ShowItem::class],
    arguments: [
        ShowItem::class => ['item_id' => 'ITEM-0001'],
    ],
);
```

An application error returned after the tool observes the canonical principal does not become an identity refusal. The harness detects package identity exceptions by class, not message text. An error response returned before the canonical principal is observed fails as an untyped refusal.

## Add a second-subject case

Pass a closure when the product stores rows owned by a principal or tenant. The harness publishes a second verified subject, registers the server again under that subject, and gives the closure an invocation function. Arrange a row for the first principal, call the relevant read tool as the second, and assert that the first principal's row is absent.

```php
use ArtisanBuild\BuiltForCloud\Console\ActingPrincipal;
use Closure;

$negative = static function (
    ActingPrincipal $first,
    ActingPrincipal $second,
    Closure $invoke,
): void {
    Item::query()->create([
        'owner_ref' => $first->identifier(),
        'name' => 'first subject only',
    ]);

    $response = $invoke(ListItems::class);

    // Assert from the tool's structured result that the inserted row is absent.
};

McpDelegatedEnforcement::assertHonors(
    ProductMcpServer::class,
    [ListItems::class, ShowItem::class],
    negativeAuthorization: $negative,
);
```

The probe records `negative_authorization` as `passed`, `failed`, or `absent`. Absence is explicit because some products have no principal-owned rows. Do not use `absent` when a tool reads principal-owned or tenant-owned data.

The fixture assertion passes `AssertionVerifier` before publication. This helper does not establish expiry enforcement after publication or the single-use `AssertionBurn` behavior paid by production middleware.

## Consumer migration inventory

The inventory below comes from the 2026-10-17 audit of the 13 catalog repositories at their recorded `origin/main` revisions. It is migration evidence, not a claim about later commits or deployments.

| Products | Required migration |
| --- | --- |
| Assay, Telltale, Wake | Replace the app-owned `RequestAssertion` and credential resolver with `ActingPrincipalResolver`. Add the exact-list enforcement assertion. Assay and Wake must keep their registration predicates; the new assertion evaluates them under delegation. |
| Reel | Replace direct `DelegatedActor` handling with the canonical resolver, then add the exact-list enforcement assertion. |
| Crate, Hone, Matte, Muster, Slate | Their audited tools were identity-blind. Every tool must observe the canonical principal, and each product must add the exact-list enforcement assertion. Add a second-subject case wherever product rows gain principal or tenant ownership. |
| Capstan | The audited resolver accepted credentials only. Move every tool to the canonical resolver and define delegated ownership without mapping the actor to a local user. Add the exact-list enforcement assertion and a scoped second-subject case. |
| Witness | The audited resolver accepted credentials only, while all six tools scoped through local user rows. Choose the delegated ownership model, migrate all tools, add the exact-list enforcement assertion, and prove isolation with a second-subject case. |
| Bobbin | Remove the delegated fallback to the first team. Resolve an explicit authorized scope, add the exact-list enforcement assertion, and add a second-subject case that fails if team-one rows cross subjects. |
| Sink | Confirm the advertised MCP path uses the package MCP middleware rather than the legacy assertion-refusing door. Make every tool observe the canonical principal and add the exact-list enforcement assertion. |

Delegated assertions remain invalid on `bfc.admin`, `bfc.auth`, and local personal-credential surfaces. This upgrade applies only to MCP tool handlers and does not widen delegated authority.
