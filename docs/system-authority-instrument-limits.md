# System Authority Instrument Limits

Built for Cloud enforces two rules at runtime while one of its requestless entries executes:

- A package command, package `ShouldQueue` job/listener, or package-registered schedule callback cannot authenticate a human through a Laravel guard that dispatches `Authenticated` or `Login`.
- The same entries cannot create a bound-user audit actor through `AuditActor::boundUser()`.

Every package command inherits the context wrapper. Queue membership remains derived with Laravel's
`ShouldQueue` interface and is pinned to the package queue marker; processed, failed, and exception
events remove that entry's context frame. Package schedule callbacks are wrapped when registered.
The authentication listener clears `SessionGuard` state before throwing a typed violation. Both
events are required: session and direct-login paths dispatch `Authenticated`, while remember-me
recaller restoration dispatches `Login` only.

## Boundary

The runtime authentication bound depends on the guard dispatching Laravel's authentication events.
`RequestGuard`, a custom host guard that dispatches neither event, and host code outside the package's
derived command, queue, and schedule inventories are host configuration rather than package entries.

`SystemAuthorityInventory` remains an advisory source tripwire and the static proof for the
`UserRole`-derived-authority prohibition over the derived inventories. Its command membership comes
from explicit provider registration, queue membership from `is_a(..., ShouldQueue::class)`, schedule
identity from registered callable/command identity, and role-write handling from tokenized positional
analysis. Its PHP-source ceiling remains: helper and transitive calls, dynamic construction, facade
spellings outside its recognized set, generated code, and unscanned host/vendor roots can evade the
tripwire. It therefore does not carry the runtime authentication or bound-user-actor claims.
