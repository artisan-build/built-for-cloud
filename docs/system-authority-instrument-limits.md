# System Authority Instrument Limits

Built for Cloud enforces two rules at runtime while one of its requestless entries executes:

- A package command, package `ShouldQueue` job/listener, or package-registered schedule callback cannot authenticate a human through a Laravel guard that dispatches `Authenticated` or `Login`.
- The same entries cannot create a bound-user audit actor through `AuditActor::boundUser()`.

Every package command inherits the context wrapper, which frames the command's own invocation.
Package queue entries are framed the same way, at invocation, by a bus pipe: `Dispatcher::dispatchNow()`
runs commands through the pipes, and the queue worker reaches `dispatchNow()` too, so the worker, the
sync driver, `dispatchSync()` and `dispatchNow()` are all covered by one mechanism. Entry identity comes
from the dispatched OBJECT — a marker interface, the class a queued-listener wrapper names, or the file a
queued closure was declared in — never from a display name, which callers control. The queue-event
listeners remain alongside as a second, independent frame. Package schedule callbacks are wrapped when
registered.
The authentication listener clears `SessionGuard` state before throwing a typed violation. Both
events are required: session and direct-login paths dispatch `Authenticated`, while remember-me
recaller restoration dispatches `Login` only.

## Boundary

The bus pipe is APPENDED to the dispatcher's existing pipes rather than replacing them, but
`Dispatcher::pipeThrough()` sets that array outright, so a host that calls it after this package boots
removes the invocation frame. The queue-event frame still applies in that case. This is the same exposure
any package has with that API.

The bound covers any guard that dispatches `Authenticated` or `Login`, not only `SessionGuard`.

Six shapes are outside the bound, and package code must not use them to authenticate a human:

- A queued entry's `failed()` method on the `sync` driver runs after the frame has closed.
- A callback handed to `defer()` runs after the frame has closed.
- A schedule `before` or `after` hook runs outside the wrapped callback.
- A schedule registered directly on `Schedule` rather than through the package wrapper is never framed.
- A queued closure dispatched by package code is never framed: a closure's declaring file does not survive serialisation, so its origin cannot be established once it reaches the queue.
- In-process tampering switches the bound off: removing the listeners, replacing a guard's event dispatcher, or rebinding the system-authority context.

Each of those six carries an open `risk=security` debt row, so any future package change that reaches one is reviewed against it.

`RequestGuard`, a custom host guard that dispatches neither event, and host code outside the package's
derived command, queue, and schedule inventories are host configuration rather than package entries.

`SystemAuthorityInventory` remains an advisory source tripwire and the static proof for the
`UserRole`-derived-authority prohibition over the derived inventories. Its command membership comes
from explicit provider registration, queue membership from `is_a(..., ShouldQueue::class)`, schedule
identity from registered callable/command identity, and role-write handling from tokenized positional
analysis. Its PHP-source ceiling remains: helper and transitive calls, dynamic construction, facade
spellings outside its recognized set, generated code, and unscanned host/vendor roots can evade the
tripwire. It therefore does not carry the runtime authentication or bound-user-actor claims.
