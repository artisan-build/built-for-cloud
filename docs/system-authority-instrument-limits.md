# System Authority Instrument Limits

Built for Cloud enforces two rules at runtime while one of its requestless entries executes:

- A package command, package `ShouldQueue` job/listener, or package-registered schedule callback cannot authenticate a human through a Laravel guard that dispatches `Authenticated` or `Login`.
- The same entries cannot create a bound-user audit actor through `AuditActor::boundUser()`.

Every package command inherits the context wrapper, which frames the command's own invocation.
Package queue entries are framed the same way, at invocation, by a bus pipe: `Dispatcher::dispatchNow()`
runs commands through the pipes, and the queue worker reaches `dispatchNow()` too, so the worker, the
sync driver, `dispatchSync()` and `dispatchNow()` are all covered by one mechanism. Entry identity comes from the dispatched OBJECT: a marker interface, the class a queued-listener wrapper names, or the payload's `commandName`, which the queue writes as the job's class. Never from a display name, which a job can choose. The queue-event listeners remain alongside as a second
frame, and the two fail for genuinely different reasons: the invocation frame is absent when nothing runs
through the bus dispatcher, while the queue-event frame is absent when no queue events fire, as on a direct
`dispatchNow()`. Neither shares the other's blind spot. Both take identity from the class, so neither can be
redirected by a display name. A queued entry's `failed()` handler is inside the frame, as is the middleware a queued entry runs: for a job that is its own `middleware()` method, and for a listener it is the middleware objects that method returns. A listener's `middleware()` method body is NOT — the framework calls it when the event is dispatched, so it runs in the dispatcher's context, along with `shouldQueue`, `viaConnection`, `viaQueue`, `withDelay`, `backoff`, `retryUntil` and `tries`. Those are framed only when the code dispatching the event is itself framed. The queue frame is released on `JobAttempted`, which the worker and the sync driver each dispatch from a `finally`. It is deliberately NOT released on `JobProcessed`, `JobFailed` or `JobExceptionOccurred`: each of those fires while package code can still run.
Package schedule callbacks are wrapped when registered.
The authentication listener clears `SessionGuard` state before throwing a typed violation. Both
events are required: session and direct-login paths dispatch `Authenticated`, while remember-me
recaller restoration dispatches `Login` only.

## Boundary

The bus pipe is APPENDED to the dispatcher's existing pipes rather than replacing them, but
`Dispatcher::pipeThrough()` sets that array outright, so a host that calls it after this package boots
removes the invocation frame and reverts the bound to framing by queue events alone. That is host
configuration, and it is the same exposure any package has with that API.

The bound covers any guard that dispatches `Authenticated` or `Login`, not only `SessionGuard`.

The bound is stated as a class rather than as a list of shapes, because naming shapes is how the previous four attempts each missed the next one. **Any package code that runs outside a framed invocation is outside the bound.** Package code must not authenticate a human or synthesize a bound-user actor from any of it. That class includes, and is not limited to: any callback registered for later invocation, such as `defer()`, `app()->terminating()`, a listener registered at runtime, a shutdown function, or a chain or batch `catch`/`finally` callback; and any callback attached to a schedule event, including its `before`/`after` hooks and its `when`/`skip` filters.

Two further limits are part of the same class:

- A queued closure dispatched by package code is never framed. Its declaring file does not survive serialisation, and the scope class that does survive is caller-settable, so its origin cannot be established as identity.
- In-process tampering switches the bound off: removing the listeners, replacing a guard's event dispatcher, or rebinding the system-authority context. A host that calls `Bus::pipeThrough()` after this package boots also replaces the pipe array and reverts the bound to framing by queue events alone.

Each limit above carries an open `risk=security` debt row, so any future package change that reaches one is reviewed against it.

`RequestGuard`, a custom host guard that dispatches neither event, and host code outside the package's
derived command, queue, and schedule inventories are host configuration rather than package entries.

`SystemAuthorityInventory` remains an advisory source tripwire and the static proof for the
`UserRole`-derived-authority prohibition over the derived inventories. Its command membership comes
from explicit provider registration, queue membership from `is_a(..., ShouldQueue::class)`, schedule
identity from registered callable/command identity, and role-write handling from tokenized positional
analysis. Its PHP-source ceiling remains: helper and transitive calls, dynamic construction, facade
spellings outside its recognized set, generated code, and unscanned host/vendor roots can evade the
tripwire. It therefore does not carry the runtime authentication or bound-user-actor claims.
