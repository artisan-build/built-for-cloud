# The sealed plaintext carrier and the negative-leakage harness

This release ships the two pieces of shared machinery every later
secret-producing surface builds on: the sealed carrier a framework-minted
plaintext travels in, and the reusable negative-leakage harness that proves
a secret never escaped. Nothing here mints a real secret over any user
surface — this is the containment machinery plus its own proof.

## The carrier: `MintedSecret`

A final class that carries a framework-minted plaintext from creation to
its single point of delivery, and structurally refuses every accidental
egress:

- **The plaintext lives outside the object** — in a class-level WeakMap
  keyed by instance — so `var_export`, `print_r`, `var_dump`,
  `get_object_vars()`, `json_encode(get_object_vars())` and reflection
  walks over the instance's properties show nothing.
- **Serialization throws.** `serialize()`, `__sleep`, `__serialize` and
  `json_encode()` all throw, so a queued job payload, cache write, session
  put, log context or component snapshot cannot carry the value out.
- **No string conversion.** There is no `__toString`; interpolation and
  `(string)` casts are fatal errors, never a silent secret.
- **Cloning throws** — a copy would be a second delivery.
- **Reveal-once.** The value leaves through exactly one accessor:
  `reveal()` returns the plaintext once, drops it from memory, and throws
  a `LogicException` on every later call. `revealed()` inspects without
  touching the value. The TTY print-once and reveal-once rules of D7
  become structural rather than conventional.
- **`hash()`** exposes the sha256 — the intended at-rest form — any number
  of times; a hash is not a secret.
- The constructor parameter carries `#[SensitiveParameter]`, so stack
  traces and exception context redact it.

What the carrier cannot enforce: a consumer that assigns
`$carrier->reveal()` to a variable owns that copy, and reflection is not
an egress boundary — `ReflectionProperty` on the class-level store can
recover an unrevealed plaintext, because no in-memory design resists
reflection. The carrier makes accidental egress
(serialize/json/dump/export) structurally impossible, not deliberate
egress. Delivery shapes (PRD 1.6, later releases) wrap this class; it
stays final and metadata-free so they can.

## The harness: `Testing\DetectsSecretLeaks`

A Pest/PHPUnit trait — also mixed into `Testing\ContractTestCase` for
consuming apps — that asserts a secret marker never escapes while an
action runs:

```php
$this->assertNoSecretLeakage($plaintext, fn () => $this->postJson(...));
```

Watched channels: **log** (every record's message + context), **database**
(INSERT/UPDATE/REPLACE write statements during the action — Eloquent's
write shapes; data-modifying CTEs, procedures and raw PDO writes are
caught only by the at-rest sweep — plus a post-action sweep of every
table's stored values, where a value that is exactly
`hash('sha256', marker)` is allowed, the intended at-rest form), **queue**
(the real enqueued artifact: JobQueued payloads, the raw body of every
processing job — the sync driver's observable point — the serialized job
object itself, and a sweep of `Queue::fake()`'s pushed jobs), **cache**
(every value written), and the **session** payload. Per-artifact helpers
cover the rest: `assertResponseCarriesNoSecret` (body + headers),
`assertConsoleOutputCarriesNoSecret`, and `assertExceptionCarriesNoSecret`
(message, rendered trace, context, the whole previous chain).

Detection sees through recoverable encodings, not just literal bytes:
every captured string is also scanned URL-decoded, JSON-unescaped, and
with every base64-alphabet run decoded — which is what catches a logged
`Basic base64(user:secret)` header. If the watched action throws, the
captured channels are still asserted: a leak fails the test naming both
signals; a clean throw propagates untouched. Failure messages name the
leaking channel and the matched form, and never echo the leaked content.
No state bleeds between tests.

Every channel ships with a falsifiability self-test that deliberately
plants the marker in that channel — literal and encoded, throwing and
not — and asserts the harness catches it; a detector that cannot catch a
planted leak is a detector that cannot fail. On the guard path itself, a
deliberately leaky middleware that logs the Authorization header proves
the harness would fire on the basic path.

## The D7 row this discharges

D7's surface table ends with the "everywhere" row: snapshot, export and
observability tests assert secret markers are absent. This release ships
that row's shared machinery — the carrier and the harness — and proves it
against the existing guard paths (a bearer and a basic presentation to a
`bfc`-guarded route leak nothing, accepted or rejected). Each later
secret-producing surface (claim codes, mint verbs, rotation, hmac) still
ships its own surface-specific negative tests using this harness; the
TTY-delivery commands of later releases will add an explicit reveal-once
console allowance when they exist.
