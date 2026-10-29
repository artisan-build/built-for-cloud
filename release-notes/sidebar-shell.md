# Sidebar shell

The package default `<x-bfc-layout>` now uses the same sidebar structure as Scalpels. From `lg`, the
sidebar stays beside the page. On smaller screens, navigation becomes a native popover drawer and
signed-in controls move from the sidebar foot to the mobile header, without loading Flux or Alpine
JavaScript from the package or app.

Apps can add their navigation below the package links with a named slot:

```blade
<x-bfc-layout>
    <x-slot:sidebar>
        <nav aria-label="Product navigation">
            {{-- App-owned links --}}
        </nav>
    </x-slot:sidebar>

    {{-- Page content --}}
</x-bfc-layout>
```

Full-page Livewire views can declare the same `<x-slot:sidebar>` inside their root element. Livewire
then forwards the slot to the configured layout.

## Upgrade

Move app-owned navigation into the `sidebar` slot. Remove any sidebar that the app currently nests
inside `<x-bfc-layout>` so the page does not render two navigation columns. Apps that omit the slot
receive the package fallback. The package serves the shell CSS through `bfc.assets`, so consumers do
not need an asset build.

Configured layout replacements, subclasses of `Layout`, the `livewire_layout` opt-out, and the
`head` and `scripts` stacks keep their existing behavior.
