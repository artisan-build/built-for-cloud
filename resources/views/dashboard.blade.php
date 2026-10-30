<x-bfc-layout title="Dashboard">
<section data-testid="dashboard"
         class="bfc-dashboard">
    <header>
        <h1 class="bfc-dashboard-title">Ask {{ $name }}</h1>
        <p class="bfc-dashboard-lede">{{ $name }} answers through your agent. Copy a prompt into your agent chat to get started.</p>
    </header>

    @include('bfc::shell.agent-prompts', ['prompts' => $prompts])
</section>
</x-bfc-layout>
