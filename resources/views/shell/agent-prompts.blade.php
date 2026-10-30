{{-- Copyable prompts that put questions to this app through the Scalpels MCP; see AgentPrompts. --}}
<div class="bfc-prompts">
    @foreach ($prompts as $prompt)
        <article data-testid="dashboard-prompt"
                 class="bfc-prompt">
            <h2 class="bfc-prompt-title">{{ $prompt['title'] }}</h2>
            <textarea id="bfc-prompt-{{ $loop->index }}"
                      class="bfc-prompt-text"
                      rows="4"
                      readonly>{{ $prompt['prompt'] }}</textarea>
            <div class="bfc-prompt-actions">
                <button type="button"
                        class="bfc-button-soft"
                        data-testid="dashboard-prompt-copy"
                        onclick="navigator.clipboard.writeText(document.getElementById('bfc-prompt-{{ $loop->index }}').value).then(() => { this.nextElementSibling.textContent = 'Copied'; }, () => { this.nextElementSibling.textContent = 'Select the text and copy it'; })">
                    Copy prompt
                </button>
                <span class="bfc-prompt-status"
                      aria-live="polite"></span>
            </div>
        </article>
    @endforeach
</div>
