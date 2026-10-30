<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\View;

use ArtisanBuild\BuiltForCloud\LandingManifest;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Config;

/**
 * The prompts a person copies into their agent to put questions to this app
 * through the Scalpels MCP: the app's declared `dashboard_prompts`, or general
 * ones when it declares none, each behind the same opening. Shared by the
 * default dashboard and any app dashboard that shows them in its own page.
 */
class AgentPrompts
{
    /**
     * Every prompt, ready to copy.
     *
     * @return list<array{title: string, prompt: string}>
     */
    public function all(): array
    {
        $name = App::make(LandingManifest::class)->name;

        return array_map(
            fn (array $prompt): array => [
                'title' => $prompt['title'],
                'prompt' => $this->opening($name).' '.$prompt['ask'],
            ],
            $this->declared() ?: $this->general(),
        );
    }

    /**
     * The prompts the app declared, keeping only well-formed ones.
     *
     * @return list<array{title: string, ask: string}>
     */
    protected function declared(): array
    {
        $prompts = Config::get('built-for-cloud.dashboard_prompts', []);

        if (! is_array($prompts)) {
            return [];
        }

        return array_values(array_filter(
            array_map(
                fn (mixed $prompt): ?array => is_array($prompt) && is_string($prompt['title'] ?? null) && is_string($prompt['ask'] ?? null)
                    ? ['title' => $prompt['title'], 'ask' => $prompt['ask']]
                    : null,
                $prompts,
            ),
        ));
    }

    /**
     * Questions worth asking any app, for one that declares none of its own.
     *
     * @return list<array{title: string, ask: string}>
     */
    protected function general(): array
    {
        return [
            ['title' => 'What can it tell me?', 'ask' => 'Explain in plain language what this app can report on, then suggest three questions worth asking it.'],
            ['title' => 'Does anything need my attention?', 'ask' => 'Look for anything that needs my attention right now, and tell me what to do about each one.'],
            ['title' => 'What changed this week?', 'ask' => 'Summarize what has changed over the last seven days compared with the week before.'],
        ];
    }

    /** How every prompt starts: how the agent reaches this app through the Scalpels MCP. */
    protected function opening(string $name): string
    {
        return "Use the Scalpels MCP to work with my {$name} app. Call `installed_apps` and choose the installed {$name} app, then call `app_tools` to see what it offers.";
    }
}
