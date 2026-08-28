<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Commands\Concerns;

use Illuminate\Console\Command;

/**
 * Shared input parsing for the unified-verb commands. Note what is NOT
 * here: no secret is ever accepted as an argument or option (D7's CLI
 * rule — argv reaches shell history and the process table). These
 * commands OUTPUT secrets, printed once to the TTY; they never take one.
 *
 * @phpstan-require-extends Command
 */
trait ParsesCredentialVerbInput
{
    private function stringOption(string $key): ?string
    {
        $value = $this->option($key);

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * @return list<string>|null
     */
    private function abilitiesOption(): ?array
    {
        $value = $this->stringOption('abilities');

        if ($value === null) {
            return null;
        }

        $abilities = array_values(array_filter(array_map(
            static fn (string $ability): string => trim($ability),
            explode(',', $value),
        ), static fn (string $ability): bool => $ability !== ''));

        return $abilities === [] ? null : $abilities;
    }

    /**
     * The unified verbs run over exactly two transports (PRD 1.0): this
     * command with `--local` (zero Cloud dependency, direct database, same
     * process) or the versioned HTTP contract. There is no cloud-wrapped
     * driver mode here to fall back to.
     */
    private function requireLocal(): bool
    {
        if ((bool) $this->option('local')) {
            return true;
        }

        $this->error(
            'This verb runs locally: pass --local to act on this machine\'s database. '
            .'To manage a remote instance, call its HTTP contract (docs/http-contract.md) '
            .'with an operator credential.',
        );

        return false;
    }
}
