<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Commands;

use ArtisanBuild\BuiltForCloud\Database\Seeders\OwnerSeeder;
use Illuminate\Console\Prohibitable;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Str;
use ReflectionClass;

/**
 * Rebuilds a development database from nothing: `migrate:fresh`, the package's
 * Owner, then every seeder the app defines. It refuses to run in production,
 * and wherever the app has prohibited destructive database commands.
 */
final class FreshCommand extends SystemAuthorityCommand
{
    use Prohibitable;

    protected $signature = 'fresh';

    protected $description = 'Migrate fresh, seed the Owner (owner@example.com / password), then run every app seeder. Never runs in production.';

    /** Wipe and reseed the database, stopping at the first step that fails. */
    public function handle(): int
    {
        if ($this->laravel->isProduction()) {
            $this->components->error('fresh refuses to run in production: it drops every table.');

            return self::FAILURE;
        }

        if ($this->isProhibited()) {
            return self::FAILURE;
        }

        foreach ([['migrate:fresh', []], ['db:seed', ['--class' => OwnerSeeder::class]], ...$this->appSeederCalls()] as [$command, $arguments]) {
            if ($this->call($command, $arguments) !== self::SUCCESS) {
                return self::FAILURE;
            }
        }

        $this->components->info('Sign in as '.OwnerSeeder::EMAIL.' / '.OwnerSeeder::PASSWORD.'.');

        return self::SUCCESS;
    }

    /**
     * One db:seed call per concrete Seeder under the app's database/seeders,
     * in class name order. DatabaseSeeder is skipped: it is conventionally the
     * seeder that calls the others, so running it too would seed them twice.
     *
     * @return list<array{string, array<string, string>}>
     */
    private function appSeederCalls(): array
    {
        $directory = $this->laravel->databasePath('seeders');

        if (! File::isDirectory($directory)) {
            return [];
        }

        $seeders = collect(File::allFiles($directory))
            ->map(static fn (\SplFileInfo $file): string => 'Database\\Seeders\\'.Str::of($file->getRelativePathname())->beforeLast('.php')->replace('/', '\\'))
            ->filter(static fn (string $class): bool => $class !== 'Database\\Seeders\\DatabaseSeeder'
                && class_exists($class)
                && is_subclass_of($class, Seeder::class)
                && ! (new ReflectionClass($class))->isAbstract())
            ->sort()
            ->values();

        return $seeders->map(static fn (string $class): array => ['db:seed', ['--class' => $class]])->all();
    }
}
