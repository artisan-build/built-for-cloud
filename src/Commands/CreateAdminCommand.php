<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Commands;

use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Hash;

use function Laravel\Prompts\password;
use function Laravel\Prompts\text;

final class CreateAdminCommand extends Command
{
    protected $signature = 'create-admin {--email=} {--password=} {--name=} {--force}';

    protected $description = 'Create an administrator user for the configured auth model';

    public function handle(): int
    {
        $userClass = $this->userModelClass();

        if (! (bool) $this->option('force') && $userClass::query()->where('is_admin', true)->exists()) {
            $this->error('An admin user already exists. Pass --force to create another.');

            return self::FAILURE;
        }

        $email = $this->stringOption('email') ?? text(label: 'Email');
        $plainPassword = $this->stringOption('password') ?? password(label: 'Password');
        $name = $this->stringOption('name') ?? text(label: 'Name');

        $userClass::query()->create([
            'name' => $name,
            'email' => $email,
            'password' => Hash::make($plainPassword),
            'is_admin' => true,
        ]);

        $this->line("Admin user {$email} created.");

        return self::SUCCESS;
    }

    private function stringOption(string $key): ?string
    {
        $value = $this->option($key);

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * @return class-string<Model>
     */
    private function userModelClass(): string
    {
        $configured = config('auth.providers.users.model', 'App\\Models\\User');

        return is_string($configured) && is_a($configured, Model::class, true)
            ? $configured
            : 'App\\Models\\User';
    }
}
