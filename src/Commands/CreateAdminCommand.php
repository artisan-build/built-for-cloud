<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Commands;

use ArtisanBuild\BuiltForCloud\CloudCommandRunner;
use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Schema;

use function Laravel\Prompts\password;
use function Laravel\Prompts\select;
use function Laravel\Prompts\text;

final class CreateAdminCommand extends Command
{
    protected $signature = 'create-admin {--execute} {--email=} {--password=} {--password-hash=} {--name=} {--environment=} {--local} {--force}';

    protected $description = 'Create an administrator user for the configured auth model';

    public function handle(CloudCommandRunner $runner): int
    {
        if ((bool) $this->option('execute')) {
            return $this->handleExecute();
        }

        $email = $this->collectEmail();
        $name = $this->collectName();
        $plainPassword = $this->collectPassword();

        if ($email === null || $name === null || $plainPassword === null) {
            return self::FAILURE;
        }

        $target = $this->target($runner);
        $force = (bool) $this->option('force');

        if ($target === 'local') {
            return $this->createAdmin($email, $name, Hash::make($plainPassword), $force);
        }

        $result = $runner->run(
            $target,
            'create-admin --execute --email='.$this->quote($email)
                .' --name='.$this->quote($name)
                .' --password-hash='.$this->quote(Hash::make($plainPassword))
                .($force ? ' --force' : ''),
        );

        $this->line($result['output']);

        return $result['exitCode'];
    }

    private function handleExecute(): int
    {
        $email = $this->stringOption('email');

        if ($email === null) {
            $this->error('The --email option is required when using --execute.');

            return self::FAILURE;
        }

        $passwordHash = $this->stringOption('password-hash');
        $plainPassword = $this->stringOption('password');

        if ($passwordHash === null) {
            if ($plainPassword === null) {
                $this->error('The --password-hash or --password option is required when using --execute.');

                return self::FAILURE;
            }

            $passwordHash = Hash::make($plainPassword);
        }

        return $this->createAdmin(
            $email,
            $this->stringOption('name') ?? '',
            $passwordHash,
            (bool) $this->option('force'),
        );
    }

    private function createAdmin(string $email, string $name, string $passwordHash, bool $force): int
    {
        $userClass = $this->userModelClass();
        $userModel = new $userClass;
        $userTable = $userModel->getTable();

        if (! Schema::hasColumn($userTable, 'is_admin')) {
            $this->error('The is_admin column is missing — run your migrations first.');

            return self::FAILURE;
        }

        if (! $force && $userClass::query()->where('is_admin', true)->exists()) {
            $this->error('An admin user already exists. Pass --force to create another.');

            return self::FAILURE;
        }

        $user = $userClass::query()->create([
            'name' => $name,
            'email' => $email,
            'password' => $passwordHash,
        ]);

        $user->forceFill(['is_admin' => true])->save();

        $this->line("Admin user {$email} created.");

        return self::SUCCESS;
    }

    private function collectEmail(): ?string
    {
        $email = $this->stringOption('email') ?? text(
            label: 'Email',
            validate: $this->validateEmail(...),
        );

        $error = $this->validateEmail($email);

        if ($error !== null) {
            $this->error($error);

            return null;
        }

        return $email;
    }

    private function collectName(): ?string
    {
        $name = $this->stringOption('name') ?? text(
            label: 'Name',
            validate: fn (string $value): ?string => trim($value) !== '' ? null : 'Name is required.',
        );

        if (trim($name) === '') {
            $this->error('Name is required.');

            return null;
        }

        return $name;
    }

    private function collectPassword(): ?string
    {
        $password = $this->stringOption('password');

        if ($password !== null) {
            $error = $this->validatePassword($password);

            if ($error !== null) {
                $this->error($error);

                return null;
            }

            return $password;
        }

        $password = password(
            label: 'Password',
            validate: $this->validatePassword(...),
        );
        $confirmation = password(label: 'Confirm password');

        if ($password !== $confirmation) {
            $this->error('Passwords do not match.');

            return null;
        }

        return $password;
    }

    private function target(CloudCommandRunner $runner): string
    {
        if ((bool) $this->option('local')) {
            return 'local';
        }

        $environment = $this->stringOption('environment');

        if ($environment !== null) {
            return $environment;
        }

        $environments = $runner->listEnvironments();

        if ($environments === []) {
            $this->warn('Laravel Cloud environments could not be listed; only local creation is available.');
        }

        return (string) select(
            label: 'Where should this admin be created?',
            options: ['local' => 'This machine (local database)'] + $environments,
            default: 'local',
        );
    }

    private function stringOption(string $key): ?string
    {
        $value = $this->option($key);

        return is_string($value) && $value !== '' ? $value : null;
    }

    private function validateEmail(string $email): ?string
    {
        if (trim($email) === '') {
            return 'Email is required.';
        }

        return filter_var($email, FILTER_VALIDATE_EMAIL) === false
            ? 'Enter a valid email address.'
            : null;
    }

    private function validatePassword(string $password): ?string
    {
        return strlen($password) >= 8
            ? null
            : 'Password must be at least 8 characters.';
    }

    private function quote(string $value): string
    {
        return escapeshellarg($value);
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
