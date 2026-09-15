<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use InvalidArgumentException;
use JsonSerializable;

/** The resolved, production-equivalent shared state identity of one HTTP node. */
final readonly class SharedRuntimeIdentity implements JsonSerializable
{
    /** @param array<string, array{driver: string, version: string, identity: string}> $roles */
    public function __construct(
        public string $database,
        public array $roles,
    ) {
        PostgresRunIdentity::assertDatabaseName($database);

        if (array_keys($roles) !== P6GateContract::SHARED_ROLES) {
            throw new InvalidArgumentException('The shared runtime role inventory is incomplete or out of order.');
        }

        foreach ($roles as $role => $resolved) {
            if (array_keys($resolved) !== ['driver', 'version', 'identity']
                || $resolved['driver'] === ''
                || $resolved['version'] === ''
                || $resolved['identity'] === ''
                || in_array(strtolower($resolved['driver']), P6GateContract::ISOLATED_DRIVERS, true)) {
                throw new InvalidArgumentException("The resolved {$role} substrate is not shared.");
            }
        }
    }

    public function assertSameAs(self $other): void
    {
        if ($this->database !== $other->database || $this->roles !== $other->roles) {
            throw new InvalidArgumentException('The two HTTP nodes do not resolve the same shared runtime identity.');
        }
    }

    /** @return array{database: string, roles: array<string, array{driver: string, version: string, identity: string}>} */
    public function jsonSerialize(): array
    {
        return ['database' => $this->database, 'roles' => $this->roles];
    }
}
