<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

final class SecondStoreResolver
{
    public function resolve(string $secret): ?SecondStoreRecord
    {
        return SecondStoreRecord::query()->where('token_hash', hash('sha256', $secret))->first();
    }
}

final class SecondStoreRecord
{
    public static function query(): SecondStoreQuery
    {
        return new SecondStoreQuery;
    }
}

final class SecondStoreQuery
{
    public function where(string $column, string $value): self
    {
        return $this;
    }

    public function first(): ?SecondStoreRecord
    {
        return null;
    }
}
