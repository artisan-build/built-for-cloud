<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

final class SecondStoreResolver
{
    public function resolve(string $secret): ?OtherStoreRecord
    {
        return OtherStoreRecord::query()->where('token_hash', hash('sha256', $secret))->first();
    }
}

final class OtherStoreRecord
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

    public function first(): ?OtherStoreRecord
    {
        return null;
    }
}
