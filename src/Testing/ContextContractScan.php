<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use ReflectionClass;
use ReflectionIntersectionType;
use ReflectionNamedType;
use ReflectionType;
use ReflectionUnionType;

final class ContextContractScan
{
    /** @param class-string $contract
     *  @return list<string>
     */
    public static function violations(string $contract): array
    {
        $violations = [];

        foreach ((new ReflectionClass($contract))->getMethods() as $method) {
            $normalizedName = strtolower($method->getName());

            if (preg_match('/password|hash|guard|token.?name|display.?name/', $normalizedName) === 1) {
                $violations[] = $method->getName().':sensitive-name';
            }

            foreach ($method->getParameters() as $parameter) {
                $normalizedParameter = strtolower($parameter->getName());

                if (preg_match('/password|hash|guard|token.?name|display.?name/', $normalizedParameter) === 1) {
                    $violations[] = $method->getName().':$'.$parameter->getName();
                }

                self::collectTypeViolations($method->getName(), $parameter->getType(), $violations);
            }

            self::collectTypeViolations($method->getName(), $method->getReturnType(), $violations);
        }

        return array_values(array_unique($violations));
    }

    /** @param list<string> $violations */
    private static function collectTypeViolations(string $method, ?ReflectionType $type, array &$violations): void
    {
        if ($type instanceof ReflectionUnionType || $type instanceof ReflectionIntersectionType) {
            foreach ($type->getTypes() as $member) {
                self::collectTypeViolations($method, $member, $violations);
            }

            return;
        }

        if (! $type instanceof ReflectionNamedType || $type->isBuiltin()) {
            return;
        }

        $name = $type->getName();

        if (str_starts_with($name, 'Illuminate\\')
            || str_starts_with($name, 'Symfony\\')
            || is_a($name, Model::class, true)
            || is_a($name, Authenticatable::class, true)) {
            $violations[] = $method.':'.$name;
        }
    }
}
