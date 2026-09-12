<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use RuntimeException;
use SplFileInfo;

/**
 * Derives every statically attributable literal `built-for-cloud.ui.*` read
 * in a PHP source tree. P5-AC13 compares those identities with its reviewed
 * visibility-only set, so an added enforcement consumer is unexpected.
 *
 * This scanner sees global `config('key')`, `config()->get('key')`, imported
 * Config facade reads, and reads on a variable declared with the injected
 * Config Repository contract. Reads include `get` and the typed `string`,
 * `integer`, `float`, `boolean`, and `array` getters. It does not claim data-
 * flow analysis: dynamic/concatenated keys, untyped repositories, wrappers,
 * reflection, Blade/resources, host code and generated caches remain review
 * concerns. Executed enforcement fixtures prove every supported read form.
 */
final class UiConfigReadScan
{
    /**
     * @return list<string> `<consumer>|<exact key>|<ordinal>` identities
     */
    public static function discover(string $root): array
    {
        $reads = [];

        foreach (self::phpFiles($root) as $relativePath => $file) {
            $contents = file_get_contents($file->getPathname());

            if (! is_string($contents)) {
                throw new RuntimeException("Could not read [{$file->getPathname()}].");
            }

            $tokens = token_get_all($contents, TOKEN_PARSE);
            $consumer = self::consumer($tokens) ?? str_replace('/', '\\', substr($relativePath, 0, -4));
            $ordinals = [];

            foreach (self::literalConfigReads($tokens) as $key) {
                if (! str_starts_with($key, 'built-for-cloud.ui.')) {
                    continue;
                }

                $ordinals[$key] = ($ordinals[$key] ?? 0) + 1;
                $reads[] = $consumer.'|'.$key.'|'.$ordinals[$key];
            }
        }

        sort($reads);

        return $reads;
    }

    public static function countPhpFiles(string $root): int
    {
        return count(iterator_to_array(self::phpFiles($root)));
    }

    /**
     * @param  list<array{int, string, int}|string>  $tokens
     * @return list<string>
     */
    private static function literalConfigReads(array $tokens): array
    {
        $reads = [];
        [$facades, $repositoryVariables] = self::configSymbols($tokens);

        foreach ($tokens as $index => $token) {
            if (! is_array($token)) {
                continue;
            }

            $isConfig = ($token[0] === T_STRING && strtolower($token[1]) === 'config')
                || ($token[0] === T_NAME_FULLY_QUALIFIED && strtolower($token[1]) === '\\config');

            if ($isConfig && ! self::isMethodCall($tokens, $index)) {
                $open = self::nextSignificant($tokens, $index + 1);
                $argument = $open === null ? null : self::nextSignificant($tokens, $open + 1);

                if ($open !== null && $tokens[$open] === '(' && $argument !== null) {
                    $key = $tokens[$argument] === ')'
                        ? self::chainedGetLiteral($tokens, $argument)
                        : self::literalArgument($tokens, $argument);

                    if ($key !== null) {
                        $reads[] = $key;
                    }
                }
            }

            if (self::isConfigFacade($token, $facades)) {
                $key = self::staticGetLiteral($tokens, $index);

                if ($key !== null) {
                    $reads[] = $key;
                }
            }

            if ($token[0] === T_VARIABLE && in_array($token[1], $repositoryVariables, true)) {
                $key = self::objectGetLiteral($tokens, $index);

                if ($key !== null) {
                    $reads[] = $key;
                }
            }

            if ($token[0] === T_VARIABLE && $token[1] === '$this') {
                $key = self::repositoryPropertyGetLiteral($tokens, $index, $repositoryVariables);

                if ($key !== null) {
                    $reads[] = $key;
                }
            }
        }

        return $reads;
    }

    /**
     * @param  list<array{int, string, int}|string>  $tokens
     * @return array{list<string>, list<string>}
     */
    private static function configSymbols(array $tokens): array
    {
        $facades = [];
        $repositories = [];

        foreach ($tokens as $index => $token) {
            if (! is_array($token) || $token[0] !== T_USE) {
                continue;
            }

            $statement = '';

            for ($cursor = $index + 1, $count = count($tokens); $cursor < $count && $tokens[$cursor] !== ';'; $cursor++) {
                $statement .= is_array($tokens[$cursor]) ? $tokens[$cursor][1] : $tokens[$cursor];
            }

            $statement = trim($statement);

            array_push($facades, ...self::importedAliases($statement, 'Illuminate\\Support\\Facades\\Config'));
            array_push($repositories, ...self::importedAliases($statement, 'Illuminate\\Contracts\\Config\\Repository'));
        }

        $repositoryVariables = [];

        foreach ($tokens as $index => $token) {
            if (! is_array($token) || $token[0] !== T_VARIABLE) {
                continue;
            }

            $typeIndex = self::previousSignificant($tokens, $index - 1);
            $type = $typeIndex === null ? null : $tokens[$typeIndex];

            if (is_array($type)
                && (($type[0] === T_STRING && in_array($type[1], $repositories, true))
                    || (in_array($type[0], [T_NAME_QUALIFIED, T_NAME_FULLY_QUALIFIED], true)
                        && ltrim(strtolower($type[1]), '\\') === 'illuminate\\contracts\\config\\repository'))) {
                $repositoryVariables[] = $token[1];
            }
        }

        return [array_values(array_unique($facades)), array_values(array_unique($repositoryVariables))];
    }

    /** @return list<string> */
    private static function importedAliases(string $statement, string $class): array
    {
        foreach (self::expandedImports($statement) as $import) {
            $pattern = '/^\\\\?'.preg_quote($class, '/').'(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?$/i';

            if (preg_match($pattern, $import, $match) === 1) {
                return [$match[1] ?? self::shortName($class)];
            }
        }

        return [];
    }

    /** @return list<string> */
    private static function expandedImports(string $statement): array
    {
        $imports = [];

        foreach (self::topLevelUseItems($statement) as $item) {
            $open = strpos($item, '{');

            if ($open === false) {
                $imports[] = trim($item);

                continue;
            }

            $close = strrpos($item, '}');

            if ($close === false) {
                continue;
            }

            $prefix = rtrim(trim(substr($item, 0, $open)), '\\').'\\';

            foreach (self::topLevelUseItems(substr($item, $open + 1, $close - $open - 1)) as $member) {
                $imports[] = $prefix.trim($member);
            }
        }

        return $imports;
    }

    /** @return list<string> */
    private static function topLevelUseItems(string $statement): array
    {
        $items = [];
        $item = '';
        $depth = 0;

        foreach (str_split($statement) as $character) {
            if ($character === '{') {
                $depth++;
            } elseif ($character === '}') {
                $depth--;
            }

            if ($character === ',' && $depth === 0) {
                $items[] = $item;
                $item = '';

                continue;
            }

            $item .= $character;
        }

        $items[] = $item;

        return $items;
    }

    private static function shortName(string $class): string
    {
        $separator = strrpos($class, '\\');

        return $separator === false ? $class : substr($class, $separator + 1);
    }

    /**
     * @param  array{int, string, int}  $token
     * @param  list<string>  $facades
     */
    private static function isConfigFacade(array $token, array $facades): bool
    {
        if ($token[0] === T_STRING) {
            return in_array($token[1], $facades, true);
        }

        return in_array($token[0], [T_NAME_QUALIFIED, T_NAME_FULLY_QUALIFIED], true)
            && ltrim(strtolower($token[1]), '\\') === 'illuminate\\support\\facades\\config';
    }

    /** @param list<array{int, string, int}|string> $tokens */
    private static function staticGetLiteral(array $tokens, int $index): ?string
    {
        $operator = self::nextSignificant($tokens, $index + 1);

        if ($operator === null || ! is_array($tokens[$operator]) || $tokens[$operator][0] !== T_DOUBLE_COLON) {
            return null;
        }

        return self::getLiteralAfterOperator($tokens, $operator);
    }

    /** @param list<array{int, string, int}|string> $tokens */
    private static function objectGetLiteral(array $tokens, int $index): ?string
    {
        $operator = self::nextSignificant($tokens, $index + 1);

        if ($operator === null || ! is_array($tokens[$operator]) || $tokens[$operator][0] !== T_OBJECT_OPERATOR) {
            return null;
        }

        return self::getLiteralAfterOperator($tokens, $operator);
    }

    /**
     * @param  list<array{int, string, int}|string>  $tokens
     * @param  list<string>  $repositoryVariables
     */
    private static function repositoryPropertyGetLiteral(array $tokens, int $index, array $repositoryVariables): ?string
    {
        $propertyOperator = self::nextSignificant($tokens, $index + 1);
        $property = $propertyOperator === null ? null : self::nextSignificant($tokens, $propertyOperator + 1);
        $getOperator = $property === null ? null : self::nextSignificant($tokens, $property + 1);

        if ($propertyOperator === null || ! is_array($tokens[$propertyOperator])
            || $tokens[$propertyOperator][0] !== T_OBJECT_OPERATOR || $property === null
            || ! is_array($tokens[$property]) || $tokens[$property][0] !== T_STRING
            || ! in_array('$'.$tokens[$property][1], $repositoryVariables, true)
            || $getOperator === null || ! is_array($tokens[$getOperator])
            || $tokens[$getOperator][0] !== T_OBJECT_OPERATOR) {
            return null;
        }

        return self::getLiteralAfterOperator($tokens, $getOperator);
    }

    /** @param list<array{int, string, int}|string> $tokens */
    private static function chainedGetLiteral(array $tokens, int $closeParenthesis): ?string
    {
        $operator = self::nextSignificant($tokens, $closeParenthesis + 1);

        if ($operator === null || ! is_array($tokens[$operator]) || $tokens[$operator][0] !== T_OBJECT_OPERATOR) {
            return null;
        }

        return self::getLiteralAfterOperator($tokens, $operator);
    }

    /** @param list<array{int, string, int}|string> $tokens */
    private static function getLiteralAfterOperator(array $tokens, int $operator): ?string
    {
        $method = self::nextSignificant($tokens, $operator + 1);
        $open = $method === null ? null : self::nextSignificant($tokens, $method + 1);
        $argument = $open === null ? null : self::nextSignificant($tokens, $open + 1);

        if ($method === null || ! is_array($tokens[$method]) || $tokens[$method][0] !== T_STRING
            || ! in_array(strtolower($tokens[$method][1]), ['get', 'string', 'integer', 'float', 'boolean', 'array'], true)
            || $open === null || $tokens[$open] !== '('
            || $argument === null) {
            return null;
        }

        return self::literalArgument($tokens, $argument);
    }

    /** @param list<array{int, string, int}|string> $tokens */
    private static function literalArgument(array $tokens, int $argument): ?string
    {
        $literal = $tokens[$argument];

        if (! is_array($literal) || $literal[0] !== T_CONSTANT_ENCAPSED_STRING) {
            return null;
        }

        $after = self::nextSignificant($tokens, $argument + 1);

        if ($after === null || ! in_array($tokens[$after], [')', ','], true)) {
            return null;
        }

        return self::decodeLiteral($literal[1]);
    }

    /** @param list<array{int, string, int}|string> $tokens */
    private static function isMethodCall(array $tokens, int $index): bool
    {
        $previous = self::previousSignificant($tokens, $index - 1);

        if ($previous === null) {
            return false;
        }

        $token = $tokens[$previous];

        return is_array($token) && in_array($token[0], [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION], true);
    }

    private static function decodeLiteral(string $literal): string
    {
        $quote = $literal[0];
        $value = substr($literal, 1, -1);

        return $quote === "'"
            ? str_replace(['\\\\', "\\'"], ['\\', "'"], $value)
            : stripcslashes($value);
    }

    /**
     * @param  list<array{int, string, int}|string>  $tokens
     */
    private static function consumer(array $tokens): ?string
    {
        $namespace = '';
        $class = null;

        foreach ($tokens as $index => $token) {
            if (! is_array($token)) {
                continue;
            }

            if ($token[0] === T_NAMESPACE) {
                $namespace = self::nameAfter($tokens, $index + 1);
            }

            if (in_array($token[0], [T_CLASS, T_ENUM, T_INTERFACE, T_TRAIT], true)
                && ! self::precededByDoubleColon($tokens, $index)) {
                $class = self::nameAfter($tokens, $index + 1);
                break;
            }
        }

        if ($class === null || $class === '') {
            return null;
        }

        return $namespace === '' ? $class : $namespace.'\\'.$class;
    }

    /** @param list<array{int, string, int}|string> $tokens */
    private static function precededByDoubleColon(array $tokens, int $index): bool
    {
        $previous = self::previousSignificant($tokens, $index - 1);

        return $previous !== null && is_array($tokens[$previous]) && $tokens[$previous][0] === T_DOUBLE_COLON;
    }

    /** @param list<array{int, string, int}|string> $tokens */
    private static function nameAfter(array $tokens, int $start): string
    {
        $name = '';

        for ($index = $start, $count = count($tokens); $index < $count; $index++) {
            $token = $tokens[$index];

            if (is_array($token) && in_array($token[0], [T_WHITESPACE, T_NAME_QUALIFIED, T_STRING, T_NS_SEPARATOR], true)) {
                if ($token[0] !== T_WHITESPACE) {
                    $name .= $token[1];
                }

                continue;
            }

            break;
        }

        return $name;
    }

    /** @param list<array{int, string, int}|string> $tokens */
    private static function nextSignificant(array $tokens, int $start): ?int
    {
        for ($index = $start, $count = count($tokens); $index < $count; $index++) {
            if (! self::trivia($tokens[$index])) {
                return $index;
            }
        }

        return null;
    }

    /** @param list<array{int, string, int}|string> $tokens */
    private static function previousSignificant(array $tokens, int $start): ?int
    {
        for ($index = $start; $index >= 0; $index--) {
            if (! self::trivia($tokens[$index])) {
                return $index;
            }
        }

        return null;
    }

    /** @param array{int, string, int}|string $token */
    private static function trivia(array|string $token): bool
    {
        return is_array($token) && in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true);
    }

    /**
     * @return iterable<string, SplFileInfo>
     */
    private static function phpFiles(string $root): iterable
    {
        $files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
        );

        /** @var SplFileInfo $file */
        foreach ($files as $file) {
            if ($file->isFile() && $file->getExtension() === 'php') {
                yield substr($file->getPathname(), strlen($root) + 1) => $file;
            }
        }
    }
}
