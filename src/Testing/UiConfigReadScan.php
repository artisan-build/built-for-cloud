<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use RuntimeException;
use SplFileInfo;

/**
 * Derives every direct literal `config('built-for-cloud.ui.*')` read in a
 * PHP source tree. P5-AC13 compares those identities with its reviewed
 * visibility-only set, so an added enforcement consumer is unexpected.
 *
 * This scanner sees `config()` and `\config()` calls whose first argument is
 * one literal string. It deliberately does not claim data-flow analysis: it
 * cannot see dynamic/concatenated keys, Config facade calls, injected config
 * repositories, wrappers, aliases, reflection, Blade/resources, host code or
 * generated caches. The positive-control enforcement fixture proves the
 * direct-call class this instrument claims; review remains responsible for
 * newly introduced indirection.
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

        foreach ($tokens as $index => $token) {
            $isConfig = is_array($token)
                && (($token[0] === T_STRING && strtolower($token[1]) === 'config')
                    || ($token[0] === T_NAME_FULLY_QUALIFIED && strtolower($token[1]) === '\\config'));

            if (! $isConfig || self::isMethodCall($tokens, $index)) {
                continue;
            }

            $open = self::nextSignificant($tokens, $index + 1);
            $argument = $open === null ? null : self::nextSignificant($tokens, $open + 1);

            if ($open === null || $tokens[$open] !== '(' || $argument === null) {
                continue;
            }

            $literal = $tokens[$argument];

            if (is_array($literal) && $literal[0] === T_CONSTANT_ENCAPSED_STRING) {
                $reads[] = self::decodeLiteral($literal[1]);
            }
        }

        return $reads;
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
