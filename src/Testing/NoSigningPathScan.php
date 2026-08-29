<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 * The executable half of the Console's key-custody guarantee (Console
 * PRD D12): this package holds only PUBLIC halves and NOTHING in it
 * signs, so stealing an app's whole database yields no ability to mint
 * an assertion for any deployment.
 *
 * That guarantee is a claim about ABSENCE, which nothing enforces on its
 * own — a later change adds one signing call and every docblock quietly
 * becomes false. This scanner is what makes the absence checkable, and
 * it ships in `src/Testing` rather than in the test suite so a CONSUMING
 * app can point it at its own tree and hold the same line.
 *
 * The one allowed exception,
 * `sodium_crypto_sign_ed25519_pk_to_curve25519()`, converts a public
 * signing key to a public encryption key and signs nothing. It is
 * matched EXACTLY: a name that merely starts the same way — the
 * `sk_to_curve25519` variant, which takes a SECRET key — is an offence.
 *
 * NOTE ON THIS FILE'S OWN TEXT: the paseto secret-key class name is
 * assembled from two halves below, and never written whole anywhere in
 * this file, so the scanner is not excluded from its own walk. An
 * exclusion is what would let a signing call hide in the one file
 * nobody scans; a split literal costs nothing and keeps the file
 * inside the net with everything else.
 */
final class NoSigningPathScan
{
    /** The public-key conversion, and the only permitted sodium sign-family call. */
    public const string ALLOWED_CALL = 'sodium_crypto_sign_ed25519_pk_to_curve25519(';

    /**
     * Paseto's signing-key class. Split so this file does not contain
     * the name it is looking for — see the class docblock.
     */
    public const string SECRET_KEY_CLASS = 'Asymmetric'.'SecretKey';

    /**
     * Every offence in one file's contents, in the order they appear.
     *
     * @return list<string>
     */
    public static function offencesIn(string $contents): array
    {
        $offences = [];

        if (str_contains($contents, self::SECRET_KEY_CLASS)) {
            $offences[] = self::SECRET_KEY_CLASS;
        }

        preg_match_all('/sodium_crypto_sign\w*\s*\(/', $contents, $matches);

        foreach ($matches[0] as $call) {
            $normalized = (string) preg_replace('/\s+/', '', $call);

            if ($normalized !== self::ALLOWED_CALL) {
                $offences[] = $normalized;
            }
        }

        return $offences;
    }

    /**
     * Walk a tree and collect every offending PHP file, keyed by its
     * path relative to the root.
     *
     * @return array<string, list<string>>
     */
    public static function scan(string $root): array
    {
        $offenders = [];

        foreach (self::phpFiles($root) as $relativePath => $file) {
            $offences = self::offencesIn((string) file_get_contents($file->getPathname()));

            if ($offences !== []) {
                $offenders[$relativePath] = $offences;
            }
        }

        ksort($offenders);

        return $offenders;
    }

    /**
     * How many PHP files the walk actually visited — the floor that
     * stops a scanner which enumerated nothing from reporting "clean".
     */
    public static function countPhpFiles(string $root): int
    {
        return count(iterator_to_array(self::phpFiles($root)));
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
