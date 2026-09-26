<?php

declare(strict_types=1);

/*
 * Compiles resources/css/bfc.css into the committed resources/dist/bfc.css
 * with Tailwind's standalone CLI: no Node, no npm, no Vite, like the rest of
 * the fleet. The binary is downloaded once into .tools/ (gitignored); point
 * TAILWIND_BINARY at an existing one to skip the download.
 */

$root = dirname(__DIR__);
$version = 'v4.3.0';
$binary = getenv('TAILWIND_BINARY') ?: "{$root}/.tools/tailwindcss/{$version}/tailwindcss";

if (! is_file($binary)) {
    $machine = strtolower(php_uname('m'));
    $arm = in_array($machine, ['arm64', 'aarch64'], true);
    $asset = match (PHP_OS_FAMILY) {
        'Darwin' => $arm ? 'tailwindcss-macos-arm64' : 'tailwindcss-macos-x64',
        'Linux' => $arm ? 'tailwindcss-linux-arm64' : 'tailwindcss-linux-x64',
        default => null,
    };

    if ($asset === null) {
        fwrite(STDERR, 'Unsupported OS for the Tailwind standalone CLI; set TAILWIND_BINARY.'.PHP_EOL);
        exit(1);
    }

    $url = "https://github.com/tailwindlabs/tailwindcss/releases/download/{$version}/{$asset}";
    fwrite(STDOUT, "Downloading Tailwind CSS {$version}...".PHP_EOL);
    $contents = @file_get_contents($url, false, stream_context_create(['http' => ['header' => "User-Agent: built-for-cloud\r\n", 'timeout' => 60]]));

    if ($contents === false) {
        fwrite(STDERR, "Unable to download {$url}".PHP_EOL);
        exit(1);
    }

    @mkdir(dirname($binary), 0755, true);
    file_put_contents($binary, $contents);
    chmod($binary, 0755);
}

$command = [$binary, '-i', "{$root}/resources/css/bfc.css", '-o', "{$root}/resources/dist/bfc.css", '--minify'];
passthru(implode(' ', array_map('escapeshellarg', $command)), $exitCode);

exit($exitCode);
