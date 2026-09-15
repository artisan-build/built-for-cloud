<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Support;

use RuntimeException;

/** Minimal raw loopback client that preserves duplicate fields and cookies. */
final class P6HttpClient
{
    /** @var array<string, string> */
    private array $cookies = [];

    /**
     * @param  list<array{0: string, 1: string}>  $headers
     * @return array{status: int, headers: array<string, list<string>>, body: string}
     */
    public function request(int $port, string $method, string $path, array $headers = [], string $body = ''): array
    {
        $socket = @stream_socket_client('tcp://127.0.0.1:'.$port, $errorNumber, $error, 0.4);
        if (! is_resource($socket)) {
            throw new RuntimeException('Could not connect to the bounded P6c loopback listener.');
        }

        stream_set_timeout($socket, 5);
        $request = strtoupper($method)." {$path} HTTP/1.1\r\n"
            ."Host: 127.0.0.1:{$port}\r\n"
            ."Accept: application/json\r\n"
            ."Connection: close\r\n";

        if ($this->cookies !== []) {
            $pairs = [];
            foreach ($this->cookies as $name => $value) {
                $pairs[] = $name.'='.$value;
            }
            $request .= 'Cookie: '.implode('; ', $pairs)."\r\n";
        }

        foreach ($headers as [$name, $value]) {
            $request .= "{$name}: {$value}\r\n";
        }

        $request .= 'Content-Length: '.strlen($body)."\r\n\r\n{$body}";
        $written = 0;
        while ($written < strlen($request)) {
            $bytes = fwrite($socket, substr($request, $written));
            if ($bytes === false || $bytes === 0) {
                fclose($socket);
                throw new RuntimeException('The P6c loopback request could not be written completely.');
            }
            $written += $bytes;
        }

        $raw = '';
        while (! feof($socket)) {
            $chunk = fread($socket, 8192);
            if ($chunk === false) {
                fclose($socket);
                throw new RuntimeException('The P6c loopback response could not be read.');
            }
            $raw .= $chunk;
            if ((stream_get_meta_data($socket)['timed_out'] ?? false) === true) {
                fclose($socket);
                throw new RuntimeException('The P6c loopback response exceeded its read deadline.');
            }
        }
        fclose($socket);

        [$head, $responseBody] = array_pad(explode("\r\n\r\n", $raw, 2), 2, '');
        $lines = explode("\r\n", $head);
        $statusLine = array_shift($lines);
        if (! is_string($statusLine) || preg_match('/^HTTP\/\S+ ([0-9]{3})(?: |$)/', $statusLine, $matches) !== 1) {
            throw new RuntimeException('The P6c loopback response had no valid HTTP status line.');
        }

        $responseHeaders = [];
        foreach ($lines as $line) {
            if (! str_contains($line, ':')) {
                continue;
            }
            [$name, $value] = explode(':', $line, 2);
            $name = strtolower($name);
            $value = trim($value);
            $responseHeaders[$name][] = $value;

            if ($name === 'set-cookie') {
                $pair = explode(';', $value, 2)[0];
                [$cookieName, $cookieValue] = array_pad(explode('=', $pair, 2), 2, '');
                if ($cookieValue === '' || str_contains(strtolower($value), 'max-age=0')) {
                    unset($this->cookies[$cookieName]);
                } else {
                    $this->cookies[$cookieName] = $cookieValue;
                }
            }
        }

        return ['status' => (int) $matches[1], 'headers' => $responseHeaders, 'body' => $responseBody];
    }

    /** @return array<string, string> */
    public function cookies(): array
    {
        return $this->cookies;
    }
}
