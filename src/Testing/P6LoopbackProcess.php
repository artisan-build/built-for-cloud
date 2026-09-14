<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use RuntimeException;
use Symfony\Component\Process\Process;

/** One bounded, PID-and-port-checked loopback listener. */
final class P6LoopbackProcess
{
    /** @param list<string> $command */
    private function __construct(
        private readonly Process $process,
        public readonly int $port,
        private readonly array $command,
    ) {}

    /** @param list<string> $command
     * @param  array<string, string>  $environment
     */
    public static function start(array $command, string $workingDirectory, array $environment, callable $ready): self
    {
        $port = self::allocatePort();
        $command = array_map(static fn (string $part): string => str_replace('{port}', (string) $port, $part), $command);
        $process = new Process($command, $workingDirectory, $environment);
        $process->setTimeout(null);
        $process->start();
        $listener = new self($process, $port, $command);

        try {
            BoundedWait::until(function () use ($listener, $ready): mixed {
                if (! $listener->process->isRunning()) {
                    throw new RuntimeException('The P6c loopback listener exited before readiness.');
                }

                return $ready($listener->port);
            }, 15, 'The P6c loopback listener did not become ready before its deadline.');
            $listener->identity();
        } catch (\Throwable $exception) {
            $listener->process->stop(1, SIGTERM);

            throw $exception;
        }

        return $listener;
    }

    /** @return array{pid: int, port: int, address: string, identity_verified: true} */
    public function identity(): array
    {
        $pid = $this->process->getPid();
        if (! is_int($pid) || ! $this->process->isRunning()) {
            throw new RuntimeException('The P6c loopback listener has no running process identity.');
        }

        $lsof = is_executable('/usr/sbin/lsof') ? '/usr/sbin/lsof' : '/usr/bin/lsof';
        if (! is_executable($lsof)) {
            throw new RuntimeException('The P6c listener identity check requires lsof.');
        }

        $identity = new Process([
            $lsof, '-nP', '-a', '-p', (string) $pid, '-iTCP:'.$this->port, '-sTCP:LISTEN', '-Fpn',
        ]);
        if ($identity->run() !== 0
            || ! str_contains($identity->getOutput(), "p{$pid}\n")
            || ! str_contains($identity->getOutput(), ':'.$this->port)) {
            throw new RuntimeException('The P6c listener PID and port identity did not match.');
        }

        return [
            'pid' => $pid,
            'port' => $this->port,
            'address' => '127.0.0.1:'.$this->port,
            'identity_verified' => true,
        ];
    }

    public function stop(): bool
    {
        if ($this->process->isRunning()) {
            $this->process->stop(3, SIGTERM);
        }

        return BoundedWait::until(
            fn (): bool => ! self::portIsBound($this->port),
            5,
            'The P6c loopback listener remained after bounded teardown.',
        );
    }

    /** @return list<string> */
    public function command(): array
    {
        return $this->command;
    }

    public function output(): string
    {
        return $this->process->getOutput().$this->process->getErrorOutput();
    }

    private static function allocatePort(): int
    {
        $socket = stream_socket_server('tcp://127.0.0.1:0', $errorNumber, $error);
        if (! is_resource($socket)) {
            throw new RuntimeException('The OS could not allocate a P6c loopback port.');
        }

        $address = stream_socket_get_name($socket, false);
        fclose($socket);
        $port = is_string($address) ? parse_url('tcp://'.$address, PHP_URL_PORT) : false;

        return is_int($port)
            ? $port
            : throw new RuntimeException('The OS-allocated P6c loopback port could not be read.');
    }

    private static function portIsBound(int $port): bool
    {
        $socket = @stream_socket_client('tcp://127.0.0.1:'.$port, $errorNumber, $error, 0.1);
        if (! is_resource($socket)) {
            return false;
        }

        fclose($socket);

        return true;
    }
}
