<?php

declare(strict_types=1);

/**
 * A second process whose only job is to RETARGET one credential row and
 * commit, blocking for as long as somebody else holds that row's lock.
 *
 * It exists because a blocking write cannot be issued from the process
 * that is running the transaction it has to queue behind. Plain PDO, no
 * framework: the point is one UPDATE whose lock-queue position is known.
 *
 * Input (STDIN, JSON): id, column, value, application_name.
 * Output (STDOUT, JSON): committed=true, plus the microsecond timestamps
 * either side of the UPDATE so a caller can see it really did wait.
 */
$input = json_decode((string) stream_get_contents(STDIN), true, flags: JSON_THROW_ON_ERROR);

if (! is_array($input)) {
    fwrite(STDERR, "Invalid retarget worker input.\n");
    exit(2);
}

$environment = static fn (string $name, string $default): string => (($value = getenv($name)) === false ? $default : $value);

$column = (string) $input['column'];

if (preg_match('/^[a-z_]+$/', $column) !== 1) {
    fwrite(STDERR, "Refusing a column name that is not a plain identifier.\n");
    exit(2);
}

try {
    $pdo = new PDO(
        sprintf(
            'pgsql:host=%s;port=%s;dbname=%s;sslmode=%s',
            $environment('PGSQL_TESTING_HOST', '127.0.0.1'),
            $environment('PGSQL_TESTING_PORT', '5432'),
            $environment('PGSQL_TESTING_DATABASE', ''),
            $environment('PGSQL_TESTING_SSLMODE', 'prefer'),
        ),
        $environment('PGSQL_TESTING_USERNAME', 'postgres'),
        $environment('PGSQL_TESTING_PASSWORD', 'postgres'),
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION],
    );

    $pdo->exec("set application_name = '".(string) $input['application_name']."'");
    $pdo->beginTransaction();

    $startedAt = microtime(true);
    $statement = $pdo->prepare(sprintf('update credentials set %s = :value where id = :id', $column));
    $statement->execute(['value' => (string) $input['value'], 'id' => (string) $input['id']]);
    $acquiredAt = microtime(true);

    $pdo->commit();

    fwrite(STDOUT, json_encode([
        'committed' => true,
        'rows' => $statement->rowCount(),
        'waited_seconds' => $acquiredAt - $startedAt,
    ], JSON_THROW_ON_ERROR));
} catch (Throwable $exception) {
    fwrite(STDERR, $exception::class.': '.$exception->getMessage()."\n");
    exit(1);
}
