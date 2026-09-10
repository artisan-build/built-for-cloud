<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\StandaloneAccess;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Cookie\CookieValuePrefix;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\DB;

require __DIR__.'/../../vendor/autoload.php';

$app = require __DIR__.'/../../vendor/orchestra/testbench-core/laravel/bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();

$email = $argv[1] ?? '';
$user = User::query()->where('email', $email)->sole();
$rows = DB::table('sessions')->where('user_id', $user->getKey())->get(['id', 'payload']);
$keys = [];
$authMatches = 0;
$versionMatches = 0;
$marked = $rows->filter(static function (object $row) use (&$keys, &$authMatches, &$versionMatches, $user): bool {
    $decoded = base64_decode((string) $row->payload, true);
    $payload = is_string($decoded) ? @unserialize($decoded, ['allowed_classes' => false]) : null;

    if (is_array($payload)) {
        $keys = array_values(array_unique([...$keys, ...array_keys($payload)]));
        $authKey = null;

        foreach (array_keys($payload) as $key) {
            if (str_starts_with($key, 'login_web_')) {
                $authKey = $key;
                break;
            }
        }

        if (is_string($authKey) && (string) $payload[$authKey] === (string) $user->getKey()) {
            $authMatches++;
        }

        if ((int) Arr::get($payload, StandaloneAccess::SESSION_VERSION_KEY) === $user->auth_session_version) {
            $versionMatches++;
        }
    }

    return is_array($payload) && Arr::has($payload, StandaloneAccess::SESSION_VERSION_KEY);
})->count();

$cookieMatch = 'unchecked';
$cookieFile = $argv[2] ?? null;

if (is_string($cookieFile) && is_file($cookieFile)) {
    $cookieName = (string) config('session.cookie');
    $cookieValue = null;

    foreach (file($cookieFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
        if (str_starts_with($line, '#') && ! str_starts_with($line, '#HttpOnly_')) {
            continue;
        }

        $fields = explode("\t", $line);

        if (($fields[5] ?? null) === $cookieName) {
            $cookieValue = rawurldecode((string) ($fields[6] ?? ''));
        }
    }

    try {
        $encrypter = app('encrypter');
        $decrypted = is_string($cookieValue) ? $encrypter->decrypt($cookieValue, false) : null;
        $sessionId = is_string($decrypted)
            ? CookieValuePrefix::validate($cookieName, $decrypted, [$encrypter->getKey(), ...$encrypter->getPreviousKeys()])
            : null;
        $cookieMatch = is_string($sessionId) && $rows->contains('id', $sessionId) ? 'yes' : 'no';
    } catch (Throwable) {
        $cookieMatch = 'decrypt-failed';
    }
}

fwrite(STDOUT, 'sessions='.$rows->count().' marked='.$marked.' version_match='.$versionMatches.' auth_match='.$authMatches.' cookie_match='.$cookieMatch.' keys='.implode(',', $keys).PHP_EOL);
