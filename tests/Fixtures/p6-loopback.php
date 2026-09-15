<?php

declare(strict_types=1);

header('Content-Type: application/json');
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);

if ($path === '/duplicate') {
    http_response_code(207);
    echo json_encode(['duplicate' => $_SERVER['HTTP_X_BFC_DUPLICATE'] ?? null], JSON_THROW_ON_ERROR);

    return;
}

if ($path === '/cookies') {
    echo json_encode(['cookie' => $_SERVER['HTTP_COOKIE'] ?? ''], JSON_THROW_ON_ERROR);

    return;
}

if ($path === '/set-cookie') {
    header('Set-Cookie: p6_one=first; Path=/');
    header('Set-Cookie: p6_two=second; Path=/', false);
} elseif ($path === '/clear-cookie') {
    header('Set-Cookie: p6_one=; Max-Age=0; Path=/');
}

echo '{"ready":true}';
