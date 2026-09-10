#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/bfc-managed-harness.XXXXXX")"
DB="${RUN_DIR}/database.sqlite"
CERT="${RUN_DIR}/authority.crt"
STATUS="${RUN_DIR}/authority-status.json"
SERVER_LOG="/dev/null"
AUTHORITY_LOG="${RUN_DIR}/authority.log"
STAMP="bfc-managed-live-$(date -u +%Y%m%dT%H%M%SZ)-$$"
APP_PORT="$(php -r '$socket = stream_socket_server("tcp://127.0.0.1:0", $errno, $error); if ($socket === false) { exit(1); } echo parse_url(stream_socket_get_name($socket, false), PHP_URL_PORT);')"
AUTHORITY_PORT="$(php -r '$socket = stream_socket_server("tcp://127.0.0.1:0", $errno, $error); if ($socket === false) { exit(1); } echo parse_url(stream_socket_get_name($socket, false), PHP_URL_PORT);')"
APP_BASE="http://127.0.0.1:${APP_PORT}"
AUTHORITY_BASE="https://127.0.0.1:${AUTHORITY_PORT}"
CLIENT_SECRET="$(php -r 'echo bin2hex(random_bytes(32));')"
CLIENT_APP_KEY="$(php -r 'echo "base64:".base64_encode(random_bytes(32));')"
AUTHORITY_APP_KEY="$(php -r 'echo "base64:".base64_encode(random_bytes(32));')"

fail() {
    printf 'managed harness failure: %s (run directory: %s)\n' "$1" "${RUN_DIR}" >&2
    if [[ -s "${AUTHORITY_LOG}" ]]; then
        perl -ne 'print' "${AUTHORITY_LOG}" >&2
    fi
    if [[ -s "${SERVER_LOG}" ]]; then
        perl -ne 'print' "${SERVER_LOG}" >&2
    fi
    exit 1
}

status_of() {
    printf '%s' "$1" | perl -ne 'if (/^HTTP\/\S+ (\d+)/) { print $1; exit }'
}

header_of() {
    local name="$1"
    printf '%s' "$2" | perl -ne 'BEGIN { $name = lc($ARGV[0]); shift @ARGV } if (/^([^:]+):\s*(.*?)\r?$/ && lc($1) eq $name) { print $2; exit }' "${name}"
}

cookie_of() {
    printf '%s' "$1" | perl -ne 'if (/^Set-Cookie:\s*(laravel_session=[^;]+)/i) { print $1; exit }'
}

cleanup() {
    if [[ -n "${SERVER_PID:-}" ]]; then
        kill "${SERVER_PID}" 2>/dev/null || true
        wait "${SERVER_PID}" 2>/dev/null || true
    fi
    if [[ -n "${AUTHORITY_PID:-}" ]]; then
        kill "${AUTHORITY_PID}" 2>/dev/null || true
        wait "${AUTHORITY_PID}" 2>/dev/null || true
    fi
    rm -rf "${RUN_DIR}"
}
trap cleanup EXIT

touch "${DB}"
cd "${ROOT}"
BFC_MANAGED_FIXTURE_CLIENT_SECRET="${CLIENT_SECRET}" \
BFC_MANAGED_FIXTURE_APP_KEY="${AUTHORITY_APP_KEY}" \
BFC_MANAGED_CLIENT_APP_KEY="${CLIENT_APP_KEY}" \
php tests/Live/managed-authority.php "${AUTHORITY_PORT}" "${CERT}" "${APP_BASE}" "${STATUS}" >"${AUTHORITY_LOG}" 2>&1 &
AUTHORITY_PID=$!

for _ in {1..100}; do
    if [[ -s "${CERT}" ]] && curl --silent --show-error --cacert "${CERT}" "${AUTHORITY_BASE}/not-ready" >/dev/null; then
        break
    fi
    if ! kill -0 "${AUTHORITY_PID}" 2>/dev/null; then
        fail "authority exited before readiness"
    fi
    sleep 0.05
done
[[ -s "${CERT}" ]] || fail "authority certificate was not produced"

HARNESS_ENV=(
    env -i
    "HOME=${HOME}"
    "PATH=${PATH}"
    "APP_ENV=testing"
    "APP_KEY=${CLIENT_APP_KEY}"
    "APP_URL=${APP_BASE}"
    "DB_CONNECTION=sqlite"
    "DB_DATABASE=${DB}"
    "SESSION_DRIVER=database"
    "CACHE_STORE=array"
    "MAIL_MAILER=array"
    "BUILT_FOR_CLOUD_SURFACE_DATA_MIGRATIONS=false"
    "BUILT_FOR_CLOUD_MANAGED_CLIENT_SECRET=${CLIENT_SECRET}"
    "BUILT_FOR_CLOUD_MANAGED_CA_BUNDLE=${CERT}"
    "BFC_MANAGED_AUTHORITY_BASE_URL=${AUTHORITY_BASE}"
)
"${HARNESS_ENV[@]}" vendor/bin/testbench migrate:fresh --force --no-interaction >"${RUN_DIR}/migrate.log"
"${HARNESS_ENV[@]}" php tests/Live/seed-managed-harness.php
"${HARNESS_ENV[@]}" vendor/bin/testbench serve --host=127.0.0.1 --port="${APP_PORT}" >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!

for _ in {1..100}; do
    READY_STATUS="$(curl --silent --output /dev/null --write-out '%{http_code}' "${APP_BASE}/bfc/login" || true)"
    if [[ "${READY_STATUS}" == 404 ]]; then
        break
    fi
    if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
        fail "application exited before readiness"
    fi
    sleep 0.05
done
[[ "${READY_STATUS}" == 404 ]] || fail "application did not become ready in managed mode"

ENTRY_HEADERS="$(curl --silent --show-error --dump-header - --output /dev/null "${APP_BASE}/bfc/managed/login")"
[[ "$(status_of "${ENTRY_HEADERS}")" == 302 ]] || fail "managed entry did not redirect"
AUTHORIZATION_URL="$(header_of Location "${ENTRY_HEADERS}")"
COOKIE="$(cookie_of "${ENTRY_HEADERS}")"
[[ -n "${AUTHORIZATION_URL}" && -n "${COOKIE}" ]] || fail "managed entry omitted redirect or session cookie"
[[ "${AUTHORIZATION_URL%%\?*}" == "${AUTHORITY_BASE}/managed-auth/v1/authorize" ]] || fail "managed entry returned an unexpected authority origin or path"

AUTH_HEADERS="$(curl --silent --show-error --cacert "${CERT}" --dump-header - --output /dev/null "${AUTHORIZATION_URL}")"
[[ "$(status_of "${AUTH_HEADERS}")" == 302 ]] || fail "fixture authorization did not redirect"
CALLBACK_URL="$(header_of Location "${AUTH_HEADERS}")"
[[ "${CALLBACK_URL%%\?*}" == "${APP_BASE}/bfc/managed/callback" ]] || fail "fixture returned an unexpected callback"
CALLBACK_HEADERS="$(curl --silent --show-error --header "Cookie: ${COOKIE}" --dump-header - --output /dev/null "${CALLBACK_URL}")"
CALLBACK_STATUS="$(status_of "${CALLBACK_HEADERS}")"
[[ "${CALLBACK_STATUS}" == 302 ]] || fail "managed callback did not establish a session; status ${CALLBACK_STATUS}"
ROTATED_COOKIE="$(cookie_of "${CALLBACK_HEADERS}")"
[[ -n "${ROTATED_COOKIE}" ]] || fail "managed callback did not rotate the session cookie"
DOMAIN_STATUS="$(curl --silent --show-error --header "Cookie: ${ROTATED_COOKIE}" --output /dev/null --write-out '%{http_code}' "${APP_BASE}/domain")"
[[ "${DOMAIN_STATUS}" == 200 ]] || fail "managed session did not reach a protected route"

SECOND_HEADERS="$(curl --silent --show-error --dump-header - --output /dev/null "${APP_BASE}/bfc/managed/login")"
SECOND_URL="$(header_of Location "${SECOND_HEADERS}")"
SECOND_COOKIE="$(cookie_of "${SECOND_HEADERS}")"
SECOND_AUTH_HEADERS="$(curl --silent --show-error --cacert "${CERT}" --dump-header - --output /dev/null "${SECOND_URL}")"
SECOND_CALLBACK="$(header_of Location "${SECOND_AUTH_HEADERS}")"
REFUSAL_HEADERS="$(curl --silent --show-error --dump-header - --output "${RUN_DIR}/refusal.txt" "${SECOND_CALLBACK}")"
[[ "$(status_of "${REFUSAL_HEADERS}")" == 404 ]] || fail "wrong-browser callback did not refuse"
[[ -z "$(header_of Location "${REFUSAL_HEADERS}")" ]] || fail "wrong-browser refusal redirected"
[[ "$(<"${RUN_DIR}/refusal.txt")" == 'Not Found' ]] || fail "wrong-browser refusal disclosed a different body"

SECOND_SUCCESS="$(curl --silent --show-error --header "Cookie: ${SECOND_COOKIE}" --output /dev/null --write-out '%{http_code}' "${SECOND_CALLBACK}")"
[[ "${SECOND_SUCCESS}" == 302 ]] || fail "initiating browser could not complete after wrong-browser refusal"

MANAGED_STANDALONE_STATUS="$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' "${APP_BASE}/bfc/login")"
[[ "${MANAGED_STANDALONE_STATUS}" == 404 ]] || fail "standalone route did not refuse managed mode"
"${HARNESS_ENV[@]}" php tests/Live/set-standalone-authority.php
STANDALONE_MANAGED_STATUS="$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' "${APP_BASE}/bfc/managed/login")"
[[ "${STANDALONE_MANAGED_STATUS}" == 404 ]] || fail "managed route did not refuse standalone mode"

EXCHANGE_COUNT="$(php -r '$status = json_decode(file_get_contents($argv[1]), true, flags: JSON_THROW_ON_ERROR); echo $status["exchange_count"];' "${STATUS}")"
[[ "${EXCHANGE_COUNT}" == 2 ]] || fail "fixture observed an unexpected exchange count"

printf 'managed live harness passed\nstamp: %s\nchecks: authenticated TLS handoff/exchange, exact authority redirect origin/path, browser-session binding refusal and success, session rotation/protected access, mode exclusivity\n' "${STAMP}"
