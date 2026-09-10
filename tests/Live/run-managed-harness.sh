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

set_authority_response() {
    php -r 'file_put_contents($argv[1], json_encode(["membership_status" => $argv[2], "connection_status" => "active", "role" => $argv[3]], JSON_THROW_ON_ERROR));' "${STATUS}.response" "$1" "$2"
}

set_confirmation_status() {
    php -r 'file_put_contents($argv[1], $argv[2]);' "${STATUS}.confirmation-status" "$1"
}

confirmation_count() {
    php -r '$status = json_decode(file_get_contents($argv[1]), true, flags: JSON_THROW_ON_ERROR); echo $status["confirmation_count"];' "${STATUS}"
}

assert_standalone_refusal_matrix() {
    local state="$1"
    local surface
    local route
    local method
    local path
    local body="${RUN_DIR}/standalone-refusal.txt"
    local result
    local status
    local redirect
    local cells=0
    local mode

    mode="$("${HARNESS_ENV[@]}" php tests/Live/managed-user-state.php mode)"
    [[ "${mode}" == managed ]] || fail "${state} standalone sweep did not run in managed mode"

    while IFS=$'\t' read -r surface route method path; do
        result="$(curl --silent --show-error --request "${method}" --output "${body}" --write-out '%{http_code}|%{redirect_url}' "${APP_BASE}${path}")"
        status="${result%%|*}"
        redirect="${result#*|}"
        [[ "${status}" == 404 ]] || fail "${state} reached ${method} ${path} (${route}) with status ${status}"
        [[ -z "${redirect}" ]] || fail "${state} was redirected from ${method} ${path} (${route}) to ${redirect}"
        printf 'matrix: state=%s surface=%s route=%s method=%s status=404 authority=managed gate=EnsureStandaloneAuthority\n' \
            "${state}" "${surface}" "${route}" "${method}"
        cells=$((cells + 1))
    done <"${STANDALONE_ROUTES}"

    [[ "${cells}" -gt 0 ]] || fail "${state} standalone sweep derived no browser routes"
}

assert_standalone_openness_matrix() {
    local surface
    local route
    local method
    local path
    local body="${RUN_DIR}/standalone-openness.txt"
    local cookies="${RUN_DIR}/standalone-openness.cookies"
    local status
    local cells=0
    local mode

    mode="$("${HARNESS_ENV[@]}" php tests/Live/managed-user-state.php mode)"
    [[ "${mode}" == standalone ]] || fail "standalone openness sweep did not run in standalone mode"

    touch "${cookies}"
    while IFS=$'\t' read -r surface route method path; do
        [[ "${method}" == GET ]] || continue
        curl --silent --show-error --request "${method}" --cookie "${cookies}" --cookie-jar "${cookies}" \
            --output "${body}" "${APP_BASE}${path}"
    done <"${STANDALONE_ROUTES}"

    while IFS=$'\t' read -r surface route method path; do
        status="$(curl --silent --show-error --request "${method}" --cookie "${cookies}" --cookie-jar "${cookies}" \
            --output "${body}" --write-out '%{http_code}' "${APP_BASE}${path}")"
        [[ "${status}" != 404 ]] || fail "standalone mode could not reach ${method} ${path} (${route})"
        printf 'openness: surface=%s route=%s method=%s status=%s authority=standalone\n' \
            "${surface}" "${route}" "${method}" "${status}"
        cells=$((cells + 1))
    done <"${STANDALONE_ROUTES}"

    [[ "${cells}" -gt 0 ]] || fail "standalone openness sweep derived no browser routes"
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
STANDALONE_ROUTES="${RUN_DIR}/standalone-routes.tsv"
"${HARNESS_ENV[@]}" php tests/Live/managed-standalone-routes.php >"${STANDALONE_ROUTES}"
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
[[ -n "${ROTATED_COOKIE}" ]] && [[ "${ROTATED_COOKIE}" != "${COOKIE}" ]] || fail "managed callback did not rotate the session cookie"
DOMAIN_STATUS="$(curl --silent --show-error --header "Cookie: ${ROTATED_COOKIE}" --output /dev/null --write-out '%{http_code}' "${APP_BASE}/domain")"
[[ "${DOMAIN_STATUS}" == 200 ]] || fail "managed session did not reach a protected route"

USER_ID_BEFORE="$("${HARNESS_ENV[@]}" php tests/Live/managed-user-state.php age 300)"
set_confirmation_status 503
CONFIRMATIONS_BEFORE="$(confirmation_count)"
REFRESH_FAILURE_STATUS="$(curl --silent --show-error --header "Cookie: ${ROTATED_COOKIE}" --output /dev/null --write-out '%{http_code}' "${APP_BASE}/domain")"
[[ "${REFRESH_FAILURE_STATUS}" == 200 ]] || fail "managed refresh failure did not remain available inside grace"
CONFIRMATIONS_AFTER="$(confirmation_count)"
[[ "${CONFIRMATIONS_AFTER}" == $((CONFIRMATIONS_BEFORE + 1)) ]] || fail "refresh-failure state did not execute exactly one live authority confirmation"
assert_standalone_refusal_matrix refresh-failure

"${HARNESS_ENV[@]}" php tests/Live/managed-user-state.php age 900 >/dev/null
CONFIRMATIONS_BEFORE="$(confirmation_count)"
GRACE_STATUS="$(curl --silent --show-error --header "Cookie: ${ROTATED_COOKIE}" --output /dev/null --write-out '%{http_code}' "${APP_BASE}/domain")"
[[ "${GRACE_STATUS}" == 200 ]] || fail "managed grace did not retain browser access before the deadline"
CONFIRMATIONS_AFTER="$(confirmation_count)"
[[ "${CONFIRMATIONS_AFTER}" == $((CONFIRMATIONS_BEFORE + 1)) ]] || fail "managed grace did not execute exactly one live failed confirmation"
assert_standalone_refusal_matrix grace

"${HARNESS_ENV[@]}" php tests/Live/managed-user-state.php age 1800 >/dev/null
OUTAGE_HEADERS="$(curl --silent --show-error --header "Cookie: ${ROTATED_COOKIE}" --dump-header - --output /dev/null "${APP_BASE}/domain")"
[[ "$(status_of "${OUTAGE_HEADERS}")" == 302 ]] || fail "expired managed session was not denied during an authority outage"
[[ "$(header_of Location "${OUTAGE_HEADERS}")" == "${APP_BASE}/bfc/login" ]] || fail "outage denial did not use the package unauthenticated path"
assert_standalone_refusal_matrix outage-expiry

set_confirmation_status 200
RESTORE_HEADERS="$(curl --silent --show-error --dump-header - --output /dev/null "${APP_BASE}/bfc/managed/login")"
RESTORE_URL="$(header_of Location "${RESTORE_HEADERS}")"
RESTORE_COOKIE="$(cookie_of "${RESTORE_HEADERS}")"
RESTORE_AUTH_HEADERS="$(curl --silent --show-error --cacert "${CERT}" --dump-header - --output /dev/null "${RESTORE_URL}")"
RESTORE_CALLBACK="$(header_of Location "${RESTORE_AUTH_HEADERS}")"
RESTORE_CALLBACK_HEADERS="$(curl --silent --show-error --header "Cookie: ${RESTORE_COOKIE}" --dump-header - --output /dev/null "${RESTORE_CALLBACK}")"
[[ "$(status_of "${RESTORE_CALLBACK_HEADERS}")" == 302 ]] || fail "managed login did not restore access after the outage"
RESTORED_COOKIE="$(cookie_of "${RESTORE_CALLBACK_HEADERS}")"
RESTORED_STATUS="$(curl --silent --show-error --header "Cookie: ${RESTORED_COOKIE}" --output /dev/null --write-out '%{http_code}' "${APP_BASE}/domain")"
[[ "${RESTORED_STATUS}" == 200 ]] || fail "restored managed session did not reach the protected route"
USER_ID_AFTER="$("${HARNESS_ENV[@]}" php tests/Live/managed-user-state.php id)"
[[ "${USER_ID_AFTER}" == "${USER_ID_BEFORE}" ]] || fail "outage restoration recreated the managed user"

set_authority_response active admin
SECOND_HEADERS="$(curl --silent --show-error --dump-header - --output /dev/null "${APP_BASE}/bfc/managed/login")"
SECOND_URL="$(header_of Location "${SECOND_HEADERS}")"
SECOND_COOKIE="$(cookie_of "${SECOND_HEADERS}")"
SECOND_AUTH_HEADERS="$(curl --silent --show-error --cacert "${CERT}" --dump-header - --output /dev/null "${SECOND_URL}")"
SECOND_CALLBACK="$(header_of Location "${SECOND_AUTH_HEADERS}")"
REFUSAL_HEADERS="$(curl --silent --show-error --dump-header - --output "${RUN_DIR}/refusal.txt" "${SECOND_CALLBACK}")"
[[ "$(status_of "${REFUSAL_HEADERS}")" == 404 ]] || fail "wrong-browser callback did not refuse"
[[ -z "$(header_of Location "${REFUSAL_HEADERS}")" ]] || fail "wrong-browser refusal redirected"
[[ "$(<"${RUN_DIR}/refusal.txt")" == 'Not Found' ]] || fail "wrong-browser refusal disclosed a different body"
assert_standalone_refusal_matrix failed-managed-entry

SECOND_SUCCESS_HEADERS="$(curl --silent --show-error --header "Cookie: ${SECOND_COOKIE}" --dump-header - --output /dev/null "${SECOND_CALLBACK}")"
[[ "$(status_of "${SECOND_SUCCESS_HEADERS}")" == 302 ]] || fail "initiating browser could not complete after wrong-browser refusal"
PROMOTED_COOKIE="$(cookie_of "${SECOND_SUCCESS_HEADERS}")"
[[ -n "${PROMOTED_COOKIE}" ]] || fail "promoted callback omitted its rotated session cookie"
PROMOTED_STATUS="$(curl --silent --show-error --header "Cookie: ${PROMOTED_COOKIE}" --output /dev/null --write-out '%{http_code}' "${APP_BASE}/managed-admin")"
[[ "${PROMOTED_STATUS}" == 200 ]] || fail "managed role promotion was not visible on the next authorization decision"

set_authority_response active member
THIRD_HEADERS="$(curl --silent --show-error --dump-header - --output /dev/null "${APP_BASE}/bfc/managed/login")"
THIRD_URL="$(header_of Location "${THIRD_HEADERS}")"
THIRD_COOKIE="$(cookie_of "${THIRD_HEADERS}")"
THIRD_AUTH_HEADERS="$(curl --silent --show-error --cacert "${CERT}" --dump-header - --output /dev/null "${THIRD_URL}")"
THIRD_CALLBACK="$(header_of Location "${THIRD_AUTH_HEADERS}")"
THIRD_CALLBACK_HEADERS="$(curl --silent --show-error --header "Cookie: ${THIRD_COOKIE}" --dump-header - --output /dev/null "${THIRD_CALLBACK}")"
[[ "$(status_of "${THIRD_CALLBACK_HEADERS}")" == 302 ]] || fail "managed demotion callback did not complete"
DEMOTED_COOKIE="$(cookie_of "${THIRD_CALLBACK_HEADERS}")"
DEMOTED_STATUS="$(curl --silent --show-error --header "Cookie: ${DEMOTED_COOKIE}" --output /dev/null --write-out '%{http_code}' "${APP_BASE}/managed-admin")"
[[ "${DEMOTED_STATUS}" == 403 ]] || fail "managed role demotion was not visible on the next authorization decision"

set_authority_response removed member
FOURTH_HEADERS="$(curl --silent --show-error --dump-header - --output /dev/null "${APP_BASE}/bfc/managed/login")"
FOURTH_URL="$(header_of Location "${FOURTH_HEADERS}")"
FOURTH_COOKIE="$(cookie_of "${FOURTH_HEADERS}")"
FOURTH_AUTH_HEADERS="$(curl --silent --show-error --cacert "${CERT}" --dump-header - --output /dev/null "${FOURTH_URL}")"
FOURTH_CALLBACK="$(header_of Location "${FOURTH_AUTH_HEADERS}")"
DENIAL_STATUS="$(curl --silent --show-error --header "Cookie: ${FOURTH_COOKIE}" --output /dev/null --write-out '%{http_code}' "${FOURTH_CALLBACK}")"
[[ "${DENIAL_STATUS}" == 404 ]] || fail "authoritative membership denial did not refuse immediately"
assert_standalone_refusal_matrix explicit-denial
ENDED_SESSION_HEADERS="$(curl --silent --show-error --header "Cookie: ${DEMOTED_COOKIE}" --dump-header - --output /dev/null "${APP_BASE}/domain")"
[[ "$(status_of "${ENDED_SESSION_HEADERS}")" == 302 ]] || fail "authoritative membership denial did not end the existing browser session"
[[ "$(header_of Location "${ENDED_SESSION_HEADERS}")" == "${APP_BASE}/bfc/login" ]] || fail "ended managed session did not follow the package unauthenticated path"
ENDED_SESSION_DESTINATION="$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' "${APP_BASE}/bfc/login")"
[[ "${ENDED_SESSION_DESTINATION}" == 404 ]] || fail "ended managed session reached a standalone login in managed mode"

MANAGED_STANDALONE_STATUS="$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' "${APP_BASE}/bfc/login")"
[[ "${MANAGED_STANDALONE_STATUS}" == 404 ]] || fail "standalone route did not refuse managed mode"
"${HARNESS_ENV[@]}" php tests/Live/set-standalone-authority.php
assert_standalone_openness_matrix
STANDALONE_LOGIN_STATUS="$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' "${APP_BASE}/bfc/login")"
[[ "${STANDALONE_LOGIN_STATUS}" == 200 ]] || fail "the standalone login control did not reopen when authority became standalone"
STANDALONE_MANAGED_STATUS="$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' "${APP_BASE}/bfc/managed/login")"
[[ "${STANDALONE_MANAGED_STATUS}" == 404 ]] || fail "managed route did not refuse standalone mode"

EXCHANGE_COUNT="$(php -r '$status = json_decode(file_get_contents($argv[1]), true, flags: JSON_THROW_ON_ERROR); echo $status["exchange_count"];' "${STATUS}")"
[[ "${EXCHANGE_COUNT}" == 5 ]] || fail "fixture observed an unexpected exchange count"

printf 'managed live harness passed\nstamp: %s\nchecks: authenticated TLS handoff/exchange, exact authority redirect origin/path, browser-session binding refusal and success, session rotation/protected access, structurally derived standalone refusal matrix after refresh failure/grace/outage expiry/explicit denial/failed managed entry, structurally derived standalone openness matrix, 1800-second outage denial and session ending, same-user restoration after authority recovery, role promotion and demotion on the next authorization decision, immediate authoritative browser denial and session ending, mode exclusivity\n' "${STAMP}"
