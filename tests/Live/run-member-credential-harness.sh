#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/bfc-member-credential.XXXXXX")"
DB="${RUN_DIR}/database.sqlite"
SERVER_LOG="${RUN_DIR}/server.log"
PORT="$(php -r '$socket = stream_socket_server("tcp://127.0.0.1:0", $errno, $error); if ($socket === false) { fwrite(STDERR, $error); exit(1); } echo parse_url(stream_socket_get_name($socket, false), PHP_URL_PORT);')"
BASE="http://127.0.0.1:${PORT}"
COOKIE="${RUN_DIR}/member.cookies"

fail() {
    printf 'member credential harness failure: %s (run directory: %s)\n' "$1" "${RUN_DIR}" >&2
    exit 1
}

request() {
    local expected="$1"
    local output="$2"
    shift 2
    local status
    status="$(curl --silent --show-error --output "${output}" --write-out '%{http_code}' "$@")"
    [[ "${status}" == "${expected}" ]] || fail "expected HTTP ${expected}, observed ${status} for $*"
}

json_value() {
    php -r '$data = json_decode(file_get_contents($argv[1]), true, flags: JSON_THROW_ON_ERROR); foreach (explode(".", $argv[2]) as $part) { $data = $data[$part]; } echo $data;' "$1" "$2"
}

cleanup() {
    if [[ -n "${SERVER_PID:-}" ]]; then
        kill "${SERVER_PID}" 2>/dev/null || true
        wait "${SERVER_PID}" 2>/dev/null || true
    fi
    if [[ "${BFC_HARNESS_KEEP_RUN:-false}" != true ]]; then
        rm -rf "${RUN_DIR}"
    fi
}
trap cleanup EXIT

touch "${DB}"
HARNESS_ENV=(
    env -i
    "HOME=${HOME}"
    "PATH=${PATH}"
    "APP_ENV=testing"
    "APP_KEY=base64:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
    "APP_URL=${BASE}"
    "DB_CONNECTION=sqlite"
    "DB_DATABASE=${DB}"
    "SESSION_DRIVER=database"
    "CACHE_STORE=array"
    "BUILT_FOR_CLOUD_SURFACE_DATA_MIGRATIONS=false"
)

cd "${ROOT}"
"${HARNESS_ENV[@]}" vendor/bin/testbench migrate:fresh --force --no-interaction >"${RUN_DIR}/migrate.log"
"${HARNESS_ENV[@]}" php tests/Live/seed-standalone-harness.php >"${RUN_DIR}/seeded-ids"
"${HARNESS_ENV[@]}" vendor/bin/testbench serve --host=127.0.0.1 --port="${PORT}" >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!

for _ in {1..80}; do
    if curl --silent --output "${RUN_DIR}/login.html" --cookie "${COOKIE}" --cookie-jar "${COOKIE}" "${BASE}/bfc/login"; then
        break
    fi
    kill -0 "${SERVER_PID}" 2>/dev/null || fail "server exited before readiness; see ${SERVER_LOG}"
    sleep 0.1
done

CSRF="$(perl -0777 -ne 'print $1 if /name="_token" value="([^"]+)"/' "${RUN_DIR}/login.html")"
[[ -n "${CSRF}" ]] || fail 'login CSRF token was absent'
request 302 "${RUN_DIR}/login-response" --cookie "${COOKIE}" --cookie-jar "${COOKIE}" \
    --data-urlencode "_token=${CSRF}" --data-urlencode 'email=member@example.test' \
    --data-urlencode 'password=harness owner password' "${BASE}/bfc/login"
request 200 "${RUN_DIR}/session-page.html" --cookie "${COOKIE}" --cookie-jar "${COOKIE}" "${BASE}/bfc/me/sessions"
CSRF="$(perl -0777 -ne 'print $1 if /name="_token" value="([^"]+)"/' "${RUN_DIR}/session-page.html")"
[[ -n "${CSRF}" ]] || fail 'authenticated CSRF token was absent'

for pass in 1 2; do
    request 201 "${RUN_DIR}/mint-${pass}.json" --cookie "${COOKIE}" --cookie-jar "${COOKIE}" \
        --data-urlencode "_token=${CSRF}" --data-urlencode 'subject_type=installation' \
        --data-urlencode "subject_ref=live-member-${pass}" --data-urlencode "name=live-pass-${pass}" \
        "${BASE}/bfc/installation/credentials"
    CREDENTIAL_ID="$(json_value "${RUN_DIR}/mint-${pass}.json" 'credential.id')"
    SECRET="$(json_value "${RUN_DIR}/mint-${pass}.json" 'delivery.secret')"
    [[ -n "${CREDENTIAL_ID}" && -n "${SECRET}" ]] || fail "pass ${pass} mint did not persist and reveal a credential"

    request 200 "${RUN_DIR}/auth-minted-${pass}.json" --header 'Accept: application/json' --header "Authorization: Bearer ${SECRET}" \
        "${BASE}/_bfc-harness/credential-auth"
    request 200 "${RUN_DIR}/list-${pass}.json" --cookie "${COOKIE}" "${BASE}/bfc/installation/credentials"
    php -r '$data = json_decode(file_get_contents($argv[1]), true, flags: JSON_THROW_ON_ERROR); $ids = array_column($data["credentials"], "id"); exit(in_array($argv[2], $ids, true) ? 0 : 1);' \
        "${RUN_DIR}/list-${pass}.json" "${CREDENTIAL_ID}" || fail "pass ${pass} listing omitted its persisted credential"

    request 201 "${RUN_DIR}/rotate-${pass}.json" --cookie "${COOKIE}" --cookie-jar "${COOKIE}" \
        --data-urlencode "_token=${CSRF}" "${BASE}/bfc/installation/credentials/${CREDENTIAL_ID}/rotate"
    REPLACEMENT_ID="$(json_value "${RUN_DIR}/rotate-${pass}.json" 'credential.id')"
    REPLACEMENT_SECRET="$(json_value "${RUN_DIR}/rotate-${pass}.json" 'delivery.secret')"
    [[ -n "${REPLACEMENT_ID}" && -n "${REPLACEMENT_SECRET}" ]] || fail "pass ${pass} rotate did not persist and reveal a replacement"
    request 200 "${RUN_DIR}/auth-rotated-${pass}.json" --header 'Accept: application/json' --header "Authorization: Bearer ${REPLACEMENT_SECRET}" \
        "${BASE}/_bfc-harness/credential-auth"

    request 204 "${RUN_DIR}/revoke-${pass}.json" --request DELETE --cookie "${COOKIE}" --cookie-jar "${COOKIE}" \
        --data-urlencode "_token=${CSRF}" "${BASE}/bfc/installation/credentials/${REPLACEMENT_ID}"
    request 401 "${RUN_DIR}/auth-revoked-${pass}.json" --header 'Accept: application/json' --header "Authorization: Bearer ${REPLACEMENT_SECRET}" \
        "${BASE}/_bfc-harness/credential-auth"
done

printf 'LIVE PASS: one Member session completed issue/list/rotate/revoke plus persisted-row and bearer-authentication proofs twice.\n'
