#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/bfc-p5d-k5-standalone.XXXXXX")"
DB="${RUN_DIR}/database.sqlite"
COOKIE="${RUN_DIR}/owner.cookies"
SERVER_LOG="${RUN_DIR}/server.log"
STAMP="bfc-p5d-k5-standalone-$(date -u +%Y%m%dT%H%M%SZ)-$$"
PORT="$(php -r '$socket = stream_socket_server("tcp://127.0.0.1:0", $errno, $error); if ($socket === false) { exit(1); } echo parse_url(stream_socket_get_name($socket, false), PHP_URL_PORT);')"
BASE="http://127.0.0.1:${PORT}"
AUDIENCE="urn:bfc:p5d:k5:${STAMP}"
BODY='{"event":"p5d-k5-live"}'

fail() {
    printf 'P5d K5 standalone failure: %s (run directory: %s)\n' "$1" "${RUN_DIR}" >&2
    [[ ! -s "${SERVER_LOG}" ]] || perl -ne 'print' "${SERVER_LOG}" >&2
    exit 1
}

assert_equal() {
    [[ "$1" == "$2" ]] || fail "$3: expected [$1], observed [$2]"
}

response_status() {
    printf '%s' "$1" | perl -ne '$last = $_; END { chomp $last; print $last }'
}

response_body() {
    printf '%s' "$1" | perl -0777 -pe 's/\n[^\n]*\z//'
}

json_value() {
    php -r '$value = json_decode(stream_get_contents(STDIN), true, flags: JSON_THROW_ON_ERROR); foreach (explode(".", $argv[1]) as $part) { $value = $value[$part]; } if (! is_scalar($value)) { exit(1); } echo $value;' "$1"
}

csrf_from_body() {
    printf '%s' "$1" | perl -0777 -ne 'print $1 if /name="_token" value="([^"]+)"/'
}

sign_header() {
    php -r 'echo json_encode(["key_id" => $argv[1], "signing_key" => $argv[2], "audience" => $argv[3], "body" => $argv[4]], JSON_THROW_ON_ERROR);' \
        "${KEY_ID}" "${SIGNING_KEY}" "${AUDIENCE}" "${BODY}" | "${HARNESS_ENV[@]}" php tests/Live/p5d-k5-sign.php
}

cleanup() {
    if [[ -n "${SERVER_PID:-}" ]]; then
        kill "${SERVER_PID}" 2>/dev/null || true
        wait "${SERVER_PID}" 2>/dev/null || true
    fi
    [[ "${BFC_HARNESS_KEEP_RUN:-false}" == true ]] || rm -rf "${RUN_DIR}"
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
    "MAIL_MAILER=array"
    "BUILT_FOR_CLOUD_SURFACE_DATA_MIGRATIONS=false"
    "BUILT_FOR_CLOUD_HMAC_AUDIENCE=${AUDIENCE}"
    "BFC_HARNESS_PERSONAL_HMAC=true"
)

cd "${ROOT}"
"${HARNESS_ENV[@]}" vendor/bin/testbench migrate:fresh --force --no-interaction >"${RUN_DIR}/migrate.log"
SEED="$("${HARNESS_ENV[@]}" php tests/Live/seed-p5d-k5-standalone.php)"
OWNER_ID="${SEED%%$'\t'*}"
OPERATOR_BEARER="${SEED#*$'\t'}"
[[ -n "${OWNER_ID}" && -n "${OPERATOR_BEARER}" ]] || fail 'seed omitted the owner or operator credential'

"${HARNESS_ENV[@]}" vendor/bin/testbench serve --host=127.0.0.1 --port="${PORT}" >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
for _ in {1..80}; do
    READY_STATUS="$(curl --silent --output /dev/null --write-out '%{http_code}' "${BASE}/bfc/login" || true)"
    [[ "${READY_STATUS}" == 200 ]] && break
    kill -0 "${SERVER_PID}" 2>/dev/null || fail 'server exited before readiness'
    sleep 0.1
done
assert_equal 200 "${READY_STATUS}" 'server readiness'

LOGIN="$(curl --silent --show-error --cookie "${COOKIE}" --cookie-jar "${COOKIE}" --write-out $'\n%{http_code}' "${BASE}/bfc/login")"
assert_equal 200 "$(response_status "${LOGIN}")" 'login page status'
CSRF="$(csrf_from_body "$(response_body "${LOGIN}")")"
[[ -n "${CSRF}" ]] || fail 'login page omitted the CSRF token'

LOGIN_RESULT="$(curl --silent --show-error --cookie "${COOKIE}" --cookie-jar "${COOKIE}" --output /dev/null --write-out '%{http_code}' \
    --data-urlencode "_token=${CSRF}" --data-urlencode 'email=p5d-k5-owner@example.test' \
    --data-urlencode 'password=p5d k5 owner password' "${BASE}/bfc/login")"
assert_equal 302 "${LOGIN_RESULT}" 'session login status'

SESSION_PAGE="$(curl --silent --show-error --cookie "${COOKIE}" --cookie-jar "${COOKIE}" --write-out $'\n%{http_code}' "${BASE}/bfc/me/sessions")"
assert_equal 200 "$(response_status "${SESSION_PAGE}")" 'authenticated session status'
CSRF="$(csrf_from_body "$(response_body "${SESSION_PAGE}")")"
[[ -n "${CSRF}" ]] || fail 'authenticated page omitted the CSRF token'

MINT="$(curl --silent --show-error --cookie "${COOKIE}" --cookie-jar "${COOKIE}" --header 'Accept: application/json' \
    --header 'Content-Type: application/json' --header "X-CSRF-TOKEN: ${CSRF}" --write-out $'\n%{http_code}' \
    --data '{"name":"p5d-k5-live","kind":"hmac"}' "${BASE}/bfc/me/credentials")"
assert_equal 201 "$(response_status "${MINT}")" 'personal HMAC mint status'
MINT_BODY="$(response_body "${MINT}")"
KEY_ID="$(printf '%s' "${MINT_BODY}" | json_value delivery.key_id)"
SIGNING_KEY="$(printf '%s' "${MINT_BODY}" | json_value delivery.signing_key)"
FINGERPRINT="$(printf '%s' "${MINT_BODY}" | json_value delivery.delivery_fingerprint)"
[[ -n "${KEY_ID}" && -n "${SIGNING_KEY}" && -n "${FINGERPRINT}" ]] || fail 'personal HMAC mint omitted delivery material'

PENDING_STATE="$("${HARNESS_ENV[@]}" php tests/Live/p5d-k5-credential-state.php "${KEY_ID}")"
assert_equal "kind=hmac subject=user:${OWNER_ID} user=${OWNER_ID} status=pending delivered=yes activated=no" "${PENDING_STATE}" 'fresh-process pending state'

PENDING_SIGNATURE="$(sign_header)"
PENDING_STATUS="$(curl --silent --show-error --header 'Content-Type: application/json' --header "BFC-Signature: ${PENDING_SIGNATURE}" \
    --data "${BODY}" --output /dev/null --write-out '%{http_code}' "${BASE}/_bfc-harness/p5d-hmac/${OWNER_ID}")"
assert_equal 401 "${PENDING_STATUS}" 'pending HMAC refusal'

ACTIVATION="$(curl --silent --show-error --header 'Accept: application/json' --header 'Content-Type: application/json' \
    --header "Authorization: Bearer ${OPERATOR_BEARER}" --write-out $'\n%{http_code}' \
    --data "{\"delivery_fingerprint\":\"${FINGERPRINT}\"}" "${BASE}/bfc/credentials/${KEY_ID}/activate")"
assert_equal 200 "$(response_status "${ACTIVATION}")" 'unified credential:rotate activation status'
assert_equal "${KEY_ID}" "$(response_body "${ACTIVATION}" | json_value credential.id)" 'activated credential id'

ACTIVE_STATE="$("${HARNESS_ENV[@]}" php tests/Live/p5d-k5-credential-state.php "${KEY_ID}")"
assert_equal "kind=hmac subject=user:${OWNER_ID} user=${OWNER_ID} status=active delivered=yes activated=yes" "${ACTIVE_STATE}" 'fresh-process active state'

SIGNATURE="$(sign_header)"
VERIFIED="$(curl --silent --show-error --header 'Content-Type: application/json' --header "BFC-Signature: ${SIGNATURE}" \
    --data "${BODY}" --write-out $'\n%{http_code}' "${BASE}/_bfc-harness/p5d-hmac/${OWNER_ID}")"
assert_equal 200 "$(response_status "${VERIFIED}")" 'bfc.hmac verification status'
assert_equal "${KEY_ID}" "$(response_body "${VERIFIED}" | json_value credential_id)" 'bfc.hmac verified credential id'

printf 'P5d K5 standalone live-verified\nstamp: %s\ntransport: real HTTP socket %s\nchecks: session login=302, personal hmac mint=201, pending signature=401, unified credential:rotate activation=200, activated signature=200, fresh-process state oracles=pending+active\n' "${STAMP}" "${BASE}"
