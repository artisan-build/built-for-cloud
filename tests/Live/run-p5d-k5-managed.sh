#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCALPELS_ROOT="${P5D_K5_SCALPELS_ROOT:?Set P5D_K5_SCALPELS_ROOT to the disposable real-Scalpels runtime}"
TLS_ROOT="${P5D_K5_TLS_ROOT:?Set P5D_K5_TLS_ROOT to the disposable private-CA directory}"
RUN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/bfc-p5d-k5-managed.XXXXXX")"
DB="${RUN_DIR}/database.sqlite"
COOKIE="${RUN_DIR}/owner.cookies"
APP_LOG="${RUN_DIR}/bfc.log"
SCALPELS_LOG="${RUN_DIR}/scalpels.log"
CADDY_LOG="${RUN_DIR}/caddy.log"
STAMP="bfc-p5d-k5-managed-$(date -u +%Y%m%dT%H%M%SZ)-$$"
AUDIENCE="urn:bfc:p5d:k5:${STAMP}"
BODY='{"event":"p5d-k5-managed-live"}'
CADDY_BIN="$(command -v caddy || true)"

alloc_port() {
    php -r '$socket = stream_socket_server("tcp://127.0.0.1:0", $errno, $error); if ($socket === false) { exit(1); } echo parse_url(stream_socket_get_name($socket, false), PHP_URL_PORT);'
}

SCALPELS_HTTP_PORT="$(alloc_port)"
SCALPELS_TLS_PORT="$(alloc_port)"
BFC_HTTP_PORT="$(alloc_port)"
BFC_TLS_PORT="$(alloc_port)"
SCALPELS_BASE="https://127.0.0.1:${SCALPELS_TLS_PORT}"
BFC_BASE="https://127.0.0.1:${BFC_TLS_PORT}"
CA="${TLS_ROOT}/ca.pem"
CERT="${TLS_ROOT}/leaf.pem"
KEY="${TLS_ROOT}/leaf.key"

fail() {
    printf 'P5d K5 managed failure: %s (run directory: %s)\n' "$1" "${RUN_DIR}" >&2
    for log in "${SCALPELS_LOG}" "${APP_LOG}" "${CADDY_LOG}"; do
        [[ ! -s "${log}" ]] || perl -ne 'print' "${log}" >&2
    done
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

hmac_status() {
    local signature
    signature="$(sign_header)"
    curl --silent --show-error --cacert "${CA}" --header 'Content-Type: application/json' \
        --header "BFC-Signature: ${signature}" --data "${BODY}" --output /dev/null --write-out '%{http_code}' \
        "${BFC_BASE}/_bfc-harness/p5d-hmac/${OWNER_ID}"
}

start_scalpels() {
    APP_URL="${SCALPELS_BASE}" php "${SCALPELS_ROOT}/artisan" serve --host=127.0.0.1 --port="${SCALPELS_HTTP_PORT}" >"${SCALPELS_LOG}" 2>&1 &
    SCALPELS_PID=$!

    for _ in {1..100}; do
        SCALPELS_READY="$(curl --silent --output /dev/null --write-out '%{http_code}' "http://127.0.0.1:${SCALPELS_HTTP_PORT}/" || true)"
        [[ "${SCALPELS_READY}" == 200 ]] && return
        kill -0 "${SCALPELS_PID}" 2>/dev/null || fail 'real Scalpels exited before readiness'
        sleep 0.1
    done
    fail 'real Scalpels did not become ready'
}

start_bfc() {
    "${HARNESS_ENV[@]}" vendor/bin/testbench serve --host=127.0.0.1 --port="${BFC_HTTP_PORT}" >"${APP_LOG}" 2>&1 &
    APP_PID=$!

    for _ in {1..100}; do
        BFC_READY="$(curl --silent --output /dev/null --write-out '%{http_code}' "http://127.0.0.1:${BFC_HTTP_PORT}/_bfc-harness/users/${OWNER_ID}" || true)"
        [[ "${BFC_READY}" == 200 ]] && return
        kill -0 "${APP_PID}" 2>/dev/null || fail 'BFC application exited before readiness'
        sleep 0.1
    done
    fail 'BFC application did not become ready'
}

stop_scalpels() {
    kill "${SCALPELS_PID}" 2>/dev/null || true
    wait "${SCALPELS_PID}" 2>/dev/null || true
    unset SCALPELS_PID
}

stop_bfc() {
    kill "${APP_PID}" 2>/dev/null || true
    wait "${APP_PID}" 2>/dev/null || true
    unset APP_PID
}

start_clock_second() {
    php -r '$now = microtime(true); usleep((int) ((ceil($now) - $now + 0.05) * 1_000_000));'
}

cleanup() {
    if [[ -n "${SCALPELS_PID:-}" ]]; then kill "${SCALPELS_PID}" 2>/dev/null || true; wait "${SCALPELS_PID}" 2>/dev/null || true; fi
    if [[ -n "${APP_PID:-}" ]]; then kill "${APP_PID}" 2>/dev/null || true; wait "${APP_PID}" 2>/dev/null || true; fi
    if [[ -n "${CADDY_PID:-}" ]]; then kill "${CADDY_PID}" 2>/dev/null || true; wait "${CADDY_PID}" 2>/dev/null || true; fi
    [[ "${BFC_HARNESS_KEEP_RUN:-false}" == true ]] || rm -rf "${RUN_DIR}"
}
trap cleanup EXIT

[[ -n "${CADDY_BIN}" ]] || fail 'caddy is unavailable'
[[ -f "${SCALPELS_ROOT}/artisan" ]] || fail 'the disposable real-Scalpels runtime is missing'
[[ -f "${CA}" && -f "${CERT}" && -f "${KEY}" ]] || fail 'the private CA or leaf keypair is missing'

cd "${ROOT}"
APP_URL="${SCALPELS_BASE}" php "${SCALPELS_ROOT}/artisan" migrate:fresh --force --no-interaction >"${RUN_DIR}/scalpels-migrate.log"
SCALPELS_SEED="$(APP_URL="${SCALPELS_BASE}" php tests/Live/p5d-k5-seed-real-scalpels.php "${SCALPELS_ROOT}" "${BFC_BASE}")"
ISSUER="$(printf '%s' "${SCALPELS_SEED}" | json_value issuer)"
CONNECTION_ID="$(printf '%s' "${SCALPELS_SEED}" | json_value connection_id)"
ORGANIZATION_ID="$(printf '%s' "${SCALPELS_SEED}" | json_value organization_id)"
INSTALLATION_ID="$(printf '%s' "${SCALPELS_SEED}" | json_value installation_id)"
GENERATION="$(printf '%s' "${SCALPELS_SEED}" | json_value generation)"
ROSTER_VERSION="$(printf '%s' "${SCALPELS_SEED}" | json_value roster_version)"
SCALPELS_ID="$(printf '%s' "${SCALPELS_SEED}" | json_value scalpels_id)"
CLIENT_SECRET="$(printf '%s' "${SCALPELS_SEED}" | json_value secret)"

touch "${DB}"
HARNESS_ENV=(
    env -i
    "HOME=${HOME}"
    "PATH=${PATH}"
    "APP_ENV=testing"
    "APP_KEY=base64:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
    "APP_URL=${BFC_BASE}"
    "DB_CONNECTION=sqlite"
    "DB_DATABASE=${DB}"
    "SESSION_DRIVER=database"
    "CACHE_STORE=array"
    "MAIL_MAILER=array"
    "BUILT_FOR_CLOUD_SURFACE_DATA_MIGRATIONS=false"
    "BUILT_FOR_CLOUD_HMAC_AUDIENCE=${AUDIENCE}"
    "BUILT_FOR_CLOUD_MANAGED_CLIENT_SECRET=${CLIENT_SECRET}"
    "BUILT_FOR_CLOUD_MANAGED_CA_BUNDLE=${CA}"
    "BFC_HARNESS_PERSONAL_HMAC=true"
)
"${HARNESS_ENV[@]}" vendor/bin/testbench migrate:fresh --force --no-interaction >"${RUN_DIR}/migrate.log"
SEED="$("${HARNESS_ENV[@]}" php tests/Live/seed-p5d-k5-standalone.php)"
OWNER_ID="${SEED%%$'\t'*}"
OPERATOR_BEARER="${SEED#*$'\t'}"

start_scalpels
start_bfc
SCALPELS_HTTP_PORT="${SCALPELS_HTTP_PORT}" SCALPELS_TLS_PORT="${SCALPELS_TLS_PORT}" \
    BFC_HTTP_PORT="${BFC_HTTP_PORT}" BFC_TLS_PORT="${BFC_TLS_PORT}" \
    P5D_K5_TLS_CERT="${CERT}" P5D_K5_TLS_KEY="${KEY}" \
    "${CADDY_BIN}" run --adapter caddyfile --config tests/Live/p5d-k5-Caddyfile >"${CADDY_LOG}" 2>&1 &
CADDY_PID=$!

for _ in {1..100}; do
    READY="$(curl --silent --cacert "${CA}" --output /dev/null --write-out '%{http_code}' "${BFC_BASE}/bfc/login" || true)"
    [[ "${READY}" == 200 ]] && break
    kill -0 "${APP_PID}" 2>/dev/null || fail 'BFC application exited before readiness'
    kill -0 "${CADDY_PID}" 2>/dev/null || fail 'Caddy exited before readiness'
    sleep 0.1
done
assert_equal 200 "${READY}" 'TLS application readiness'

for port in "${SCALPELS_TLS_PORT}" "${BFC_TLS_PORT}"; do
    IDENTITY="$(openssl s_client -connect "127.0.0.1:${port}" -CAfile "${CA}" </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer)"
    [[ "${IDENTITY}" == *'issuer=CN=P5d K5 Interop Local CA'* ]] || fail "listener ${port} did not present the run-owned certificate"
done

LOGIN="$(curl --silent --show-error --cacert "${CA}" --cookie "${COOKIE}" --cookie-jar "${COOKIE}" --write-out $'\n%{http_code}' "${BFC_BASE}/bfc/login")"
assert_equal 200 "$(response_status "${LOGIN}")" 'login page status'
CSRF="$(csrf_from_body "$(response_body "${LOGIN}")")"
LOGIN_STATUS="$(curl --silent --show-error --cacert "${CA}" --cookie "${COOKIE}" --cookie-jar "${COOKIE}" --output /dev/null --write-out '%{http_code}' \
    --data-urlencode "_token=${CSRF}" --data-urlencode 'email=p5d-k5-owner@example.test' \
    --data-urlencode 'password=p5d k5 owner password' "${BFC_BASE}/bfc/login")"
assert_equal 302 "${LOGIN_STATUS}" 'session login status'
SESSION_PAGE="$(curl --silent --show-error --cacert "${CA}" --cookie "${COOKIE}" --cookie-jar "${COOKIE}" --write-out $'\n%{http_code}' "${BFC_BASE}/bfc/me/sessions")"
assert_equal 200 "$(response_status "${SESSION_PAGE}")" 'authenticated session status'
CSRF="$(csrf_from_body "$(response_body "${SESSION_PAGE}")")"

MINT="$(curl --silent --show-error --cacert "${CA}" --cookie "${COOKIE}" --cookie-jar "${COOKIE}" --header 'Accept: application/json' \
    --header 'Content-Type: application/json' --header "X-CSRF-TOKEN: ${CSRF}" --write-out $'\n%{http_code}' \
    --data '{"name":"p5d-k5-real-managed","kind":"hmac"}' "${BFC_BASE}/bfc/me/credentials")"
assert_equal 201 "$(response_status "${MINT}")" 'personal HMAC mint status'
MINT_BODY="$(response_body "${MINT}")"
KEY_ID="$(printf '%s' "${MINT_BODY}" | json_value delivery.key_id)"
SIGNING_KEY="$(printf '%s' "${MINT_BODY}" | json_value delivery.signing_key)"
FINGERPRINT="$(printf '%s' "${MINT_BODY}" | json_value delivery.delivery_fingerprint)"
ACTIVATION="$(curl --silent --show-error --cacert "${CA}" --header 'Accept: application/json' --header 'Content-Type: application/json' \
    --header "Authorization: Bearer ${OPERATOR_BEARER}" --write-out $'\n%{http_code}' \
    --data "{\"delivery_fingerprint\":\"${FINGERPRINT}\"}" "${BFC_BASE}/bfc/credentials/${KEY_ID}/activate")"
assert_equal 200 "$(response_status "${ACTIVATION}")" 'unified credential:rotate activation status'

"${HARNESS_ENV[@]}" php tests/Live/p5d-k5-managed-state.php bind "${OWNER_ID}" "${KEY_ID}" \
    "${ISSUER}" "${CONNECTION_ID}" "${ORGANIZATION_ID}" "${INSTALLATION_ID}" "${SCALPELS_BASE}" \
    "${SCALPELS_ID}" "${GENERATION}" "${ROSTER_VERSION}" >/dev/null

assert_equal 200 "$(hmac_status)" 'fresh managed HMAC status'
AUTHORITY_WHILE_FRESH="$(APP_URL="${SCALPELS_BASE}" php tests/Live/p5d-k5-real-scalpels-state.php \
    "${SCALPELS_ROOT}" "${ORGANIZATION_ID}" "${SCALPELS_ID}" "${CONNECTION_ID}" state)"
assert_equal 0 "$(printf '%s' "${AUTHORITY_WHILE_FRESH}" | json_value response_sequence)" 'fresh-window authority sequence'
"${HARNESS_ENV[@]}" php tests/Live/p5d-k5-managed-state.php age "${OWNER_ID}" "${KEY_ID}" 300 >/dev/null
PACKAGE_BEFORE_SUCCESS="$("${HARNESS_ENV[@]}" php tests/Live/p5d-k5-managed-state.php state "${OWNER_ID}" "${KEY_ID}")"
assert_equal managed "$(printf '%s' "${PACKAGE_BEFORE_SUCCESS}" | json_value authority)" 'package authority mode before confirmation'
CONFIRMED_AGE="$(printf '%s' "${PACKAGE_BEFORE_SUCCESS}" | json_value membership_confirmed_age)"
[[ "${CONFIRMED_AGE}" =~ ^[0-9]+$ && "${CONFIRMED_AGE}" -ge 300 ]] \
    || fail "package confirmation age before confirmation: expected at least [300], observed [${CONFIRMED_AGE}]"
assert_equal 200 "$(hmac_status)" 'real-authority confirmation status'
AUTHORITY_AFTER_SUCCESS="$(APP_URL="${SCALPELS_BASE}" php tests/Live/p5d-k5-real-scalpels-state.php \
    "${SCALPELS_ROOT}" "${ORGANIZATION_ID}" "${SCALPELS_ID}" "${CONNECTION_ID}" state)"
assert_equal 1 "$(printf '%s' "${AUTHORITY_AFTER_SUCCESS}" | json_value response_sequence)" 'real-authority success sequence'
PACKAGE_AFTER_SUCCESS="$("${HARNESS_ENV[@]}" php tests/Live/p5d-k5-managed-state.php state "${OWNER_ID}" "${KEY_ID}")"
assert_equal 1 "$(printf '%s' "${PACKAGE_AFTER_SUCCESS}" | json_value response_sequence)" 'package success sequence'
assert_equal yes "$(printf '%s' "${PACKAGE_AFTER_SUCCESS}" | json_value confirmation_reset)" 'successful confirmation reset timestamp'

stop_scalpels
start_clock_second
"${HARNESS_ENV[@]}" php tests/Live/p5d-k5-managed-state.php age "${OWNER_ID}" "${KEY_ID}" 1799 >/dev/null
PACKAGE_AT_1799="$("${HARNESS_ENV[@]}" php tests/Live/p5d-k5-managed-state.php state "${OWNER_ID}" "${KEY_ID}")"
assert_equal 1799 "$(printf '%s' "${PACKAGE_AT_1799}" | json_value membership_confirmed_age)" 'managed grace age before 1799-second request'
assert_equal 200 "$(hmac_status)" '1799-second managed grace status'
start_clock_second
"${HARNESS_ENV[@]}" php tests/Live/p5d-k5-managed-state.php age "${OWNER_ID}" "${KEY_ID}" 1800 >/dev/null
PACKAGE_AT_1800="$("${HARNESS_ENV[@]}" php tests/Live/p5d-k5-managed-state.php state "${OWNER_ID}" "${KEY_ID}")"
assert_equal 1800 "$(printf '%s' "${PACKAGE_AT_1800}" | json_value membership_confirmed_age)" 'managed grace age before 1800-second request'
assert_equal 401 "$(hmac_status)" '1800-second managed grace status'

stop_bfc
start_bfc
start_scalpels
"${HARNESS_ENV[@]}" php tests/Live/p5d-k5-managed-state.php age "${OWNER_ID}" "${KEY_ID}" 300 >/dev/null
assert_equal 200 "$(hmac_status)" 'restored real-authority confirmation status'
AUTHORITY_AFTER_RESTORE="$(APP_URL="${SCALPELS_BASE}" php tests/Live/p5d-k5-real-scalpels-state.php \
    "${SCALPELS_ROOT}" "${ORGANIZATION_ID}" "${SCALPELS_ID}" "${CONNECTION_ID}" state)"
assert_equal 2 "$(printf '%s' "${AUTHORITY_AFTER_RESTORE}" | json_value response_sequence)" 'restored real-authority sequence'
PACKAGE_AFTER_RESTORE="$("${HARNESS_ENV[@]}" php tests/Live/p5d-k5-managed-state.php state "${OWNER_ID}" "${KEY_ID}")"
assert_equal 2 "$(printf '%s' "${PACKAGE_AFTER_RESTORE}" | json_value response_sequence)" 'package restored sequence'
assert_equal yes "$(printf '%s' "${PACKAGE_AFTER_RESTORE}" | json_value confirmation_reset)" 'restored confirmation reset timestamp'

stop_bfc
start_bfc
REMOVED="$(APP_URL="${SCALPELS_BASE}" php tests/Live/p5d-k5-real-scalpels-state.php \
    "${SCALPELS_ROOT}" "${ORGANIZATION_ID}" "${SCALPELS_ID}" "${CONNECTION_ID}" remove)"
assert_equal removed "$(printf '%s' "${REMOVED}" | json_value membership)" 'real Scalpels membership removal'
"${HARNESS_ENV[@]}" php tests/Live/p5d-k5-managed-state.php age "${OWNER_ID}" "${KEY_ID}" 300 >/dev/null
assert_equal 401 "$(hmac_status)" 'authoritative-removal managed HMAC status'
PACKAGE_REMOVED="$("${HARNESS_ENV[@]}" php tests/Live/p5d-k5-managed-state.php state "${OWNER_ID}" "${KEY_ID}")"
assert_equal removed "$(printf '%s' "${PACKAGE_REMOVED}" | json_value membership_status)" 'package authoritative membership state'
assert_equal active "$(printf '%s' "${PACKAGE_REMOVED}" | json_value credential_status)" 'same HMAC credential retained lifecycle status'
assert_equal yes "$(printf '%s' "${PACKAGE_REMOVED}" | json_value credential_revoked)" 'same HMAC credential revoked timestamp'

printf 'P5d K5 managed live-verified against real Scalpels\nstamp: %s\nscalpels_sha: %s\ntransport: private-CA TLS on authority %s and BFC %s\nchecks: same personal HMAC credential fresh=200, real confirmation=200, outage grace 1799=200, outage boundary 1800=401, restored confirmation=200, real Scalpels membership removal=401 and credential revoked\n' \
    "${STAMP}" "${P5D_K5_SCALPELS_SHA:-unknown}" "${SCALPELS_BASE}" "${BFC_BASE}"
