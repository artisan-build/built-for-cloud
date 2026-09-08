#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/bfc-standalone-harness.XXXXXX")"
DB="${RUN_DIR}/database.sqlite"
SERVER_LOG="${RUN_DIR}/server.log"
STAMP="bfc-live-$(date -u +%Y%m%dT%H%M%SZ)-$$"
PORT="$(php -r '$socket = stream_socket_server("tcp://127.0.0.1:0", $errno, $error); if ($socket === false) { fwrite(STDERR, $error); exit(1); } echo parse_url(stream_socket_get_name($socket, false), PHP_URL_PORT);')"
BASE="http://127.0.0.1:${PORT}"
EXPECT_LOGIN_STATUS="${BFC_HARNESS_EXPECT_LOGIN_STATUS:-302}"
BROWSER_MODE=false

if [[ "${1:-}" == "--serve-browser" ]]; then
    BROWSER_MODE=true
elif [[ $# -gt 0 ]]; then
    printf 'Unknown argument: %s\n' "$1" >&2
    exit 2
fi

fail() {
    printf 'standalone harness failure: %s (run directory: %s)\n' "$1" "${RUN_DIR}" >&2
    exit 1
}

assert_equal() {
    local expected="$1"
    local actual="$2"
    local label="$3"

    if [[ "${actual}" != "${expected}" ]]; then
        fail "${label}: expected [${expected}], observed [${actual}]"
    fi
}

assert_nonempty() {
    local value="$1"
    local label="$2"

    if [[ -z "${value}" ]]; then
        fail "${label}: expected a non-empty value"
    fi
}

assert_file_contains() {
    local file="$1"
    local needle="$2"
    local label="$3"

    if ! perl -0777 -e 'my ($needle, $file) = @ARGV; open my $fh, "<", $file or die $!; local $/; my $body = <$fh>; exit(index($body, $needle) < 0);' "${needle}" "${file}"; then
        fail "${label}: [${needle}] was absent from ${file}"
    fi
}

csrf_from_file() {
    perl -0777 -ne 'print $1 if /name="_token" value="([^"]+)"/' "$1"
}

request() {
    local label="$1"
    local expected="$2"
    local output="$3"
    shift 3
    local result
    local status
    local redirect

    if ! result="$(curl --silent --show-error --output "${output}" --write-out $'%{http_code}\n%{redirect_url}' "$@")"; then
        fail "${label}: curl failed"
    fi

    status="${result%%$'\n'*}"
    redirect="${result#*$'\n'}"

    if [[ "${status}" != "${expected}" ]]; then
        fail "${label} HTTP status: expected [${expected}], observed [${status}], redirect [${redirect:-none}]"
    fi
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
    "MAIL_MAILER=array"
    "BUILT_FOR_CLOUD_SURFACE_DATA_MIGRATIONS=false"
    "BFC_HARNESS_STAMP=${STAMP}"
)

cd "${ROOT}"
"${HARNESS_ENV[@]}" vendor/bin/testbench migrate:fresh --force --no-interaction >"${RUN_DIR}/migrate.log"
read -r OWNER_ID ADMIN_ID MEMBER_ID < <("${HARNESS_ENV[@]}" php tests/Live/seed-standalone-harness.php)
assert_nonempty "${OWNER_ID}" "seeded Owner id"
assert_nonempty "${ADMIN_ID}" "seeded Admin id"
assert_nonempty "${MEMBER_ID}" "seeded Member id"

"${HARNESS_ENV[@]}" vendor/bin/testbench serve --host=127.0.0.1 --port="${PORT}" >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!

READY=false
for _ in {1..80}; do
    if curl --silent --output "${RUN_DIR}/ready.html" "${BASE}/bfc/login"; then
        READY=true
        break
    fi
    if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
        fail "server exited before readiness; see ${SERVER_LOG}"
    fi
    sleep 0.1
done
assert_equal true "${READY}" "server readiness"

if [[ "${BROWSER_MODE}" == true ]]; then
    printf 'Standalone browser handoff ready\nURL: %s/bfc/login\nOwner: owner@example.test\nAdmin: admin@example.test\nMember: member@example.test\nPassword: harness owner password\nStamp: %s\nRun directory: %s\nMailer: array\nPress Ctrl-C to stop and clean up this run.\n' \
        "${BASE}" "${STAMP}" "${RUN_DIR}"
    wait "${SERVER_PID}"
    exit 0
fi

COOKIE="${RUN_DIR}/owner.cookies"
ADMIN_COOKIE="${RUN_DIR}/admin.cookies"
MEMBER_COOKIE="${RUN_DIR}/member.cookies"
INVITEE_COOKIE="${RUN_DIR}/invitee.cookies"
OTHER_COOKIE="${RUN_DIR}/other.cookies"

request "owner login page" 200 "${RUN_DIR}/owner-login.html" --cookie "${COOKIE}" --cookie-jar "${COOKIE}" "${BASE}/bfc/login"
assert_file_contains "${RUN_DIR}/owner-login.html" 'data-testid="login-form"' "owner login structure"
CSRF="$(csrf_from_file "${RUN_DIR}/owner-login.html")"
assert_nonempty "${CSRF}" "owner login CSRF token"

request "owner wrong password" 302 "${RUN_DIR}/owner-login-failed.html" --cookie "${COOKIE}" --cookie-jar "${COOKIE}" \
    --data-urlencode "_token=${CSRF}" --data-urlencode "email=owner@example.test" --data-urlencode "password=wrong-password" \
    "${BASE}/bfc/login"

request "owner login retry page" 200 "${RUN_DIR}/owner-login-retry.html" --cookie "${COOKIE}" --cookie-jar "${COOKIE}" "${BASE}/bfc/login"
CSRF="$(csrf_from_file "${RUN_DIR}/owner-login-retry.html")"
assert_nonempty "${CSRF}" "owner retry CSRF token"
request "owner successful login" "${EXPECT_LOGIN_STATUS}" "${RUN_DIR}/owner-login-success.html" --cookie "${COOKIE}" --cookie-jar "${COOKIE}" \
    --data-urlencode "_token=${CSRF}" --data-urlencode "email=owner@example.test" \
    --data-urlencode "password=harness owner password" "${BASE}/bfc/login"

request "Owner member listing" 200 "${RUN_DIR}/owner-members.html" --cookie "${COOKIE}" "${BASE}/bfc/members"
assert_file_contains "${RUN_DIR}/owner-members.html" 'data-testid="members-management"' "member listing structure"
assert_file_contains "${RUN_DIR}/owner-members.html" 'member@example.test' "seeded Member listing"
MANAGE_TOKEN="$(csrf_from_file "${RUN_DIR}/owner-members.html")"
assert_nonempty "${MANAGE_TOKEN}" "Owner member-management CSRF token"
request "Owner promotes Member" 302 "${RUN_DIR}/promote.html" --cookie "${COOKIE}" --cookie-jar "${COOKIE}" \
    --data-urlencode "_token=${MANAGE_TOKEN}" --data-urlencode "_method=PUT" --data-urlencode "role=admin" \
    "${BASE}/bfc/members/${MEMBER_ID}/role"

request "Owner member listing after promote" 200 "${RUN_DIR}/owner-members-promoted.html" --cookie "${COOKIE}" "${BASE}/bfc/members"
MANAGE_TOKEN="$(csrf_from_file "${RUN_DIR}/owner-members-promoted.html")"
assert_nonempty "${MANAGE_TOKEN}" "Owner demotion CSRF token"
request "Owner demotes Member" 302 "${RUN_DIR}/demote.html" --cookie "${COOKIE}" --cookie-jar "${COOKIE}" \
    --data-urlencode "_token=${MANAGE_TOKEN}" --data-urlencode "_method=PUT" --data-urlencode "role=member" \
    "${BASE}/bfc/members/${MEMBER_ID}/role"

request "Admin login page" 200 "${RUN_DIR}/admin-login.html" --cookie "${ADMIN_COOKIE}" --cookie-jar "${ADMIN_COOKIE}" "${BASE}/bfc/login"
ADMIN_TOKEN="$(csrf_from_file "${RUN_DIR}/admin-login.html")"
assert_nonempty "${ADMIN_TOKEN}" "Admin login CSRF token"
request "Admin login" 302 "${RUN_DIR}/admin-login-success.html" --cookie "${ADMIN_COOKIE}" --cookie-jar "${ADMIN_COOKIE}" \
    --data-urlencode "_token=${ADMIN_TOKEN}" --data-urlencode "email=admin@example.test" \
    --data-urlencode "password=harness owner password" "${BASE}/bfc/login"
request "Admin member listing" 200 "${RUN_DIR}/admin-members.html" --cookie "${ADMIN_COOKIE}" "${BASE}/bfc/members"
ADMIN_TOKEN="$(csrf_from_file "${RUN_DIR}/admin-members.html")"
assert_nonempty "${ADMIN_TOKEN}" "Admin management CSRF token"
request "Admin cannot deactivate Admin" 403 "${RUN_DIR}/admin-boundary.html" --cookie "${ADMIN_COOKIE}" \
    --data-urlencode "_token=${ADMIN_TOKEN}" --data-urlencode "_method=DELETE" "${BASE}/bfc/members/${ADMIN_ID}"

request "Member login page" 200 "${RUN_DIR}/member-login.html" --cookie "${MEMBER_COOKIE}" --cookie-jar "${MEMBER_COOKIE}" "${BASE}/bfc/login"
MEMBER_TOKEN="$(csrf_from_file "${RUN_DIR}/member-login.html")"
assert_nonempty "${MEMBER_TOKEN}" "Member login CSRF token"
request "Member login" 302 "${RUN_DIR}/member-login-success.html" --cookie "${MEMBER_COOKIE}" --cookie-jar "${MEMBER_COOKIE}" \
    --data-urlencode "_token=${MEMBER_TOKEN}" --data-urlencode "email=member@example.test" \
    --data-urlencode "password=harness owner password" "${BASE}/bfc/login"
request "Member listing" 200 "${RUN_DIR}/member-members.html" --cookie "${MEMBER_COOKIE}" "${BASE}/bfc/members"
request "Member session page" 200 "${RUN_DIR}/member-sessions.html" --cookie "${MEMBER_COOKIE}" "${BASE}/bfc/me/sessions"
MEMBER_TOKEN="$(csrf_from_file "${RUN_DIR}/member-sessions.html")"
assert_nonempty "${MEMBER_TOKEN}" "Member session CSRF token"
request "Member cannot invite" 403 "${RUN_DIR}/member-invite-denied.html" --cookie "${MEMBER_COOKIE}" \
    --data-urlencode "_token=${MEMBER_TOKEN}" --data-urlencode "email=blocked@example.test" --data-urlencode "role=member" \
    "${BASE}/bfc/members/invitations"

INVITE_URL="$("${HARNESS_ENV[@]}" php tests/Live/mail-link.php invitation harness-invitee@example.test)"
assert_nonempty "${INVITE_URL}" "array-mail invitation URL"
request "invitation page" 200 "${RUN_DIR}/invitation.html" --cookie "${INVITEE_COOKIE}" --cookie-jar "${INVITEE_COOKIE}" "${INVITE_URL}"
assert_file_contains "${RUN_DIR}/invitation.html" 'data-testid="invitation-accept-form"' "invitation structure"
assert_file_contains "${RUN_DIR}/invitation.html" 'harness-invitee@example.test' "test-created invitation address"
INVITE_TOKEN="${INVITE_URL%%\?*}"
INVITE_TOKEN="${INVITE_TOKEN##*/}"
INVITE_CSRF="$(csrf_from_file "${RUN_DIR}/invitation.html")"
assert_nonempty "${INVITE_TOKEN}" "invitation token"
assert_nonempty "${INVITE_CSRF}" "invitation CSRF token"
request "invitation acceptance" 302 "${RUN_DIR}/invitation-accepted.html" --cookie "${INVITEE_COOKIE}" --cookie-jar "${INVITEE_COOKIE}" \
    --data-urlencode "_token=${INVITE_CSRF}" --data-urlencode "token=${INVITE_TOKEN}" --data-urlencode "name=Harness Invitee" \
    --data-urlencode "password=harness invitee password" --data-urlencode "password_confirmation=harness invitee password" \
    "${BASE}/bfc/invitations/accept"
INVITEE_SESSION_STATE="$("${HARNESS_ENV[@]}" php tests/Live/session-diagnostics.php harness-invitee@example.test "${INVITEE_COOKIE}")"
if [[ "${INVITEE_SESSION_STATE}" != sessions=1\ marked=1\ version_match=1\ auth_match=1\ cookie_match=yes* ]]; then
    fail "accepted invitee session persistence: expected one marked session, observed [${INVITEE_SESSION_STATE}]"
fi
request "accepted invitee domain" 200 "${RUN_DIR}/invitee-domain.html" --cookie "${INVITEE_COOKIE}" "${BASE}/domain"

RESET_URL="$("${HARNESS_ENV[@]}" php tests/Live/mail-link.php reset member@example.test)"
assert_nonempty "${RESET_URL}" "array-mail reset URL"
request "password reset page" 200 "${RUN_DIR}/reset.html" --cookie "${INVITEE_COOKIE}" --cookie-jar "${INVITEE_COOKIE}" "${RESET_URL}"
assert_file_contains "${RUN_DIR}/reset.html" 'data-testid="password-reset-form"' "password reset structure"
assert_file_contains "${RUN_DIR}/reset.html" 'member@example.test' "test-created reset address"
RESET_TOKEN="${RESET_URL%%\?*}"
RESET_TOKEN="${RESET_TOKEN##*/}"
RESET_CSRF="$(csrf_from_file "${RUN_DIR}/reset.html")"
assert_nonempty "${RESET_TOKEN}" "password reset token"
assert_nonempty "${RESET_CSRF}" "password reset CSRF token"
request "password reset" 302 "${RUN_DIR}/reset-complete.html" --cookie "${INVITEE_COOKIE}" --cookie-jar "${INVITEE_COOKIE}" \
    --data-urlencode "_token=${RESET_CSRF}" --data-urlencode "token=${RESET_TOKEN}" --data-urlencode "email=member@example.test" \
    --data-urlencode "password=harness reset password" --data-urlencode "password_confirmation=harness reset password" \
    "${BASE}/bfc/reset-password"

for TARGET_COOKIE in "${INVITEE_COOKIE}" "${OTHER_COOKIE}"; do
    TARGET_NAME="$(basename "${TARGET_COOKIE}" .cookies)"
    request "${TARGET_NAME} login page" 200 "${RUN_DIR}/${TARGET_NAME}-login.html" --cookie "${TARGET_COOKIE}" --cookie-jar "${TARGET_COOKIE}" "${BASE}/bfc/login"
    TARGET_TOKEN="$(csrf_from_file "${RUN_DIR}/${TARGET_NAME}-login.html")"
    assert_nonempty "${TARGET_TOKEN}" "${TARGET_NAME} login CSRF token"
    request "${TARGET_NAME} login" 302 "${RUN_DIR}/${TARGET_NAME}-login-success.html" --cookie "${TARGET_COOKIE}" --cookie-jar "${TARGET_COOKIE}" \
        --data-urlencode "_token=${TARGET_TOKEN}" --data-urlencode "email=harness-invitee@example.test" \
        --data-urlencode "password=harness invitee password" "${BASE}/bfc/login"
done

request "session listing" 200 "${RUN_DIR}/sessions.html" --cookie "${INVITEE_COOKIE}" "${BASE}/bfc/me/sessions"
assert_file_contains "${RUN_DIR}/sessions.html" 'data-testid="sessions-management"' "session listing structure"
SESSIONS_TOKEN="$(csrf_from_file "${RUN_DIR}/sessions.html")"
assert_nonempty "${SESSIONS_TOKEN}" "session revocation CSRF token"
request "revoke other sessions" 302 "${RUN_DIR}/sessions-revoked.html" --cookie "${INVITEE_COOKIE}" --cookie-jar "${INVITEE_COOKIE}" \
    --data-urlencode "_token=${SESSIONS_TOKEN}" --data-urlencode "_method=DELETE" --data-urlencode "password=harness invitee password" \
    "${BASE}/bfc/me/sessions/others"
request "revoked other session" 302 "${RUN_DIR}/other-domain-revoked.html" --cookie "${OTHER_COOKIE}" "${BASE}/domain"
request "Owner domain" 200 "${RUN_DIR}/owner-domain.html" --cookie "${COOKIE}" "${BASE}/domain"

LOGOUT_TOKEN="$(csrf_from_file "${RUN_DIR}/owner-members-promoted.html")"
assert_nonempty "${LOGOUT_TOKEN}" "Owner logout CSRF token"
request "Owner logout" 302 "${RUN_DIR}/owner-logout.html" --cookie "${COOKIE}" --cookie-jar "${COOKIE}" \
    --data-urlencode "_token=${LOGOUT_TOKEN}" "${BASE}/bfc/logout"
request "Owner domain after logout" 302 "${RUN_DIR}/owner-domain-logged-out.html" --cookie "${COOKIE}" "${BASE}/domain"

"${HARNESS_ENV[@]}" php tests/Live/set-managed-authority.php
request "managed-mode standalone refusal" 404 "${RUN_DIR}/managed-login.html" "${BASE}/bfc/login"

printf 'standalone live harness passed\nstamp: %s\nchecks: login failure/success, Member denial, Owner/Admin boundaries, array-mail invitation/reset delivery, acceptance, session revocation, logout, managed refusal\n' "${STAMP}"
