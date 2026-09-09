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

assert_bearer_absent_from_session() {
    local bearer="$1"
    local cookie_file="$2"
    local label="$3"
    local state

    if ! state="$(printf '%s' "${bearer}" | "${HARNESS_ENV[@]}" php tests/Live/bearer-session-diagnostics.php "${cookie_file}")"; then
        fail "${label}: observed [${state}]"
    fi

    assert_equal \
        "session_found=yes payload_decoded=yes bearer_absent=yes old_input_token_absent=yes previous_url_bearer_absent=yes" \
        "${state}" \
        "${label}"
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

    if ! result="$(curl --silent --show-error --output "${output}" --write-out $'%{http_code}\n%{redirect_url}\n%header{x-bfc-harness-mail}' "$@")"; then
        fail "${label}: curl failed"
    fi

    status="${result%%$'\n'*}"
    result="${result#*$'\n'}"
    redirect="${result%%$'\n'*}"
    LAST_HARNESS_MAIL="${result#*$'\n'}"

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
RESET_COOKIE="${RUN_DIR}/reset.cookies"
OLD_PASSWORD_COOKIE="${RUN_DIR}/old-password.cookies"
NEW_PASSWORD_COOKIE="${RUN_DIR}/new-password.cookies"

request "owner login page" 200 "${RUN_DIR}/owner-login.html" --cookie "${COOKIE}" --cookie-jar "${COOKIE}" "${BASE}/bfc/login"
assert_file_contains "${RUN_DIR}/owner-login.html" 'data-testid="login-form"' "owner login structure"
CSRF="$(csrf_from_file "${RUN_DIR}/owner-login.html")"
assert_nonempty "${CSRF}" "owner login CSRF token"

request "owner wrong password" 302 "${RUN_DIR}/owner-login-failed.html" --cookie "${COOKIE}" --cookie-jar "${COOKIE}" \
    --data-urlencode "_token=${CSRF}" --data-urlencode "email=owner@example.test" --data-urlencode "password=wrong-password" \
    "${BASE}/bfc/login"

request "owner login retry page" 200 "${RUN_DIR}/owner-login-retry.html" --cookie "${COOKIE}" --cookie-jar "${COOKIE}" "${BASE}/bfc/login"
assert_file_contains "${RUN_DIR}/owner-login-retry.html" 'data-testid="login-errors"' "wrong-password refusal error"
request "owner protected refusal after wrong password" 302 "${RUN_DIR}/owner-wrong-password-domain.html" --cookie "${COOKIE}" "${BASE}/domain"
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
request "Owner issues invitation through UI" 302 "${RUN_DIR}/invitation-issued.html" --cookie "${COOKIE}" --cookie-jar "${COOKIE}" \
    --data-urlencode "_token=${MANAGE_TOKEN}" --data-urlencode "email=harness-invitee@example.test" --data-urlencode "role=admin" \
    "${BASE}/bfc/members/invitations"
INVITE_URL="${LAST_HARNESS_MAIL}"
assert_nonempty "${INVITE_URL}" "array-mail invitation URL"
request "Owner listing after invitation" 200 "${RUN_DIR}/owner-members-invited.html" --cookie "${COOKIE}" "${BASE}/bfc/members"
assert_file_contains "${RUN_DIR}/owner-members-invited.html" 'data-testid="members-pending-invitations"' "pending invitation structure"
assert_file_contains "${RUN_DIR}/owner-members-invited.html" 'harness-invitee@example.test' "pending test-created invitation"
request "Owner promotes Member" 302 "${RUN_DIR}/promote.html" --cookie "${COOKIE}" --cookie-jar "${COOKIE}" \
    --data-urlencode "_token=${MANAGE_TOKEN}" --data-urlencode "_method=PUT" --data-urlencode "role=admin" \
    "${BASE}/bfc/members/${MEMBER_ID}/role"

request "Owner member listing after promote" 200 "${RUN_DIR}/owner-members-promoted.html" --cookie "${COOKIE}" "${BASE}/bfc/members"
request "promoted Member state" 200 "${RUN_DIR}/member-promoted.json" "${BASE}/_bfc-harness/users/${MEMBER_ID}"
assert_file_contains "${RUN_DIR}/member-promoted.json" 'member@example.test' "promoted test-created member"
assert_file_contains "${RUN_DIR}/member-promoted.json" '"role":"admin"' "promoted Member role"
MANAGE_TOKEN="$(csrf_from_file "${RUN_DIR}/owner-members-promoted.html")"
assert_nonempty "${MANAGE_TOKEN}" "Owner demotion CSRF token"
request "Owner demotes Member" 302 "${RUN_DIR}/demote.html" --cookie "${COOKIE}" --cookie-jar "${COOKIE}" \
    --data-urlencode "_token=${MANAGE_TOKEN}" --data-urlencode "_method=PUT" --data-urlencode "role=member" \
    "${BASE}/bfc/members/${MEMBER_ID}/role"
request "demoted Member state" 200 "${RUN_DIR}/member-demoted.json" "${BASE}/_bfc-harness/users/${MEMBER_ID}"
assert_file_contains "${RUN_DIR}/member-demoted.json" 'member@example.test' "demoted test-created member"
assert_file_contains "${RUN_DIR}/member-demoted.json" '"role":"member"' "demoted Member role"

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

request "invitation page" 200 "${RUN_DIR}/invitation.html" --cookie "${INVITEE_COOKIE}" --cookie-jar "${INVITEE_COOKIE}" "${INVITE_URL}"
assert_file_contains "${RUN_DIR}/invitation.html" 'data-testid="invitation-accept-form"' "invitation structure"
assert_file_contains "${RUN_DIR}/invitation.html" 'harness-invitee@example.test' "test-created invitation address"
INVITE_TOKEN="${INVITE_URL%%\?*}"
INVITE_TOKEN="${INVITE_TOKEN##*/}"
INVITE_CSRF="$(csrf_from_file "${RUN_DIR}/invitation.html")"
assert_nonempty "${INVITE_TOKEN}" "invitation token"
assert_nonempty "${INVITE_CSRF}" "invitation CSRF token"
request "invitation correctable validation error" 302 "${RUN_DIR}/invitation-invalid.html" --cookie "${INVITEE_COOKIE}" --cookie-jar "${INVITEE_COOKIE}" \
    --referer "${INVITE_URL}" --data-urlencode "_token=${INVITE_CSRF}" --data-urlencode "token=${INVITE_TOKEN}" \
    --data-urlencode "name=Harness Invitee" --data-urlencode "password=short" --data-urlencode "password_confirmation=mismatch" \
    "${BASE}/bfc/invitations/accept"
assert_bearer_absent_from_session "${INVITE_TOKEN}" "${INVITEE_COOKIE}" "invitation validation session secrecy"
request "invitation retry page" 200 "${RUN_DIR}/invitation-retry.html" --cookie "${INVITEE_COOKIE}" --cookie-jar "${INVITEE_COOKIE}" "${INVITE_URL}"
assert_file_contains "${RUN_DIR}/invitation-retry.html" 'data-testid="invitation-accept-errors"' "invitation correctable validation error"
assert_bearer_absent_from_session "${INVITE_TOKEN}" "${INVITEE_COOKIE}" "invitation retry page session secrecy"
INVITE_CSRF="$(csrf_from_file "${RUN_DIR}/invitation-retry.html")"
assert_nonempty "${INVITE_CSRF}" "invitation retry CSRF token"
request "invitation acceptance" 302 "${RUN_DIR}/invitation-accepted.html" --cookie "${INVITEE_COOKIE}" --cookie-jar "${INVITEE_COOKIE}" \
    --data-urlencode "_token=${INVITE_CSRF}" --data-urlencode "token=${INVITE_TOKEN}" --data-urlencode "name=Harness Invitee" \
    --data-urlencode "password=harness invitee password" --data-urlencode "password_confirmation=harness invitee password" \
    "${BASE}/bfc/invitations/accept"
INVITEE_SESSION_STATE="$("${HARNESS_ENV[@]}" php tests/Live/session-diagnostics.php harness-invitee@example.test "${INVITEE_COOKIE}")"
if [[ "${INVITEE_SESSION_STATE}" != sessions=1\ marked=1\ version_match=1\ auth_match=1\ cookie_match=yes* ]]; then
    fail "accepted invitee session persistence: expected one marked session, observed [${INVITEE_SESSION_STATE}]"
fi
request "accepted invitee domain" 200 "${RUN_DIR}/invitee-domain.html" --cookie "${INVITEE_COOKIE}" "${BASE}/domain"

request "password request page" 200 "${RUN_DIR}/password-request.html" --cookie "${RESET_COOKIE}" --cookie-jar "${RESET_COOKIE}" "${BASE}/bfc/forgot-password"
RESET_REQUEST_CSRF="$(csrf_from_file "${RUN_DIR}/password-request.html")"
assert_nonempty "${RESET_REQUEST_CSRF}" "password request CSRF token"
request "password reset request through UI" 302 "${RUN_DIR}/password-requested.html" --cookie "${RESET_COOKIE}" --cookie-jar "${RESET_COOKIE}" \
    --data-urlencode "_token=${RESET_REQUEST_CSRF}" --data-urlencode "email=member@example.test" "${BASE}/bfc/forgot-password"
RESET_URL="${LAST_HARNESS_MAIL}"
assert_nonempty "${RESET_URL}" "array-mail reset URL"
request "password reset page" 200 "${RUN_DIR}/reset.html" --cookie "${RESET_COOKIE}" --cookie-jar "${RESET_COOKIE}" "${RESET_URL}"
assert_file_contains "${RUN_DIR}/reset.html" 'data-testid="password-reset-form"' "password reset structure"
assert_file_contains "${RUN_DIR}/reset.html" 'member@example.test' "test-created reset address"
RESET_TOKEN="${RESET_URL%%\?*}"
RESET_TOKEN="${RESET_TOKEN##*/}"
RESET_CSRF="$(csrf_from_file "${RUN_DIR}/reset.html")"
assert_nonempty "${RESET_TOKEN}" "password reset token"
assert_nonempty "${RESET_CSRF}" "password reset CSRF token"
request "password reset correctable validation error" 302 "${RUN_DIR}/reset-invalid.html" --cookie "${RESET_COOKIE}" --cookie-jar "${RESET_COOKIE}" \
    --referer "${RESET_URL}" --data-urlencode "_token=${RESET_CSRF}" --data-urlencode "token=${RESET_TOKEN}" \
    --data-urlencode "email=member@example.test" --data-urlencode "password=short" --data-urlencode "password_confirmation=mismatch" \
    "${BASE}/bfc/reset-password"
assert_bearer_absent_from_session "${RESET_TOKEN}" "${RESET_COOKIE}" "password reset validation session secrecy"
request "password reset retry page" 200 "${RUN_DIR}/reset-retry.html" --cookie "${RESET_COOKIE}" --cookie-jar "${RESET_COOKIE}" "${RESET_URL}"
assert_file_contains "${RUN_DIR}/reset-retry.html" 'data-testid="password-reset-errors"' "password reset correctable validation error"
assert_bearer_absent_from_session "${RESET_TOKEN}" "${RESET_COOKIE}" "password reset retry page session secrecy"
RESET_CSRF="$(csrf_from_file "${RUN_DIR}/reset-retry.html")"
assert_nonempty "${RESET_CSRF}" "password reset retry CSRF token"
request "password reset" 302 "${RUN_DIR}/reset-complete.html" --cookie "${RESET_COOKIE}" --cookie-jar "${RESET_COOKIE}" \
    --data-urlencode "_token=${RESET_CSRF}" --data-urlencode "token=${RESET_TOKEN}" --data-urlencode "email=member@example.test" \
    --data-urlencode "password=harness reset password" --data-urlencode "password_confirmation=harness reset password" \
    "${BASE}/bfc/reset-password"
request "stale Member session after reset" 302 "${RUN_DIR}/member-domain-after-reset.html" --cookie "${MEMBER_COOKIE}" "${BASE}/domain"

request "old-password login page" 200 "${RUN_DIR}/old-password-login.html" --cookie "${OLD_PASSWORD_COOKIE}" --cookie-jar "${OLD_PASSWORD_COOKIE}" "${BASE}/bfc/login"
OLD_PASSWORD_TOKEN="$(csrf_from_file "${RUN_DIR}/old-password-login.html")"
assert_nonempty "${OLD_PASSWORD_TOKEN}" "old-password login CSRF token"
request "old password refusal" 302 "${RUN_DIR}/old-password-refused.html" --cookie "${OLD_PASSWORD_COOKIE}" --cookie-jar "${OLD_PASSWORD_COOKIE}" \
    --data-urlencode "_token=${OLD_PASSWORD_TOKEN}" --data-urlencode "email=member@example.test" \
    --data-urlencode "password=harness owner password" "${BASE}/bfc/login"
request "old password error page" 200 "${RUN_DIR}/old-password-error.html" --cookie "${OLD_PASSWORD_COOKIE}" --cookie-jar "${OLD_PASSWORD_COOKIE}" "${BASE}/bfc/login"
assert_file_contains "${RUN_DIR}/old-password-error.html" 'data-testid="login-errors"' "old password refusal error"
request "old password protected refusal" 302 "${RUN_DIR}/old-password-domain.html" --cookie "${OLD_PASSWORD_COOKIE}" "${BASE}/domain"

request "new-password login page" 200 "${RUN_DIR}/new-password-login.html" --cookie "${NEW_PASSWORD_COOKIE}" --cookie-jar "${NEW_PASSWORD_COOKIE}" "${BASE}/bfc/login"
NEW_PASSWORD_TOKEN="$(csrf_from_file "${RUN_DIR}/new-password-login.html")"
assert_nonempty "${NEW_PASSWORD_TOKEN}" "new-password login CSRF token"
request "new password login" 302 "${RUN_DIR}/new-password-success.html" --cookie "${NEW_PASSWORD_COOKIE}" --cookie-jar "${NEW_PASSWORD_COOKIE}" \
    --data-urlencode "_token=${NEW_PASSWORD_TOKEN}" --data-urlencode "email=member@example.test" \
    --data-urlencode "password=harness reset password" "${BASE}/bfc/login"
request "new password protected access" 200 "${RUN_DIR}/new-password-domain.html" --cookie "${NEW_PASSWORD_COOKIE}" "${BASE}/domain"

for TARGET_COOKIE in "${INVITEE_COOKIE}" "${OTHER_COOKIE}"; do
    TARGET_NAME="$(basename "${TARGET_COOKIE}" .cookies)"
    request "${TARGET_NAME} login page" 200 "${RUN_DIR}/${TARGET_NAME}-login.html" --cookie "${TARGET_COOKIE}" --cookie-jar "${TARGET_COOKIE}" "${BASE}/bfc/login"
    TARGET_TOKEN="$(csrf_from_file "${RUN_DIR}/${TARGET_NAME}-login.html")"
    assert_nonempty "${TARGET_TOKEN}" "${TARGET_NAME} login CSRF token"
    request "${TARGET_NAME} login" 302 "${RUN_DIR}/${TARGET_NAME}-login-success.html" --cookie "${TARGET_COOKIE}" --cookie-jar "${TARGET_COOKIE}" \
        --user-agent "bfc-harness-${TARGET_NAME}-${STAMP}" \
        --data-urlencode "_token=${TARGET_TOKEN}" --data-urlencode "email=harness-invitee@example.test" \
        --data-urlencode "password=harness invitee password" "${BASE}/bfc/login"
done

request "session listing" 200 "${RUN_DIR}/sessions.html" --cookie "${INVITEE_COOKIE}" --user-agent "bfc-harness-invitee-${STAMP}" "${BASE}/bfc/me/sessions"
assert_file_contains "${RUN_DIR}/sessions.html" 'data-testid="sessions-management"' "session listing structure"
assert_file_contains "${RUN_DIR}/sessions.html" 'data-testid="sessions-current"' "current session marker"
assert_file_contains "${RUN_DIR}/sessions.html" "bfc-harness-invitee-${STAMP}" "test-created current session content"
assert_file_contains "${RUN_DIR}/sessions.html" "bfc-harness-other-${STAMP}" "test-created other session content"
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

printf 'standalone live harness passed\nstamp: %s\nchecks: wrong-password refusal/login success, Member denial, persisted Owner/Admin boundaries, HTTP array-mail invitation/reset delivery, validation-error session secrecy and retry, acceptance, reset old/stale refusal and new-password success, current/other session content and revocation, logout, managed refusal\n' "${STAMP}"
