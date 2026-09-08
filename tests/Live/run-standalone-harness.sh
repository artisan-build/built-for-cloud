#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DB="/tmp/bfc-standalone-harness.sqlite"
COOKIE="/tmp/bfc-standalone-harness.cookies"
ADMIN_COOKIE="/tmp/bfc-standalone-harness-admin.cookies"
MEMBER_COOKIE="/tmp/bfc-standalone-harness-member.cookies"
INVITEE_COOKIE="/tmp/bfc-standalone-harness-invitee.cookies"
OTHER_COOKIE="/tmp/bfc-standalone-harness-other.cookies"
SERVER_LOG="/tmp/bfc-standalone-harness-server.log"
PORT="${BFC_HARNESS_PORT:-8187}"
BASE="http://127.0.0.1:${PORT}"

cleanup() {
    if [[ -n "${SERVER_PID:-}" ]]; then kill "${SERVER_PID}" 2>/dev/null || true; fi
    rm -f "${DB}" "${COOKIE}" "${ADMIN_COOKIE}" "${MEMBER_COOKIE}" "${INVITEE_COOKIE}" "${OTHER_COOKIE}" "${SERVER_LOG}"
}
trap cleanup EXIT

rm -f "${DB}" "${COOKIE}" "${ADMIN_COOKIE}" "${MEMBER_COOKIE}" "${INVITEE_COOKIE}" "${OTHER_COOKIE}" "${SERVER_LOG}"
touch "${DB}"

cd "${ROOT}"
DB_DATABASE="${DB}" APP_URL="${BASE}" vendor/bin/testbench migrate:fresh --force --no-interaction >/dev/null
read -r OWNER_ID ADMIN_ID MEMBER_ID < <(DB_DATABASE="${DB}" APP_URL="${BASE}" php tests/Live/seed-standalone-harness.php)
DB_DATABASE="${DB}" APP_URL="${BASE}" vendor/bin/testbench serve --host=127.0.0.1 --port="${PORT}" >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!

for _ in {1..40}; do
    if curl --silent --fail "${BASE}/bfc/login" >/dev/null; then break; fi
    sleep 0.1
done

LOGIN_PAGE="$(curl --silent --show-error --cookie "${COOKIE}" --cookie-jar "${COOKIE}" "${BASE}/bfc/login")"
CSRF="$(printf '%s' "${LOGIN_PAGE}" | perl -ne 'print $1 if /name="_token" value="([^"]+)"/')"
[[ "${LOGIN_PAGE}" == *'data-testid="login-form"'* ]]

FAIL_CODE="$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "${COOKIE}" --cookie-jar "${COOKIE}" \
    --data-urlencode "_token=${CSRF}" --data-urlencode "email=owner@example.test" --data-urlencode "password=wrong-password" \
    "${BASE}/bfc/login")"
[[ "${FAIL_CODE}" == "302" ]]

LOGIN_PAGE="$(curl --silent --show-error --cookie "${COOKIE}" --cookie-jar "${COOKIE}" "${BASE}/bfc/login")"
CSRF="$(printf '%s' "${LOGIN_PAGE}" | perl -ne 'print $1 if /name="_token" value="([^"]+)"/')"
SUCCESS_CODE="$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "${COOKIE}" --cookie-jar "${COOKIE}" \
    --data-urlencode "_token=${CSRF}" --data-urlencode "email=owner@example.test" \
    --data-urlencode "password=harness owner password" "${BASE}/bfc/login")"
[[ "${SUCCESS_CODE}" == "302" ]]

MEMBERS="$(curl --silent --show-error --cookie "${COOKIE}" "${BASE}/bfc/members")"
[[ "${MEMBERS}" == *'data-testid="members-management"'* ]]
[[ "${MEMBERS}" == *'member@example.test'* ]]

MANAGE_TOKEN="$(printf '%s' "${MEMBERS}" | perl -ne 'print $1 if /name="_token" value="([^"]+)"/')"
PROMOTE_CODE="$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "${COOKIE}" --cookie-jar "${COOKIE}" \
    --data-urlencode "_token=${MANAGE_TOKEN}" --data-urlencode "_method=PUT" --data-urlencode "role=admin" \
    "${BASE}/bfc/members/${MEMBER_ID}/role")"
[[ "${PROMOTE_CODE}" == "302" ]]
MEMBERS="$(curl --silent --show-error --cookie "${COOKIE}" "${BASE}/bfc/members")"
MANAGE_TOKEN="$(printf '%s' "${MEMBERS}" | perl -ne 'print $1 if /name="_token" value="([^"]+)"/')"
DEMOTE_CODE="$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "${COOKIE}" --cookie-jar "${COOKIE}" \
    --data-urlencode "_token=${MANAGE_TOKEN}" --data-urlencode "_method=PUT" --data-urlencode "role=member" \
    "${BASE}/bfc/members/${MEMBER_ID}/role")"
[[ "${DEMOTE_CODE}" == "302" ]]

ADMIN_PAGE="$(curl --silent --show-error --cookie-jar "${ADMIN_COOKIE}" "${BASE}/bfc/login")"
ADMIN_TOKEN="$(printf '%s' "${ADMIN_PAGE}" | perl -ne 'print $1 if /name="_token" value="([^"]+)"/')"
curl --silent --output /dev/null --cookie "${ADMIN_COOKIE}" --cookie-jar "${ADMIN_COOKIE}" \
    --data-urlencode "_token=${ADMIN_TOKEN}" --data-urlencode "email=admin@example.test" \
    --data-urlencode "password=harness owner password" "${BASE}/bfc/login"
ADMIN_MEMBERS="$(curl --silent --show-error --cookie "${ADMIN_COOKIE}" "${BASE}/bfc/members")"
ADMIN_TOKEN="$(printf '%s' "${ADMIN_MEMBERS}" | perl -ne 'print $1 if /name="_token" value="([^"]+)"/')"
ADMIN_BOUNDARY="$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "${ADMIN_COOKIE}" \
    --data-urlencode "_token=${ADMIN_TOKEN}" --data-urlencode "_method=DELETE" "${BASE}/bfc/members/${ADMIN_ID}")"
[[ "${ADMIN_BOUNDARY}" == "403" ]]

MEMBER_PAGE="$(curl --silent --show-error --cookie-jar "${MEMBER_COOKIE}" "${BASE}/bfc/login")"
MEMBER_TOKEN="$(printf '%s' "${MEMBER_PAGE}" | perl -ne 'print $1 if /name="_token" value="([^"]+)"/')"
curl --silent --output /dev/null --cookie "${MEMBER_COOKIE}" --cookie-jar "${MEMBER_COOKIE}" \
    --data-urlencode "_token=${MEMBER_TOKEN}" --data-urlencode "email=member@example.test" \
    --data-urlencode "password=harness owner password" "${BASE}/bfc/login"
MEMBER_VIEW="$(curl --silent --show-error --cookie "${MEMBER_COOKIE}" "${BASE}/bfc/members")"
MEMBER_TOKEN="$(printf '%s' "${MEMBER_VIEW}" | perl -ne 'print $1 if /name="_token" value="([^"]+)"/')"
MEMBER_DENIAL="$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "${MEMBER_COOKIE}" \
    --data-urlencode "_token=${MEMBER_TOKEN}" --data-urlencode "email=blocked@example.test" --data-urlencode "role=member" \
    "${BASE}/bfc/members/invitations")"
[[ "${MEMBER_DENIAL}" == "403" ]]

INVITE_URL="$(DB_DATABASE="${DB}" APP_URL="${BASE}" php tests/Live/mail-link.php invitation harness-invitee@example.test)"
INVITE_PAGE="$(curl --silent --show-error --cookie-jar "${INVITEE_COOKIE}" "${INVITE_URL}")"
INVITE_TOKEN="${INVITE_URL%%\?*}"
INVITE_TOKEN="${INVITE_TOKEN##*/}"
INVITE_CSRF="$(printf '%s' "${INVITE_PAGE}" | perl -ne 'print $1 if /name="_token" value="([^"]+)"/')"
ACCEPT_RESULT="$(curl --silent --output /dev/null --write-out $'%{http_code}\n%{redirect_url}' --cookie "${INVITEE_COOKIE}" --cookie-jar "${INVITEE_COOKIE}" \
    --data-urlencode "_token=${INVITE_CSRF}" --data-urlencode "token=${INVITE_TOKEN}" --data-urlencode "name=Harness Invitee" \
    --data-urlencode "password=harness invitee password" --data-urlencode "password_confirmation=harness invitee password" \
    "${BASE}/bfc/invitations/accept")"
ACCEPT_CODE="${ACCEPT_RESULT%%$'\n'*}"
ACCEPT_REDIRECT="${ACCEPT_RESULT#*$'\n'}"
[[ "${ACCEPT_CODE}" == "302" ]]
[[ "${ACCEPT_REDIRECT}" == "${BASE}/" ]]
ACCEPTED_DOMAIN="$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "${INVITEE_COOKIE}" "${BASE}/domain")"
[[ "${ACCEPTED_DOMAIN}" == "200" ]]

RESET_URL="$(DB_DATABASE="${DB}" APP_URL="${BASE}" php tests/Live/mail-link.php reset member@example.test)"
RESET_PAGE="$(curl --silent --show-error --cookie "${INVITEE_COOKIE}" --cookie-jar "${INVITEE_COOKIE}" "${RESET_URL}")"
RESET_TOKEN="${RESET_URL%%\?*}"
RESET_TOKEN="${RESET_TOKEN##*/}"
RESET_CSRF="$(printf '%s' "${RESET_PAGE}" | perl -ne 'print $1 if /name="_token" value="([^"]+)"/')"
RESET_CODE="$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "${INVITEE_COOKIE}" --cookie-jar "${INVITEE_COOKIE}" \
    --data-urlencode "_token=${RESET_CSRF}" --data-urlencode "token=${RESET_TOKEN}" --data-urlencode "email=member@example.test" \
    --data-urlencode "password=harness reset password" --data-urlencode "password_confirmation=harness reset password" \
    "${BASE}/bfc/reset-password")"
[[ "${RESET_CODE}" == "302" ]]

for TARGET_COOKIE in "${INVITEE_COOKIE}" "${OTHER_COOKIE}"; do
    TARGET_PAGE="$(curl --silent --show-error --cookie-jar "${TARGET_COOKIE}" "${BASE}/bfc/login")"
    TARGET_TOKEN="$(printf '%s' "${TARGET_PAGE}" | perl -ne 'print $1 if /name="_token" value="([^"]+)"/')"
    curl --silent --output /dev/null --cookie "${TARGET_COOKIE}" --cookie-jar "${TARGET_COOKIE}" \
        --data-urlencode "_token=${TARGET_TOKEN}" --data-urlencode "email=harness-invitee@example.test" \
        --data-urlencode "password=harness invitee password" "${BASE}/bfc/login"
done

SESSIONS_PAGE="$(curl --silent --show-error --cookie "${INVITEE_COOKIE}" "${BASE}/bfc/me/sessions")"
[[ "${SESSIONS_PAGE}" == *'data-testid="sessions-current"'* ]]
SESSIONS_TOKEN="$(printf '%s' "${SESSIONS_PAGE}" | perl -ne 'print $1 if /name="_token" value="([^"]+)"/')"
REVOKE_CODE="$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "${INVITEE_COOKIE}" --cookie-jar "${INVITEE_COOKIE}" \
    --data-urlencode "_token=${SESSIONS_TOKEN}" --data-urlencode "_method=DELETE" --data-urlencode "password=harness invitee password" \
    "${BASE}/bfc/me/sessions/others")"
[[ "${REVOKE_CODE}" == "302" ]]
REVOKED_OTHER="$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "${OTHER_COOKIE}" "${BASE}/domain")"
[[ "${REVOKED_OTHER}" == "302" ]]

DOMAIN_CODE="$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "${COOKIE}" "${BASE}/domain")"
[[ "${DOMAIN_CODE}" == "200" ]]

LOGOUT_TOKEN="$(printf '%s' "${MEMBERS}" | perl -ne 'print $1 if /name="_token" value="([^"]+)"/')"
LOGOUT_CODE="$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "${COOKIE}" --cookie-jar "${COOKIE}" \
    --data-urlencode "_token=${LOGOUT_TOKEN}" "${BASE}/bfc/logout")"
[[ "${LOGOUT_CODE}" == "302" ]]

AFTER_LOGOUT="$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "${COOKIE}" "${BASE}/domain")"
[[ "${AFTER_LOGOUT}" == "302" ]]

DB_DATABASE="${DB}" APP_URL="${BASE}" php tests/Live/set-managed-authority.php
MANAGED_CODE="$(curl --silent --output /dev/null --write-out '%{http_code}' "${BASE}/bfc/login")"
[[ "${MANAGED_CODE}" == "404" ]]

printf 'standalone live harness passed: login failure/success, Member denial, Owner/Admin boundaries, array-mail invitation/reset delivery, acceptance, session revocation, logout, managed refusal\n'
