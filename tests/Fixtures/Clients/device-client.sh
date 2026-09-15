#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    printf '%s\n' 'usage: device-client.sh <base-url> <bearer-file>' >&2
    exit 2
fi

base_url=${1%/}
bearer_file=$2
IFS= read -r device_code

case "$device_code" in
    ''|*[!A-Za-z0-9_-]*) printf '%s\n' 'invalid device code on stdin' >&2; exit 2 ;;
esac

if [ "${#device_code}" -ne 43 ]; then
    printf '%s\n' 'invalid device code on stdin' >&2
    exit 2
fi

private_dir=$(dirname "$bearer_file")
mkdir -p "$private_dir"
chmod 700 "$private_dir"
body=$(mktemp "$private_dir/.bfc-device-body.XXXXXX")
headers=$(mktemp "$private_dir/.bfc-device-headers.XXXXXX")
chmod 600 "$body" "$headers"
cleanup() {
    rm -f "$body" "$headers"
    unset device_code access_token
}
trap cleanup EXIT HUP INT TERM

interval=5
attempt=0
while [ "$attempt" -lt 180 ]; do
    attempt=$((attempt + 1))
    : > "$body"
    : > "$headers"
    curl --silent --show-error --dump-header "$headers" --output "$body" --config - <<EOF
url = "$base_url/bfc/device/token"
request = "POST"
header = "Content-Type: application/json"
data = "{\"device_code\":\"$device_code\"}"
EOF

    error=$(php -r '$j=json_decode(stream_get_contents(STDIN), true); echo is_array($j) && is_string($j["error"] ?? null) ? $j["error"] : "";' < "$body")

    if [ -z "$error" ]; then
        : > "$bearer_file"
        chmod 600 "$bearer_file"
        php -r '$j=json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR); if (!is_string($j["access_token"] ?? null) || $j["access_token"] === "") { exit(2); } fwrite(STDOUT, $j["access_token"].PHP_EOL);' < "$body" > "$bearer_file"
        exit 0
    fi

    case "$error" in
        authorization_pending|slow_down|temporarily_unavailable) ;;
        access_denied|expired_token|invalid_grant|invalid_request) exit 1 ;;
        *) exit 1 ;;
    esac

    returned=$(php -r '$j=json_decode(stream_get_contents(STDIN), true); $n=$j["interval"] ?? 0; echo is_int($n) && $n >= 1 && $n <= 30 ? $n : 0;' < "$body")
    retry=$(php -r '$n=0; foreach (file("php://stdin") ?: [] as $line) { if (stripos($line, "Retry-After:") === 0) { $v=trim(substr($line, 12)); if (ctype_digit($v)) { $n=(int)$v; } } } echo $n >= 1 && $n <= 30 ? $n : 0;' < "$headers")

    if [ "$error" = temporarily_unavailable ] && [ "$retry" -eq 0 ]; then retry=5; fi
    if [ "$returned" -gt "$interval" ]; then interval=$returned; fi
    if [ "$retry" -gt "$interval" ]; then interval=$retry; fi
    sleep "$interval"
done

exit 1
