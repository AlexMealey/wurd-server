#!/usr/bin/env bash
# End-to-end tests for the Wurd server. Starts a throwaway container from the wurd-server image with
# small limits, checks the API and every security rule in PLAN.md, then removes the container.
#
#   docker build -t wurd-server . && tests/smoke.sh
#
# Needs bash, curl and docker.
set -euo pipefail

IMAGE=${IMAGE:-wurd-server}
PORT=${PORT:-18181}
NAME=wurd-smoke-$$
URL=http://127.0.0.1:$PORT
TOKEN=$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')
WORK=$(mktemp -d)
passed=0
failed=0

cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker volume rm "$NAME" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# ---- Helpers --------------------------------------------------------------

check() { # check <description> <expected> <actual>
  if [[ "$3" == "$2" ]]; then
    passed=$((passed + 1))
    printf '  ok    %s\n' "$1"
  else
    failed=$((failed + 1))
    printf '  FAIL  %s\n        expected: %s\n        got:      %s\n' "$1" "$2" "$3"
  fi
}

section() { printf '\n%s\n' "$1"; }

# api <method> <path> [curl args...]: prints the status code; the body lands in $WORK/body, headers in $WORK/headers
api() {
  local method=$1 path=$2
  shift 2
  curl -s --path-as-is -o "$WORK/body" -D "$WORK/headers" -w '%{http_code}' -X "$method" "$@" "$URL$path"
}
authed() { api "$@" -H "Authorization: Bearer $TOKEN"; }
upload() { # upload <method> <path> <file> <percent-encoded name> [curl args...]
  local method=$1 path=$2 file=$3 name=$4
  shift 4
  authed "$method" "$path" --data-binary "@$file" -H "X-File-Name: $name" "$@"
}

header() { grep -i "^$1:" "$WORK/headers" | head -1 | cut -d' ' -f2- | tr -d '\r' || true; }
has_header() { grep -qi "^$1:" "$WORK/headers" && echo yes || echo no; }
field() { grep -o "\"$1\":\"\?[^,\"}]*" "$WORK/body" | head -1 | sed -E 's/^"[^"]+":"?//' || true; }

# Test files
printf 'PK\003\004 a docx is a zip file' >"$WORK/doc.docx"
printf 'PK\003\004 version two' >"$WORK/doc-v2.docx"
printf 'not a zip' >"$WORK/fake.docx"
printf '<h1>Hi</h1><script>alert(1)</script>' >"$WORK/page.html"
printf '{\n  "wurd": "encrypted-document",\n  "v": 1\n}\n' >"$WORK/secret.wurd"
printf '{"something": "else"}' >"$WORK/fake.wurd"
printf 'hello' >"$WORK/small.txt"
head -c 1048576 /dev/zero | tr '\0' 'a' >"$WORK/1mb.txt"
head -c 1048577 /dev/zero | tr '\0' 'a' >"$WORK/too-big.txt"

# A stand-in frontend, with things that must never be served or run
mkdir -p "$WORK/frontend/.git"
echo '<!doctype html><title>Wurd</title>' >"$WORK/frontend/index.html"
echo '[core]' >"$WORK/frontend/.git/config"
echo 'SECRET=1' >"$WORK/frontend/.env"
echo '<?php echo "ran";' >"$WORK/frontend/x.php"
chmod -R a+rX "$WORK/frontend"

# ---- Startup checks -------------------------------------------------------

section 'Startup refuses unsafe configuration'
run_status() { docker run --rm "$@" "$IMAGE" >/dev/null 2>&1 && echo started || echo refused; }
check 'no token' refused "$(run_status)"
check 'short token' refused "$(run_status -e WURD_TOKEN=short)"
check 'wildcard origin' refused "$(run_status -e WURD_TOKEN="$TOKEN" -e 'WURD_ALLOWED_ORIGINS=*')"
check 'bad trusted proxy' refused "$(run_status -e WURD_TOKEN="$TOKEN" -e 'WURD_TRUSTED_PROXIES=not-an-ip')"

docker run -d --name "$NAME" \
  -e WURD_TOKEN="$TOKEN" \
  -e WURD_MAX_FILE_MB=1 -e WURD_MAX_TOTAL_MB=2 -e WURD_MAX_FILES=5 \
  -e 'WURD_ALLOWED_ORIGINS=http://allowed.example null' \
  --read-only --tmpfs /tmp:size=16m --cap-drop ALL --security-opt no-new-privileges:true \
  -v "$NAME:/data" -v "$WORK/frontend:/srv/wurd:ro" \
  -p "127.0.0.1:$PORT:8026" "$IMAGE" >/dev/null

for _ in $(seq 50); do
  curl -sf "$URL/api/health" >/dev/null 2>&1 && break
  sleep 0.2
done

section 'Container'
check 'runs as www-data' 33 "$(docker exec "$NAME" id -u)"
check 'root filesystem is read-only' no "$(docker exec "$NAME" touch /app/x 2>/dev/null && echo yes || echo no)"

section 'Frontend'
check 'index is served' 200 "$(api GET /)"
check 'index has a CSP' yes "$(header Content-Security-Policy | grep -q "default-src 'self'" && echo yes || echo no)"
check '.git is not served' 403 "$(api GET /.git/config)"
check 'dotfiles are not served' 403 "$(api GET /.env)"
api GET /x.php >/dev/null
check 'PHP in the frontend folder does not run' no "$(grep -qx ran "$WORK/body" && echo yes || echo no)"

section 'Health and authentication'
check 'health needs no token' 200 "$(api GET /api/health)"
check 'health body' '{"ok":true}' "$(cat "$WORK/body")"
check 'server header has no version' Apache "$(header Server)"
check 'no X-Powered-By' no "$(has_header X-Powered-By)"
check 'no token is refused' 401 "$(api GET /api/files)"
check 'refusal names the scheme' Bearer "$(header WWW-Authenticate)"
check 'wrong token is refused' 401 "$(api GET /api/files -H 'Authorization: Bearer wrong-token')"

section 'Create, list and download'
check 'create a .docx' 201 "$(upload POST /api/files "$WORK/doc.docx" 'R%C3%A9sum%C3%A9.docx')"
ID=$(field id)
check 'id is 32 hex characters' yes "$([[ $ID =~ ^[0-9a-f]{32}$ ]] && echo yes || echo no)"
check 'ETag is the first revision' '"1"' "$(header ETag)"
check 'Location points at the file' "/api/files/$ID" "$(header Location)"
check 'UTF-8 name is kept' 'Résumé.docx' "$(field name)"
check 'list' 200 "$(authed GET /api/files)"
check 'list includes the file' yes "$(grep -q "$ID" "$WORK/body" && echo yes || echo no)"
check 'download' 200 "$(authed GET "/api/files/$ID")"
check 'downloaded bytes are identical' yes "$(cmp -s "$WORK/body" "$WORK/doc.docx" && echo yes || echo no)"
check 'download is opaque' application/octet-stream "$(header Content-Type)"
check 'download is an attachment' yes "$(header Content-Disposition | grep -q "^attachment; .*filename\*=UTF-8''R%C3%A9sum%C3%A9.docx" && echo yes || echo no)"
check 'download has nosniff' nosniff "$(header X-Content-Type-Options)"
check 'download has a sandbox CSP' yes "$(header Content-Security-Policy | grep -q sandbox && echo yes || echo no)"
check 'download is not cached' no-store "$(header Cache-Control)"
check 'create a .html page' 201 "$(upload POST /api/files "$WORK/page.html" page.html)"
HTML_ID=$(field id)
authed GET "/api/files/$HTML_ID" >/dev/null
check 'stored HTML never downloads as HTML' application/octet-stream "$(header Content-Type)"
check 'create an encrypted .wurd' 201 "$(upload POST /api/files "$WORK/secret.wurd" secret.wurd)"

section 'File names are checked'
check 'path traversal' 400 "$(upload POST /api/files "$WORK/doc.docx" '..%2F..%2Fetc%2Fpasswd.docx')"
check 'backslash' 400 "$(upload POST /api/files "$WORK/doc.docx" 'a%5Cb.docx')"
check 'control character' 400 "$(upload POST /api/files "$WORK/doc.docx" 'a%0Ab.docx')"
check 'right-to-left override' 400 "$(upload POST /api/files "$WORK/doc.docx" '%E2%80%AExcod.docx')"
check 'invalid UTF-8' 400 "$(upload POST /api/files "$WORK/doc.docx" '%FF.docx')"
check 'unknown extension' 400 "$(upload POST /api/files "$WORK/small.txt" evil.php)"
check 'extension only' 400 "$(upload POST /api/files "$WORK/doc.docx" .docx)"
check 'over 200 bytes' 400 "$(upload POST /api/files "$WORK/small.txt" "$(printf 'a%.0s' {1..197}).txt")"
check 'missing name' 400 "$(authed POST /api/files --data-binary "@$WORK/small.txt")"

section 'Contents and sizes are checked'
check '.docx that is not a zip' 415 "$(upload POST /api/files "$WORK/fake.docx" fake.docx)"
check '.wurd that is not encrypted' 415 "$(upload POST /api/files "$WORK/fake.wurd" fake.wurd)"
check 'over the file size limit' 413 "$(upload POST /api/files "$WORK/too-big.txt" big.txt)"
check 'no Content-Length' 411 "$(upload POST /api/files "$WORK/small.txt" chunked.txt -H 'Transfer-Encoding: chunked')"

section 'Update'
check 'no If-Match' 428 "$(upload PUT "/api/files/$ID" "$WORK/doc-v2.docx" new.docx)"
check 'malformed If-Match' 400 "$(upload PUT "/api/files/$ID" "$WORK/doc-v2.docx" new.docx -H 'If-Match: 1')"
check 'stale If-Match' 412 "$(upload PUT "/api/files/$ID" "$WORK/doc-v2.docx" new.docx -H 'If-Match: "7"')"
check 'conflict reports the current ETag' '"1"' "$(header ETag)"
check 'matching If-Match' 200 "$(upload PUT "/api/files/$ID" "$WORK/doc-v2.docx" 'Renamed.odt' -H 'If-Match: "1"')"
check 'revision goes up' '"2"' "$(header ETag)"
check 'rename changes the name' Renamed.odt "$(field name)"
check 'rename changes the format' odt "$(field format)"
authed GET "/api/files/$ID" >/dev/null
check 'new contents are stored' yes "$(cmp -s "$WORK/body" "$WORK/doc-v2.docx" && echo yes || echo no)"
check 'without a name, the name is kept' 200 "$(authed PUT "/api/files/$ID" --data-binary "@$WORK/doc.docx" -H 'If-Match: "2"')"
check 'kept name' Renamed.odt "$(field name)"
check 'update an unknown file' 404 "$(upload PUT /api/files/0123456789abcdef0123456789abcdef "$WORK/doc.docx" x.docx -H 'If-Match: "1"')"

section 'IDs and routes'
check 'non-hex ID' 404 "$(authed GET /api/files/NOTANID)"
check 'upper-case ID' 404 "$(authed GET "/api/files/${ID^^}")"
check 'dot segments' 404 "$(authed GET /api/files/../../etc/passwd)"
check 'unknown route' 404 "$(authed GET /api/nothing)"
check 'wrong method' 405 "$(authed PATCH /api/files)"
check 'wrong method lists allowed ones' 'GET, POST' "$(header Allow)"

section 'Quotas'
check '1 MB file fits' 201 "$(upload POST /api/files "$WORK/1mb.txt" one.txt)"
check 'total storage limit' 507 "$(upload POST /api/files "$WORK/1mb.txt" two.txt)"
check 'fifth file fits' 201 "$(upload POST /api/files "$WORK/small.txt" five.txt)"
check 'file count limit' 507 "$(upload POST /api/files "$WORK/small.txt" six.txt)"

section 'Delete'
check 'no If-Match' 428 "$(authed DELETE "/api/files/$HTML_ID")"
check 'stale If-Match' 412 "$(authed DELETE "/api/files/$HTML_ID" -H 'If-Match: "9"')"
check 'matching If-Match' 204 "$(authed DELETE "/api/files/$HTML_ID" -H 'If-Match: "1"')"
check 'deleted file is gone' 404 "$(authed GET "/api/files/$HTML_ID")"
check 'its contents are gone from disk' no "$(docker exec "$NAME" test -e "/data/files/$HTML_ID" && echo yes || echo no)"

section 'CORS'
authed GET /api/files -H 'Origin: http://evil.example' >/dev/null
check 'unknown origin gets no CORS header' no "$(has_header Access-Control-Allow-Origin)"
authed GET /api/files -H 'Origin: http://allowed.example' >/dev/null
check 'allowed origin is echoed' http://allowed.example "$(header Access-Control-Allow-Origin)"
check 'ETag is readable cross-origin' ETag "$(header Access-Control-Expose-Headers)"
check 'never allows credentials' no "$(has_header Access-Control-Allow-Credentials)"
authed GET /api/files -H 'Origin: null' >/dev/null
check 'file:// pages (null) when configured' null "$(header Access-Control-Allow-Origin)"
check 'preflight from an allowed origin' 204 "$(api OPTIONS /api/files -H 'Origin: http://allowed.example' -H 'Access-Control-Request-Method: PUT')"
check 'preflight allows the API methods' 'GET, POST, PUT, DELETE' "$(header Access-Control-Allow-Methods)"
check 'preflight from an unknown origin' 403 "$(api OPTIONS /api/files -H 'Origin: http://evil.example' -H 'Access-Control-Request-Method: PUT')"

section 'Failed-login limit (last: it locks this IP out)'
for _ in $(seq 10); do
  [[ $(api GET /api/files -H 'Authorization: Bearer wrong-token') == 429 ]] && break
done
check 'after 10 failures even the right token waits' 429 "$(authed GET /api/files)"
check 'and is told when to retry' 600 "$(header Retry-After)"

section 'Logs'
check 'token never appears in the logs' no "$(docker logs "$NAME" 2>&1 | grep -q "$TOKEN" && echo yes || echo no)"
check 'no PHP warnings or errors' no "$(docker logs "$NAME" 2>&1 | grep -qiE 'PHP (warning|notice|fatal|deprecated)|wurd: ' && echo yes || echo no)"

printf '\n%d passed, %d failed\n' "$passed" "$failed"
[[ $failed -eq 0 ]]
