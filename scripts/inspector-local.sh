#!/usr/bin/env bash
# Part A of docs/INSPECTOR.md, automated: drives the real binary with the
# pinned MCP Inspector CLI against a fake mailbox on 127.0.0.1 and asserts
# every result. Plays the browser for the owner login (Basic credentials on
# /authorize, then the Inspector's loopback callback).
#
# Never touches a real mailbox or cloud account. All secrets are throwaway,
# generated per run and deleted on exit. Needs: go, npx (Node >= 22), curl,
# jq, and Linux (the binary is pointed at the dev CA via SSL_CERT_FILE).
#
#   scripts/inspector-local.sh            # exit 0 = all checks passed
#   KEEP=1 scripts/inspector-local.sh     # keep the work dir for inspection
set -euo pipefail
cd "$(dirname "$0")/.."

INSPECTOR=@modelcontextprotocol/inspector@2.11.0
PORT=${PORT:-8080}
B=http://127.0.0.1:$PORT
CALLBACK=http://127.0.0.1:6276/oauth/callback # the Inspector CLI default
CLIENT_ID=inspector-local-client

for c in go node npx curl jq; do command -v "$c" >/dev/null || { echo "missing: $c" >&2; exit 2; }; done
# The Inspector declares engines.node >=22.19.0.
node -e 'const [a, b] = process.versions.node.split(".").map(Number); process.exit(a > 22 || (a === 22 && b >= 19) ? 0 : 1)' ||
	{ echo "Node >= 22.19.0 required, found $(node --version)" >&2; exit 2; }
W=$(mktemp -d)
MBOX_PID="" SERVER_PID=""
cleanup() {
	[[ -n $SERVER_PID ]] && kill -TERM "$SERVER_PID" 2>/dev/null && wait "$SERVER_PID" 2>/dev/null || true
	[[ -n $MBOX_PID ]] && kill -INT "$MBOX_PID" 2>/dev/null && wait "$MBOX_PID" 2>/dev/null || true
	if [[ -n ${KEEP:-} ]]; then echo "work dir kept: $W"; else rm -rf "$W"; fi
}
trap cleanup EXIT

PASS=0 FAIL=0
check() { # check <id> <description> <command...>
	local id=$1 desc=$2; shift 2
	if "$@" >/dev/null 2>&1; then PASS=$((PASS + 1)); printf 'PASS %-4s %s\n' "$id" "$desc"
	else FAIL=$((FAIL + 1)); printf 'FAIL %-4s %s\n' "$id" "$desc"; fi
}

# --- fake mailbox, throwaway secrets, server ---------------------------------
go build -trimpath -o "$W/email-mcp" ./cmd/email-mcp
go test -c -o "$W/devmailbox" ./internal/testutil
mkdir -p "$W/mbox" "$W/store"
DEVMAILBOX=1 DEVMAILBOX_DIR="$W/mbox" "$W/devmailbox" -test.run '^TestDevMailbox$' -test.timeout 0 -test.v >"$W/mbox.log" 2>&1 &
MBOX_PID=$!
for _ in $(seq 100); do [[ -s $W/mbox/devmailbox.env ]] && break; sleep 0.1; done

CLIENT_SECRET=$(head -c 24 /dev/urandom | base64 | tr '+/' '-_')
OWNER_PW="owner-$(head -c 12 /dev/urandom | base64 | tr '+/' '-_')"
SIGNING_KEY=$(head -c 32 /dev/urandom | base64)
PW_HASH=$(printf '%s\n' "$OWNER_PW" | "$W/email-mcp" hash-password)

start_server() { # start_server <token epoch>
	(
		set -a; . "$W/mbox/devmailbox.env"; set +a
		BASE_URL=$B PORT=$PORT LOG_LEVEL=debug OAUTH_CLIENT_ID=$CLIENT_ID OAUTH_CLIENT_SECRET=$CLIENT_SECRET \
			OAUTH_REDIRECT_URIS="https://claude.ai/api/mcp/auth_callback,$CALLBACK" \
			TOKEN_SIGNING_KEY=$SIGNING_KEY TOKEN_EPOCH=$1 AUTHORIZE_PASSWORD_HASH=$PW_HASH \
			SEND_ALLOWLIST=example.net MAX_SENDS_PER_DAY=2 exec "$W/email-mcp"
	) >>"$W/server.log" 2>&1 &
	SERVER_PID=$!
	for _ in $(seq 100); do curl -fs -o /dev/null "$B/health" && return; sleep 0.1; done
	echo "server did not start" >&2; cat "$W/server.log" >&2; exit 1
}
start_server 1

# --- Inspector helpers ---------------------------------------------------------
RC=0
insp() { # insp <inspector args...>: sets RC, writes $W/out and $W/err
	MCP_STORAGE_DIR="$W/store" MCP_INSPECTOR_SECRET_STORE=file MCP_AUTO_OPEN_ENABLED=true \
		npx -y "$INSPECTOR" --cli --server-url "$B/mcp" --transport http \
		--client-id "$CLIENT_ID" --client-secret "$CLIENT_SECRET" "$@" >"$W/out" 2>"$W/err" &
	local pid=$! url="" authed=""
	while kill -0 "$pid" 2>/dev/null; do
		url=$(grep -oE "$B/authorize\?[^ ]+" "$W/err" | head -1 || true)
		if [[ -n $url && -z $authed ]]; then
			authed=1
			curl -sS -o /dev/null "$(curl -sS -o /dev/null -w '%{redirect_url}' -u "owner:$OWNER_PW" "$url")"
		fi
		sleep 0.2
	done
	RC=0; wait "$pid" || RC=$?
}
TEXT="" PAYLOAD="null"
call() { # call <tool> <json args>: sets RC, TEXT (tool text) and PAYLOAD (JSON in the untrusted block)
	insp --stored-auth-only --method tools/call --tool-name "$1" --tool-args-json "$2" --format json
	TEXT=$(jq -r '.result.content[0].text // empty' "$W/out" 2>/dev/null || true)
	PAYLOAD=$(sed -n '/^<untrusted_email_content boundary=/,/^<\/untrusted_email_content boundary=/p' <<<"$TEXT" | sed '1d;$d')
	[[ -n $PAYLOAD ]] || PAYLOAD=null
}
p() { jq -e "$1" <<<"$PAYLOAD"; }                  # assert on the payload
tool_error() { [[ $RC == 5 && $TEXT == "Error ($1)"* ]]; } # assert a tool error kind
id_of() { call mail_search "{\"subject\":\"$1\"}"; jq -r '.messages[0].id' <<<"$PAYLOAD"; }
smtp_count() { grep -c '^smtp:' "$W/mbox.log" || true; }

# --- A: discovery, login, tool list --------------------------------------------
insp --method tools/list --format json
check A1 "OAuth login (static client, PKCE S256, resource) and tools/list" test "$RC" = 0
check A2 "seven tools listed" jq -e '.result.tools | length == 7' "$W/out"
check A3 "send is destructive+open-world; read tools are read-only" jq -e '
	(.result.tools[] | select(.name=="mail_send_draft") | .annotations | .destructiveHint and .openWorldHint and (.readOnlyHint|not)) and
	([.result.tools[] | select(.name|IN("mail_list_folders","mail_search","mail_read")) | .annotations.readOnlyHint] | all)' "$W/out"
insp --stored-auth-only --method tools/list --strict
check A4 "schemas portable (--strict: no warnings)" bash -c "[[ $RC == 0 ]] && ! grep -q 'Warning: tool' '$W/err'"

# --- B: reading ------------------------------------------------------------------
call mail_list_folders '{}'
check B1 "folder roles discovered" p '[.folders[] | select(.role) | .role] | contains(["inbox","drafts","sent","trash","archive","junk"])'
call mail_search '{"unread_only":true}'
check B2 "unread search finds 3" p '.total_matches == 3'
call mail_read "{\"id\":\"$(id_of 'Weekly digest')\"}"
check B3 "hidden HTML content removed" p '(.body | test("HIDDEN-MARKER") | not) and (.body | test("Visible digest text"))'
call mail_read "{\"id\":\"$(id_of 'Urgent')\"}"
check B4 "injected tags neutralized: one real block, closing tag last" bash -c '
	t=$1; [[ $(grep -ci "<untrusted_email_content" <<<"$t") == 1 && $(grep -ci "</untrusted_email_content" <<<"$t") == 1 ]] &&
	[[ $(tail -n1 <<<"$t") == "</untrusted_email_content boundary="* ]]' _ "$TEXT"
call mail_read "{\"id\":\"$(id_of 'Grüße')\"}"
check B5 "ISO-8859-1 decoded; attachment as metadata only" p '.subject == "Grüße" and (.body|test("München")) and .attachments[0].filename == "report.pdf"'
call mail_search '{"unread_only":true}'
check B6 "reading did not set \\Seen" p '.total_matches == 3'
call mail_search '{"folder":"Projects"}'
check B7 "search in a named folder" p '.total_matches == 1'

# --- C: drafts and sending ----------------------------------------------------------
call mail_create_draft '{"to":["Alice <alice@example.net>"],"bcc":["audit@example.net"],"subject":"Re: Quarterly numbers","body":"Confirmed."}'
D1=$(jq -r .draft_id <<<"$PAYLOAD")
check C1 "draft created" test "${D1:0:3}" = "d1."
call mail_send_draft "{\"draft_id\":\"$D1\",\"confirm\":false}"
check C2 "send with confirm=false refused" tool_error invalid_input
call mail_send_draft "{\"draft_id\":\"$D1\"}"
check C3 "send without confirm refused by the schema" bash -c "[[ $RC == 5 ]] && grep -q 'confirm' <<<\"\$1\"" _ "$TEXT"
check C4 "nothing reached SMTP yet" test "$(smtp_count)" = 0
call mail_send_draft "{\"draft_id\":\"$D1\",\"confirm\":true}"
check C5 "send with confirm=true; saved to Sent; draft to Trash" p '.status == "sent" and .saved_to_sent and .draft_moved_to_trash and .sends_remaining_24h == 1'
sleep 0.5
check C6 "SMTP got To+Bcc as recipients, no Bcc header" grep -q 'rcpts=\[alice@example.net audit@example.net\] bcc_header=false' "$W/mbox.log"
call mail_send_draft "{\"draft_id\":\"$D1\",\"confirm\":true}"
check C7 "same draft cannot be sent twice" tool_error already_sent
call mail_create_draft '{"to":["bob@example.net"],"subject":"Kickoff","body":"Monday."}'
D2=$(jq -r .draft_id <<<"$PAYLOAD")
# Change the first MAC character: all its 6 bits are data, so the ID stays
# well-formed and only the signature is wrong. (Its last character carries
# padding bits that must be zero; changing that one can make the ID merely
# malformed, refused as invalid_input instead.)
mac=${D2##*.}
[[ ${mac:0:1} == A ]] && forged="${D2%.*}.B${mac:1}" || forged="${D2%.*}.A${mac:1}"
call mail_send_draft "{\"draft_id\":\"$forged\",\"confirm\":true}"
check C8 "draft id with a forged MAC refused" tool_error draft_invalid
call mail_create_draft '{"to":["eve@evil.example"],"subject":"x","body":"y"}'
check C9 "draft outside the allowlist carries a warning" grep -q "WARNING: sending this draft will be refused" <<<"$TEXT"
call mail_send_draft "{\"draft_id\":\"$(jq -r .draft_id <<<"$PAYLOAD")\",\"confirm\":true}"
check C10 "send outside the allowlist refused" tool_error policy
call mail_send_draft "{\"draft_id\":\"$D2\",\"confirm\":true}"
check C11 "second send allowed (cap 2); forged attempt did not burn the draft" p '.status == "sent" and .sends_remaining_24h == 0'
call mail_create_draft '{"to":["carol@example.net"],"subject":"x","body":"y"}'
call mail_send_draft "{\"draft_id\":\"$(jq -r .draft_id <<<"$PAYLOAD")\",\"confirm\":true}"
check C12 "third send refused by the daily cap" bash -c "[[ $RC == 5 ]] && grep -q 'daily send limit' <<<\"\$1\"" _ "$TEXT"
check C13 "SMTP received exactly 2 messages" test "$(smtp_count)" = 2

# --- D: organizing ------------------------------------------------------------------
Q=$(id_of Quarterly)
call mail_mark_read "{\"ids\":[\"$Q\"]}"
check D1 "mark read" p '.updated == 1'
call mail_mark_read '{"ids":null}'
check D2 "null id list refused by the schema" test "$RC" = 5
call mail_move "{\"ids\":[\"$Q\"],\"destination\":\"MCP-Send-Ledger\"}"
check D3 "move into the send ledger refused" tool_error protected
call mail_move "{\"ids\":[\"$Q\"],\"destination\":\"MCP-Auth-State\"}"
check D4 "move into the auth state refused" tool_error protected
call mail_search '{"folder":"MCP-Send-Ledger"}'
call mail_move "{\"ids\":[\"$(jq -r '.messages[0].id' <<<"$PAYLOAD")\"],\"destination\":\"trash\"}"
check D5 "move out of the send ledger refused" tool_error protected
call mail_move "{\"ids\":[\"$Q\"],\"destination\":\"trash\"}"
check D6 "delete = move to Trash" p '.destination_folder == "Trash" and (.moved | length == 1)'
call mail_read "{\"id\":\"$Q\"}"
check D7 "old id after the move is not found" tool_error not_found
call mail_search '{"query":"x"}'
check D8 "unknown arguments refused" test "$RC" = 5

# --- H: HTTP surface ---------------------------------------------------------------
hdr() { curl -sS -o /dev/null -w "$1" "${@:2}"; }
check H1 "protected resource metadata" bash -c "curl -fsS '$B/.well-known/oauth-protected-resource/mcp' | jq -e '.resource == \"$B/mcp\" and .authorization_servers == [\"$B\"]'"
check H2 "AS metadata: S256 only, iss parameter, no DCR" bash -c "curl -fsS '$B/.well-known/oauth-authorization-server' | jq -e '.code_challenge_methods_supported == [\"S256\"] and .authorization_response_iss_parameter_supported and .registration_endpoint == null'"
check H3 "no token: 401 with resource_metadata" bash -c "[[ \$(curl -sS -o /dev/null -w '%{http_code} %header{www-authenticate}' -X POST -d '{}' '$B/mcp') == '401 Bearer resource_metadata='* ]]"
check H4 "forged token: 401" test "$(hdr '%{http_code}' -X POST -H 'Authorization: Bearer eyJhbGciOiJub25lIn0.e30.' -d '{}' "$B/mcp")" = 401
check H5 "wrong client secret: 401 invalid_client" bash -c "curl -sS -u '$CLIENT_ID:wrong-secret-0123456789abcdefghij' -d grant_type=refresh_token -d refresh_token=x '$B/token' | jq -e '.error == \"invalid_client\"'"
CH=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
check H6 "unregistered redirect_uri: 400, no redirect" test "$(hdr '%{http_code}%{redirect_url}' -u "owner:$OWNER_PW" "$B/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=http%3A%2F%2F127.0.0.1%3A9%2Fcb&code_challenge=$CH&code_challenge_method=S256")" = 400
check H7 "wrong owner password: no code" bash -c "[[ \$(curl -sS -o /dev/null -w '%{http_code}' -u owner:wrong '$B/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=$CALLBACK&code_challenge=$CH&code_challenge_method=S256') == 401 ]]"

# --- R: revocation -------------------------------------------------------------------
kill -TERM "$SERVER_PID"; wait "$SERVER_PID" 2>/dev/null || true
start_server 2
insp --stored-auth-only --method tools/list
check R1 "TOKEN_EPOCH bump revokes stored access and refresh tokens" test "$RC" = 3

# --- L: logs ---------------------------------------------------------------------------
leaks=0
for s in "@example" "@evil" "Quarterly" "Kickoff" "Confirmed" "HIDDEN" "eyJ" "$CLIENT_SECRET" "$OWNER_PW" "$SIGNING_KEY" \
	"$(sed -n 's/^MAIL_PASSWORD=//p' "$W/mbox/devmailbox.env")" '"m1.' '"d1.' "code="; do
	grep -qF -- "$s" "$W/server.log" && leaks=$((leaks + 1))
done
check L1 "server log has no addresses, content, ids, tokens or secrets" test "$leaks" = 0

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ $FAIL == 0 ]]
