#!/usr/bin/env bash
# Builds the production image exactly as scripts/deploy.sh does and
# smoke-tests it locally. Needs docker; touches no cloud account or mailbox
# (all secrets are throwaway, generated per run).
#
#   scripts/image-check.sh
#   DOCKERFILE=… BUILD_FLAGS='--secret id=ca,src=…' scripts/image-check.sh   # TLS-intercepting proxies
set -euo pipefail
cd "$(dirname "$0")/.."

TAG=email-mcp:image-check
PORT=${PORT:-18080}
NAME=email-mcp-image-check
VERSION=$(git rev-parse --short=12 HEAD 2>/dev/null || echo dev)
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

PASS=0 FAIL=0
check() { # check <id> <description> <command...>
	local id=$1 desc=$2; shift 2
	if "$@" >/dev/null 2>&1; then PASS=$((PASS + 1)); printf 'PASS %-3s %s\n' "$id" "$desc"
	else FAIL=$((FAIL + 1)); printf 'FAIL %-3s %s\n' "$id" "$desc"; fi
}

# shellcheck disable=SC2086 # BUILD_FLAGS is a list of flags
docker build --platform linux/amd64 --provenance=false --sbom=false ${BUILD_FLAGS:-} \
	-f "${DOCKERFILE:-Dockerfile}" --build-arg VERSION="$VERSION" -t "$TAG" .

inspect() { docker image inspect "$TAG" --format "$1"; }
check I1 "version stamped ($VERSION)" test "$(docker run --rm "$TAG" version)" = "$VERSION"
check I2 "runs as 65532:65532" test "$(inspect '{{.Config.User}}')" = "65532:65532"
check I3 "linux/amd64" test "$(inspect '{{.Os}}/{{.Architecture}}')" = "linux/amd64"
check I4 "no shell in the image" bash -c "! docker run --rm --entrypoint /bin/sh '$TAG' -c true"
BASE=$(sed -n 's/^FROM \(gcr.io\/distroless[^ ]*\).*/\1/p' "${DOCKERFILE:-Dockerfile}")
docker pull -q --platform linux/amd64 "$BASE" >/dev/null
base_layers=$(docker image inspect "$BASE" --format '{{join .RootFS.Layers " "}}')
layers=$(inspect '{{join .RootFS.Layers " "}}')
check I5 "exactly one layer (/email-mcp) on top of the pinned base" test "$layers" = "$base_layers ${layers##* }"

SECRET=$(head -c 24 /dev/urandom | base64 | tr '+/' '-_')
KEY=$(head -c 32 /dev/urandom | base64)
HASH=$(printf 'image check password\n' | docker run -i --rm "$TAG" hash-password)
run() { # run [env...]: starts the container with throwaway settings
	cleanup
	docker run -d --name "$NAME" --network host -e PORT="$PORT" \
		-e OAUTH_CLIENT_ID=image-check-client -e OAUTH_CLIENT_SECRET="$SECRET" \
		-e TOKEN_SIGNING_KEY="$KEY" -e AUTHORIZE_PASSWORD_HASH="$HASH" \
		-e MAIL_USERNAME=user@example.org -e MAIL_PASSWORD=not-a-real-password \
		"$@" "$TAG" >/dev/null
	for _ in $(seq 50); do curl -fs -o /dev/null "http://127.0.0.1:$PORT/health" && return; sleep 0.1; done
}
code() { curl -sS -o /dev/null -w '%{http_code}' "$@"; }

run
check I6 "setup mode (no BASE_URL): /health 200" test "$(code "http://127.0.0.1:$PORT/health")" = 200
check I7 "setup mode: /mcp 503" test "$(code -X POST "http://127.0.0.1:$PORT/mcp")" = 503

B=http://127.0.0.1:$PORT
run -e BASE_URL="$B"
check I8 "full mode: protected resource metadata names $B/mcp" bash -c "curl -fsS '$B/.well-known/oauth-protected-resource/mcp' | grep -q '\"resource\":\"$B/mcp\"'"
check I9 "full mode: /mcp without token 401" test "$(code -X POST "$B/mcp")" = 401
start=$(date +%s)
docker stop --time 10 "$NAME" >/dev/null
check I10 "SIGTERM: clean exit 0 well before the kill timeout" bash -c "[[ \$(docker inspect -f '{{.State.ExitCode}}' '$NAME') == 0 && \$(( \$(date +%s) - $start )) -lt 9 ]]"
logs=$(docker logs "$NAME" 2>&1)
check I11 "logs are JSON lines" bash -c 'while IFS= read -r l; do [[ $l == "{"* ]] || exit 1; done <<<"$1"' _ "$logs"
check I12 "logs contain no secrets" bash -c '! grep -qF -e "$2" -e "$3" -e "$4" -e not-a-real-password <<<"$1"' _ "$logs" "$SECRET" "$KEY" "$HASH"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ $FAIL == 0 ]]
