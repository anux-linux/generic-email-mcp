#!/usr/bin/env bash
# Quality gate: run before every commit and in CI. Touches no real mailbox
# and no cloud account; tests use in-process IMAP/SMTP servers on 127.0.0.1.
#
#   scripts/check.sh                  all checks; fuzz targets run their seeds
#   FUZZTIME=30s scripts/check.sh     also fuzz every target for 30s each
#   SKIP_VULN=1 scripts/check.sh      skip govulncheck (needs vuln.go.dev)
#
# Exit status is non-zero on the first failing check.
set -euo pipefail
cd "$(dirname "$0")/.."

step() { printf '\n==> %s\n' "$*"; }
tool() { go tool -modfile=tools/go.mod "$@"; }

step "gofmt"
unformatted=$(gofmt -l .)
if [[ -n $unformatted ]]; then
	printf 'not gofmt-ed:\n%s\n' "$unformatted" >&2
	exit 1
fi

step "go mod verify, tidy"
go mod verify
go mod tidy -diff
(cd tools && go mod tidy -diff)

step "go vet"
go vet ./...

step "go test -race (shuffled)"
go test -race -count=1 -shuffle=on ./...

if command -v shellcheck >/dev/null; then
	step "shellcheck"
	shellcheck -x -P scripts -S warning scripts/*.sh scripts/lib/*.sh
fi

step "staticcheck"
tool staticcheck ./...

if [[ -z ${SKIP_VULN:-} ]]; then
	step "govulncheck"
	tool govulncheck ./...
fi

if [[ -n ${FUZZTIME:-} ]]; then
	step "fuzz, ${FUZZTIME} per target"
	for pkg in $(go list ./...); do
		for target in $(go test -list '^Fuzz' "$pkg" | grep '^Fuzz' || true); do
			echo "--- $pkg $target"
			go test -run '^$' -fuzz "^${target}\$" -fuzztime "$FUZZTIME" "$pkg"
		done
	done
fi

printf '\nall checks passed\n'
