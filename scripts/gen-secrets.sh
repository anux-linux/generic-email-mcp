#!/usr/bin/env bash
# Generates the token signing key and the OAuth client ID and secret and
# prints them once. Writes nothing to disk: it refuses to run unless stdout
# is a terminal, holds the values only in shell variables and prints them
# with printf (no here-documents, which bash may back with temp files).
#
#   scripts/gen-secrets.sh
set -euo pipefail

[[ -t 1 ]] || { echo "refusing: stdout is not a terminal; the values must not end up in a file or pipe" >&2; exit 1; }
[[ -r /dev/urandom ]] || { echo "/dev/urandom is not readable" >&2; exit 1; }

rand() { head -c "$1" /dev/urandom; }
# 32 random bytes each; the client ID is not secret but must be unguessable.
key=$(rand 32 | base64 | tr -d '\n')
client_id="claude-$(rand 12 | od -An -tx1 | tr -d ' \n')"
client_secret=$(rand 32 | base64 | tr '+/' '-_' | tr -d '=\n')

printf '%s\n' \
	"TOKEN_SIGNING_KEY    $key" \
	"OAUTH_CLIENT_ID      $client_id" \
	"OAUTH_CLIENT_SECRET  $client_secret" \
	"" \
	"Next steps:" \
	"  1. Put OAUTH_CLIENT_ID into deploy.env; it is not a secret." \
	"  2. Store the other two values in Secret Manager. Paste each one when asked; the input is hidden:" \
	"       scripts/gcp-secrets.sh TOKEN_SIGNING_KEY" \
	"       scripts/gcp-secrets.sh OAUTH_CLIENT_SECRET" \
	"  3. Keep the client ID and secret for the claude.ai connector dialog (README)." \
	"" \
	"Nothing was saved. Clear your terminal scrollback after the last step."
