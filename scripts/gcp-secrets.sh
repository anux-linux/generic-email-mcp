#!/usr/bin/env bash
# Stores the service secrets in Secret Manager (one secret per value, kept
# in REGION) and lets only the runtime service account read each one.
#
#   scripts/gcp-secrets.sh MAIL_PASSWORD              # hidden prompt
#   pass show mail | scripts/gcp-secrets.sh MAIL_PASSWORD   # or from stdin
#   scripts/gcp-secrets.sh AUTHORIZE_PASSWORD_HASH    # asks for the owner password, stores its argon2id hash
#   scripts/gcp-secrets.sh all                        # all four, one after another (terminal only)
#
# Values travel only through pipes, never as arguments, environment
# variables or files. Every run adds a new version; scripts/deploy.sh pins
# the newest enabled version, so a rotation takes effect on the next deploy.
set -euo pipefail
# shellcheck source=lib/gcp.sh
. "$(dirname "$0")/lib/gcp.sh"

usage() { local IFS='|'; die "usage: scripts/gcp-secrets.sh <${SECRET_KEYS[*]}|all>"; }
[[ $# == 1 ]] || usage
load_config
need gcloud

# read_value <prompt>: the value on stdout, from the terminal (hidden) or
# from stdin when it is not a terminal (one trailing newline removed).
read_value() {
	local v
	if [[ -t 0 ]]; then
		IFS= read -rsp "$1: " v </dev/tty
		printf '\n' >&2
	else
		v=$(cat; printf x)
		v=${v%x}
		v=${v%$'\n'}
	fi
	printf '%s' "$v"
}

# value <key>: reads, validates and prints the value to store.
value() {
	local v v2
	case $1 in
	MAIL_PASSWORD)
		v=$(read_value "Mailbox password for $MAIL_USERNAME")
		[[ -n $v ]] || die "empty password"
		;;
	TOKEN_SIGNING_KEY)
		v=$(read_value "TOKEN_SIGNING_KEY (from scripts/gen-secrets.sh)")
		# base64 of at least 32 bytes, as the service requires
		[[ $v =~ ^[A-Za-z0-9+/_-]{43,}={0,2}$ ]] || die "not base64 of at least 32 bytes"
		;;
	OAUTH_CLIENT_SECRET)
		v=$(read_value "OAUTH_CLIENT_SECRET (from scripts/gen-secrets.sh)")
		[[ ${#v} -ge 32 && $v =~ ^[[:graph:]]+$ ]] || die "must be at least 32 printable characters without spaces"
		;;
	AUTHORIZE_PASSWORD_HASH)
		need go
		v=$(read_value "New owner password for the /authorize login (at least 12 characters)")
		if [[ -t 0 ]]; then
			v2=$(read_value "Repeat it")
			[[ $v == "$v2" ]] || die "the passwords differ"
		fi
		v=$(printf '%s\n' "$v" | (cd "$ROOT" && go run ./cmd/email-mcp hash-password)) || die "hashing failed"
		;;
	*) usage ;;
	esac
	printf '%s' "$v"
}

store() {
	local key=$1 id v
	id=$(secret_id "$key")
	# Read and validate before touching Secret Manager, so a bad or empty
	# value can never become a version.
	v=$(value "$key")
	if ! gc secrets describe "$id" >/dev/null 2>&1; then
		mut secrets create "$id" --replication-policy=user-managed --locations="$REGION" --labels=app=email-mcp >/dev/null
	fi
	# printf is a builtin: the value reaches gcloud's stdin without ever
	# appearing in a process argument list.
	printf '%s' "$v" | gc secrets versions add "$id" --data-file=- >/dev/null
	v=""
	say "added a new version of $id"
	mut secrets add-iam-policy-binding "$id" --member="serviceAccount:$SA_EMAIL" \
		--role=roles/secretmanager.secretAccessor >/dev/null
	local n
	n=$(gc secrets versions list "$id" --filter=state=ENABLED --format='value(name)' | wc -l | tr -d ' ')
	if ((n > 1)); then
		say "$id has $n enabled versions. Once the next deploy serves, destroy the old ones" \
			"(Secret Manager bills active versions above 6 per billing account):" \
			"gcloud secrets versions list $id --project=$PROJECT_ID"
	fi
}

if [[ $1 == all ]]; then
	[[ -t 0 ]] || die "'all' needs a terminal"
	for k in "${SECRET_KEYS[@]}"; do store "$k"; done
else
	in_list "$1" "${SECRET_KEYS[@]}" || usage
	store "$1"
fi
say "done; run scripts/deploy.sh to use the new versions"
