# shellcheck shell=bash
# Shared by the GCP scripts (sourced, not executed): config loading and
# validation, and the gcloud wrapper. Compatible with bash 3.2 (macOS).
#
# Nothing here handles secret values. Scripts that do pass them only through
# pipes: no arguments, environment variables, here-documents or here-strings,
# which older bash versions back with temporary files.

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
CONFIG=${CONFIG:-$ROOT/deploy.env}

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
say() { printf '==> %s\n' "$*" >&2; }
in_list() { local x=$1 e; shift; for e in "$@"; do [[ $e == "$x" ]] && return 0; done; return 1; }
need() { local c; for c in "$@"; do command -v "$c" >/dev/null 2>&1 || die "$c is required"; done; }

# pick_container_cli: sets CTR to the container engine: $CONTAINER_CLI if set,
# else docker, else podman. The buildx-only flags are docker's alone.
pick_container_cli() {
	CTR=${CONTAINER_CLI:-}
	if [[ -z $CTR ]]; then
		if command -v docker >/dev/null 2>&1; then CTR=docker; else CTR=podman; fi
	fi
	# shellcheck disable=SC2034 # used by the sourcing scripts
	if [[ $(basename "$CTR") == podman ]]; then
		CTR_BUILD_FLAGS=()
	else
		CTR_BUILD_FLAGS=(--provenance=false --sbom=false)
	fi
	need "$CTR"
}

# Deployment settings, not passed to the service. The CD_*, WIF_* and
# DEPLOY_SA_NAME keys are only for scripts/gcp-github.sh.
DEPLOY_KEYS=(PROJECT_ID REGION SERVICE REPOSITORY RUNTIME_SA_NAME PUBLIC_ACCESS
	CD_REPO CD_REPO_ID CD_OWNER_ID WIF_POOL WIF_PROVIDER DEPLOY_SA_NAME)
# Service settings, passed to Cloud Run as plain environment variables when set.
APP_KEYS=(MAIL_USERNAME MAIL_FROM MAIL_FROM_NAME MAIL_IMAP_ADDR MAIL_SMTP_ADDR MAIL_SMTP_HELO MAIL_SAVE_SENT
	MAIL_MAX_BODY_BYTES MAIL_FOLDER_SENT MAIL_FOLDER_DRAFTS MAIL_FOLDER_TRASH MAIL_FOLDER_ARCHIVE
	SEND_ALLOWLIST MAX_SENDS_PER_DAY SEND_LEDGER SEND_LEDGER_FOLDER AUTH_STATE AUTH_STATE_FOLDER
	OAUTH_CLIENT_ID OAUTH_REDIRECT_URIS TOKEN_EPOCH AUTHORIZE_USERNAME AUTHORIZE_LOGIN LOG_LEVEL
	TRUSTED_PROXY_HOPS BASE_URL)
# Secrets: environment variable -> Secret Manager secret "<SERVICE>-<name>".
SECRET_KEYS=(MAIL_PASSWORD TOKEN_SIGNING_KEY OAUTH_CLIENT_SECRET AUTHORIZE_PASSWORD_HASH)

# Values that identify the owner. In GitHub Actions they are masked in the
# public log as soon as the configuration is loaded (see mask).
PERSONAL_KEYS=(MAIL_USERNAME MAIL_FROM MAIL_FROM_NAME SEND_ALLOWLIST OAUTH_CLIENT_ID AUTHORIZE_USERNAME)

# mask <value>: in GitHub Actions, tells the runner to print *** instead of
# the value from now on. Workflow commands go to stderr, like every other
# message here, so the mask precedes any line that contains the value.
mask() {
	[[ ${GITHUB_ACTIONS:-} == true && -n $1 ]] || return 0
	printf '::add-mask::%s\n' "$1" >&2
}

# load_config parses $CONFIG as KEY=value lines (optionally quoted). It is
# never executed as shell code; unknown keys and secrets are rejected.
load_config() {
	[[ -f $CONFIG ]] || die "$CONFIG not found: cp deploy.env.example deploy.env and edit it"
	local line key val n=0
	# Only the file counts: a variable exported in the caller's shell (say a
	# BASE_URL from local testing) must never reach a deployment.
	for key in "${DEPLOY_KEYS[@]}" "${APP_KEYS[@]}" "${SECRET_KEYS[@]}"; do unset "$key"; done
	while IFS= read -r line || [[ -n $line ]]; do
		n=$((n + 1))
		[[ $line =~ ^[[:space:]]*(#.*)?$ ]] && continue
		[[ $line =~ ^([A-Z][A-Z0-9_]*)=(.*)$ ]] || die "$CONFIG:$n: expected KEY=value"
		key=${BASH_REMATCH[1]} val=${BASH_REMATCH[2]}
		if [[ $val =~ ^\"(.*)\"$ || $val =~ ^\'(.*)\'$ ]]; then val=${BASH_REMATCH[1]}; fi
		in_list "$key" "${SECRET_KEYS[@]}" &&
			die "$CONFIG:$n: $key is a secret: store it with scripts/gcp-secrets.sh $key, never in a file"
		in_list "$key" "${DEPLOY_KEYS[@]}" "${APP_KEYS[@]}" || die "$CONFIG:$n: unknown setting $key"
		[[ $val != *'|'* ]] || die "$CONFIG:$n: values must not contain '|'"
		printf -v "$key" '%s' "$val"
	done <"$CONFIG"
	local item rest
	for key in "${PERSONAL_KEYS[@]}"; do
		mask "${!key-}"
	done
	# Each allowlist entry on its own, which covers the whole list too.
	rest=${SEND_ALLOWLIST-}
	while [[ -n $rest ]]; do
		item=${rest%%,*}
		item=${item#"${item%%[![:space:]]*}"}
		mask "${item%"${item##*[![:space:]]}"}"
		if [[ $rest == *,* ]]; then rest=${rest#*,}; else rest=""; fi
	done

	: "${PROJECT_ID:?set PROJECT_ID in $CONFIG}"
	: "${MAIL_USERNAME:?set MAIL_USERNAME in $CONFIG}"
	: "${OAUTH_CLIENT_ID:?set OAUTH_CLIENT_ID in $CONFIG (from scripts/gen-secrets.sh)}"
	REGION=${REGION:-europe-west1}
	SERVICE=${SERVICE:-email-mcp}
	REPOSITORY=${REPOSITORY:-email-mcp}
	RUNTIME_SA_NAME=${RUNTIME_SA_NAME:-email-mcp-run}
	PUBLIC_ACCESS=${PUBLIC_ACCESS:-allow-unauthenticated}
	[[ $PROJECT_ID =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]] || die "PROJECT_ID $PROJECT_ID is not a valid project ID"
	[[ $REGION =~ ^[a-z]+-[a-z]+[0-9]+$ ]] || die "REGION $REGION is not a valid region"
	[[ $SERVICE =~ ^[a-z]([a-z0-9-]{0,47}[a-z0-9])?$ ]] || die "SERVICE $SERVICE is not a valid Cloud Run service name"
	[[ $REPOSITORY =~ ^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || die "REPOSITORY $REPOSITORY is not a valid repository name"
	[[ $RUNTIME_SA_NAME =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]] || die "RUNTIME_SA_NAME $RUNTIME_SA_NAME is not a valid account ID"
	[[ $PUBLIC_ACCESS == allow-unauthenticated || $PUBLIC_ACCESS == no-invoker-iam-check ]] ||
		die "PUBLIC_ACCESS must be allow-unauthenticated or no-invoker-iam-check"
	WIF_POOL=${WIF_POOL:-email-mcp}
	WIF_PROVIDER=${WIF_PROVIDER:-github}
	DEPLOY_SA_NAME=${DEPLOY_SA_NAME:-email-mcp-deploy}
	[[ -z ${CD_REPO:-} || $CD_REPO =~ ^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$ ]] || die "CD_REPO must be OWNER/REPOSITORY"
	[[ -z ${CD_REPO_ID:-} || $CD_REPO_ID =~ ^[1-9][0-9]{0,19}$ ]] || die "CD_REPO_ID must be the numeric repository ID"
	[[ -z ${CD_OWNER_ID:-} || $CD_OWNER_ID =~ ^[1-9][0-9]{0,19}$ ]] || die "CD_OWNER_ID must be the numeric owner ID"
	local id
	for id in "$WIF_POOL" "$WIF_PROVIDER"; do
		[[ $id =~ ^[a-z0-9-]{4,32}$ && $id != gcp-* ]] ||
			die "WIF_POOL/WIF_PROVIDER $id: 4-32 characters of a-z 0-9 -, not starting with gcp-"
	done
	[[ $DEPLOY_SA_NAME =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]] || die "DEPLOY_SA_NAME $DEPLOY_SA_NAME is not a valid account ID"
	[[ $DEPLOY_SA_NAME != "$RUNTIME_SA_NAME" ]] || die "DEPLOY_SA_NAME must differ from RUNTIME_SA_NAME"
	[[ $OAUTH_CLIENT_ID =~ ^[A-Za-z0-9._~-]{8,128}$ ]] || die "OAUTH_CLIENT_ID must be 8-128 characters of A-Z a-z 0-9 . _ ~ -"
	# shellcheck disable=SC2034 # used by the sourcing scripts
	SA_EMAIL=$RUNTIME_SA_NAME@$PROJECT_ID.iam.gserviceaccount.com
	# shellcheck disable=SC2034
	DEPLOY_SA_EMAIL=$DEPLOY_SA_NAME@$PROJECT_ID.iam.gserviceaccount.com
	# shellcheck disable=SC2034
	IMAGE=$REGION-docker.pkg.dev/$PROJECT_ID/$REPOSITORY/$SERVICE
}

# access_flag prints the gcloud flag that makes the service reachable from
# the internet. allow-unauthenticated grants roles/run.invoker to allUsers;
# organizations with domain restricted sharing forbid that, so the
# alternative disables the invoker check instead. Either way the app does
# all authentication.
access_flag() {
	if [[ $PUBLIC_ACCESS == no-invoker-iam-check ]]; then
		printf '%s' --no-invoker-iam-check
	else
		printf '%s' --allow-unauthenticated
	fi
}

# secret_id MAIL_PASSWORD -> email-mcp-mail-password
secret_id() { printf '%s-%s' "$SERVICE" "$(printf '%s' "$1" | tr '[:upper:]_' '[:lower:]-')"; }

# gc runs gcloud for $PROJECT_ID, never prompting. mut also prints the
# command first; use it for everything that changes cloud state.
gc() { gcloud --project="$PROJECT_ID" --quiet "$@"; }
mut() { say "gcloud $*"; gc "$@"; }

# confirm asks before changing anything, unless YES=1.
confirm() {
	[[ ${YES:-} == 1 ]] && return 0
	[[ -t 0 ]] || die "stdin is not a terminal; set YES=1 to proceed without asking"
	local a
	read -rp "$1 [y/N] " a
	[[ $a == y || $a == Y ]] || die "aborted"
}

# account prints the gcloud account that will act.
account() { gcloud config get-value account 2>/dev/null || true; }
