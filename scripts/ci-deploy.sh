#!/usr/bin/env bash
# The deploy step of .github/workflows/deploy.yml, on a GitHub-hosted
# runner: installs the pinned gcloud, signs in through Workload Identity
# Federation and runs scripts/deploy.sh in UPDATE_ONLY mode.
#
# No long-lived credential exists anywhere. gcloud fetches the job's OIDC
# token from GitHub (audience: the provider), exchanges it at Google STS and
# impersonates the deployer service account; scripts/gcp-github.sh sets up
# both ends. Input, from the workflow:
#   GCP_WIF_PROVIDER  projects/NUMBER/locations/global/workloadIdentityPools/POOL/providers/PROVIDER
#   GCP_DEPLOY_SA     the deployer service account's email
#   DEPLOY_ENV        the content of deploy.env (an environment secret)
#   ACTIONS_ID_TOKEN_REQUEST_URL, ACTIONS_ID_TOKEN_REQUEST_TOKEN  set by the
#                     runner for jobs with permissions: id-token: write
#
# SKIP_GCLOUD_INSTALL=1 uses the gcloud in PATH instead (tests only).
set -euo pipefail
# shellcheck source=lib/gcp.sh
. "$(dirname "$0")/lib/gcp.sh"

# Google's versioned archive (docs: "Previous versions of the gcloud CLI are
# available in the download archive in Cloud Storage"). Google publishes a
# SHA-256 only for the current unversioned file; on 2026-10-20 that file
# (351ed4a2...) held the same tar as this one, whose MD5 also matches the
# Cloud Storage object (docs/VERIFY.md W6).
GCLOUD_VERSION=590.0.0
GCLOUD_SHA256=1503a6fcda689d1e1013a421e2c85850e7f58382c0be7064877b5e1a1038bc64
GCLOUD_URL=https://storage.googleapis.com/cloud-sdk-release/google-cloud-cli-$GCLOUD_VERSION-linux-x86_64.tar.gz

[[ ${GITHUB_ACTIONS:-} == true ]] || die "this runs in GitHub Actions only; deploy locally with scripts/deploy.sh"
for v in RUNNER_TEMP GCP_WIF_PROVIDER GCP_DEPLOY_SA DEPLOY_ENV; do
	[[ -n ${!v:-} ]] || die "$v is not set; see the environment settings printed by scripts/gcp-github.sh"
done
[[ -n ${ACTIONS_ID_TOKEN_REQUEST_URL:-} && -n ${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-} ]] ||
	die "no OIDC token available; the job needs permissions: id-token: write"
[[ $GCP_WIF_PROVIDER =~ ^projects/[0-9]+/locations/global/workloadIdentityPools/[a-z0-9-]{4,32}/providers/[a-z0-9-]{4,32}$ ]] ||
	die "GCP_WIF_PROVIDER must be projects/NUMBER/locations/global/workloadIdentityPools/POOL/providers/PROVIDER"
[[ $GCP_DEPLOY_SA =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$ ]] ||
	die "GCP_DEPLOY_SA must be a service account email"
need curl git jq docker

umask 077
work=$(mktemp -d "$RUNNER_TEMP/deploy.XXXXXX")
trap 'rm -rf "$work"' EXIT

# The configuration. load_config validates it and masks the owner's
# personal values in the log before anything else is printed.
printf '%s\n' "$DEPLOY_ENV" >"$work/deploy.env"
unset DEPLOY_ENV
export CONFIG=$work/deploy.env
load_config
[[ $GCP_DEPLOY_SA == "$DEPLOY_SA_EMAIL" ]] ||
	die "GCP_DEPLOY_SA is not the deployer DEPLOY_SA_NAME of project PROJECT_ID in DEPLOY_ENV"

if [[ ${SKIP_GCLOUD_INSTALL:-} != 1 ]]; then
	[[ $(uname -sm) == "Linux x86_64" ]] || die "the pinned gcloud is for Linux x86_64"
	need sha256sum tar
	say "installing gcloud $GCLOUD_VERSION"
	curl -fsSL --retry 3 --max-time 300 -o "$work/gcloud.tar.gz" "$GCLOUD_URL"
	printf '%s  %s\n' "$GCLOUD_SHA256" "$work/gcloud.tar.gz" | sha256sum -c --status - ||
		die "gcloud $GCLOUD_VERSION: SHA-256 mismatch, refusing to run it"
	tar -xzf "$work/gcloud.tar.gz" -C "$work"
	rm -f "$work/gcloud.tar.gz"
	PATH=$work/google-cloud-sdk/bin:$PATH
fi
# A configuration and Docker credentials of this job only. The deployer may
# not query which APIs are enabled, so gcloud is told not to.
export CLOUDSDK_CONFIG=$work/gcloud DOCKER_CONFIG=$work/docker CLOUDSDK_CORE_DISABLE_PROMPTS=1 \
	CLOUDSDK_CORE_DISABLE_USAGE_REPORTING=true CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK=true \
	CLOUDSDK_CORE_SHOULD_PROMPT_TO_ENABLE_API=false

# Credential configuration for an external account (the format gcloud iam
# workload-identity-pools create-cred-config writes), built by jq from the
# environment so that the request token never appears in a process argument.
# gcloud requests a fresh OIDC token from this URL whenever it needs one.
jq -n '
	("https://iam.googleapis.com/" + env.GCP_WIF_PROVIDER) as $aud |
	{
		universe_domain: "googleapis.com",
		type: "external_account",
		audience: ("//iam.googleapis.com/" + env.GCP_WIF_PROVIDER),
		subject_token_type: "urn:ietf:params:oauth:token-type:jwt",
		token_url: "https://sts.googleapis.com/v1/token",
		credential_source: {
			url: (env.ACTIONS_ID_TOKEN_REQUEST_URL + "&audience=" + ($aud | @uri)),
			headers: {Authorization: ("Bearer " + env.ACTIONS_ID_TOKEN_REQUEST_TOKEN)},
			format: {type: "json", subject_token_field_name: "value"}
		},
		service_account_impersonation_url: ("https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" + env.GCP_DEPLOY_SA + ":generateAccessToken")
	}' >"$work/credentials.json"
# From here on only gcloud, through that file, can obtain tokens.
unset ACTIONS_ID_TOKEN_REQUEST_URL ACTIONS_ID_TOKEN_REQUEST_TOKEN

gcloud auth login --cred-file="$work/credentials.json" --quiet
gcloud auth configure-docker "$REGION-docker.pkg.dev" --quiet
YES=1 UPDATE_ONLY=1 "$ROOT/scripts/deploy.sh"
