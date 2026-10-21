#!/usr/bin/env bash
# Builds the image, pushes it to Artifact Registry and deploys it to Cloud Run.
#
#   scripts/deploy.sh          # shows what it will do and asks first
#   YES=1 scripts/deploy.sh    # no question
#
# The first deploy is two-step: deploy without BASE_URL (setup mode: only
# /healthz) to learn the service URL, then redeploy with BASE_URL set to it.
# The deterministic URL (https://SERVICE-PROJECT_NUMBER.REGION.run.app) is
# preferred when the service has one. Later deploys take one step and keep
# the BASE_URL the service already has: changing it would invalidate every
# token and the claude.ai connector. Every deploy is complete and declarative:
# flags, environment (from deploy.env) and secrets (newest enabled version,
# pinned by number) are all set, so nothing is inherited from an earlier
# revision. The image is deployed by digest.
#
# UPDATE_ONLY=1 (set by scripts/ci-deploy.sh) updates an existing service
# and leaves its public access as it is. The deploying identity then needs
# rights on this one service only, not on the project (scripts/gcp-github.sh).
#
# Prerequisites: scripts/gcp-bootstrap.sh, scripts/gcp-registry.sh,
# scripts/gcp-secrets.sh all, and
# gcloud auth configure-docker <REGION>-docker.pkg.dev
set -euo pipefail
# shellcheck source=lib/gcp.sh
. "$(dirname "$0")/lib/gcp.sh"
load_config
need gcloud docker git curl jq

# --- what to deploy -------------------------------------------------------------
tag=$(git -C "$ROOT" rev-parse --short=12 HEAD)
if [[ -n $(git -C "$ROOT" status --porcelain) ]]; then
	[[ ${ALLOW_DIRTY:-} == 1 ]] || die "the working tree has uncommitted changes; commit them, or set ALLOW_DIRTY=1"
	tag=$tag-dirty-$(date -u +%Y%m%d%H%M%S)
fi

describe() { gc run services describe "$SERVICE" --region="$REGION" --format=json; }
# current_base_url <describe json>: BASE_URL of the latest revision template.
current_base_url() {
	printf '%s' "$1" | jq -r '[.spec.template.spec.containers[0].env[]? | select(.name == "BASE_URL") | .value][0] // empty'
}
# service_url <describe json>: the deterministic URL if listed, else status.url.
service_url() {
	printf '%s' "$1" | jq -r --arg re "^https://$SERVICE-[0-9]+\\.$REGION\\.run\\.app$" '
		((.metadata.annotations["run.googleapis.com/urls"] // "[]") | fromjson | map(select(test($re))) | .[0])
		// .status.url // empty'
}

# mask_urls <describe json>: every URL of the service (gcloud prints one
# after each deploy) is masked in the public GitHub Actions log.
mask_urls() {
	printf '%s' "$1" | jq -r '((.metadata.annotations["run.googleapis.com/urls"] // "[]") | fromjson[]), (.status.url // empty)' |
		while IFS= read -r u; do mask "$u"; done
}

# Listing services needs a project-wide permission; in UPDATE_ONLY mode the
# service must exist, and describe fails if it does not.
if [[ ${UPDATE_ONLY:-} == 1 ]]; then
	exists=$SERVICE
else
	exists=$(gc run services list --region="$REGION" --filter="metadata.name=$SERVICE" --format='value(metadata.name)')
fi
url=${BASE_URL:-}
if [[ -n $exists ]]; then
	svc=$(describe) || die "cannot read service $SERVICE; it must exist (a first scripts/deploy.sh as owner) and be readable"
	mask_urls "$svc"
	[[ -n $url ]] || url=$(current_base_url "$svc")
fi
mask "$url"

secrets=""
for key in "${SECRET_KEYS[@]}"; do
	id=$(secret_id "$key")
	v=$(gc secrets versions list "$id" --filter=state=ENABLED --sort-by=~createTime --limit=1 \
		--format='value(name.basename())' 2>/dev/null || true)
	[[ $v =~ ^[0-9]+$ ]] || die "secret $id has no enabled version; run scripts/gcp-secrets.sh $key"
	secrets+=${secrets:+,}$key=$id:$v
done

if [[ -n $url ]]; then plan="deploy $SERVICE with BASE_URL=$url"
elif [[ -n $exists ]]; then plan="finish setting up $SERVICE (two steps)"
else plan="create $SERVICE (two steps)"; fi
say "project $PROJECT_ID, region $REGION, account $(account)"
say "image $IMAGE:$tag"
say "secrets ${secrets//,/ }"
confirm "Build, push and $plan?"

# --- image -------------------------------------------------------------------------
digest_of() { gc artifacts docker images describe "$1" --format='value(image_summary.digest)' 2>/dev/null || true; }
digest=$(digest_of "$IMAGE:$tag")
if [[ -n $digest ]]; then
	say "image $IMAGE:$tag already pushed; reusing it"
else
	# Single-platform manifest without attestations: one registry version
	# per deploy, which the keep-2 cleanup policy counts as expected.
	docker build --platform linux/amd64 --provenance=false --sbom=false \
		--build-arg VERSION="$tag" -t "$IMAGE:$tag" "$ROOT"
	docker push "$IMAGE:$tag"
	digest=$(digest_of "$IMAGE:$tag")
fi
[[ $digest =~ ^sha256:[0-9a-f]{64}$ ]] || die "could not resolve the digest of $IMAGE:$tag"

# --- deploy ------------------------------------------------------------------------
# env_vars <base url or empty>: the service environment in gcloud's
# alternate-delimiter syntax (values may contain commas, e.g. SEND_ALLOWLIST).
env_vars() {
	local out="" key val
	for key in "${APP_KEYS[@]}"; do
		[[ $key == BASE_URL ]] && continue
		val=${!key-}
		[[ -n $val ]] && out+=${out:+|}$key=$val
	done
	[[ -n $1 ]] && out+=${out:+|}BASE_URL=$1
	printf '^|^%s' "$out"
}

# Public access is part of every deploy, except in UPDATE_ONLY mode: setting
# it changes the service's IAM policy, which a deployer limited to
# roles/run.developer may not do. The setting persists across revisions.
access=()
[[ ${UPDATE_ONLY:-} == 1 ]] || access=("$(access_flag)")

# --max-instances caps each revision, --max the whole service.
deploy() {
	mut run deploy "$SERVICE" --region="$REGION" --image="$IMAGE@$digest" \
		--service-account="$SA_EMAIL" ${access[@]+"${access[@]}"} --ingress=all --port=8080 \
		--min-instances=0 --max-instances=1 --max=1 --cpu=1 --memory=256Mi --timeout=60 \
		--execution-environment=gen1 --cpu-throttling \
		--set-env-vars="$(env_vars "$1")" --set-secrets="$secrets"
}

if [[ -z $url ]]; then
	say "step 1/2: deploy in setup mode to learn the service URL"
	deploy ""
	svc=$(describe)
	mask_urls "$svc"
	url=$(service_url "$svc")
	[[ $url =~ ^https://[a-z0-9.-]+$ ]] || die "unexpected service URL '$url'"
	say "step 2/2: redeploy with BASE_URL=$url"
fi
deploy "$url"

# --- verify ------------------------------------------------------------------------
ok=""
for _ in $(seq 30); do
	curl -fsS --max-time 10 "$url/healthz" >/dev/null 2>&1 && { ok=1; break; }
	sleep 2
done
[[ -n $ok ]] || die "$url/healthz did not answer"
curl -fsS --max-time 10 "$url/.well-known/oauth-protected-resource/mcp" |
	jq -e --arg r "$url/mcp" '.resource == $r' >/dev/null ||
	die "the protected resource metadata does not name $url/mcp; is BASE_URL right?"
code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 -X POST "$url/mcp")
[[ $code == 401 ]] || die "POST $url/mcp without a token answered $code, want 401"

printf '%s\n' "" "Deployed $IMAGE@$digest" "" \
	"claude.ai connector (Settings > Connectors > Add custom connector):" \
	"  URL            $url/mcp" \
	"  Client ID      $OAUTH_CLIENT_ID" \
	"  Client secret  the OAUTH_CLIENT_SECRET value from scripts/gen-secrets.sh"
