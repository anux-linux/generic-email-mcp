#!/usr/bin/env bash
# Lets GitHub Actions deploy the service (.github/workflows/deploy.yml)
# without any stored key, through Workload Identity Federation. Run it once
# as the project owner, after the first scripts/deploy.sh. Safe to re-run:
# it also brings the provider's condition up to date.
#
#   scripts/gcp-github.sh
#
# It sets up:
# - the pool WIF_POOL, used for nothing else, with the OIDC provider
#   WIF_PROVIDER for GitHub as its only provider. All providers of a pool
#   map into the same principals, so the grant below to
#   attribute.repository_id would admit this repository's tokens through
#   any other provider of the pool, whatever its condition. Google's best
#   practice is one provider per pool; the script refuses a pool holding
#   any other provider. The provider accepts a GitHub token only if every one of these claims
#   matches: repository ID and owner ID (immune to renames and to a
#   re-created repository of the same name), ref refs/heads/main,
#   environment production, the workflow file deploy.yml on main, and a
#   GitHub-hosted runner. Branch and environment are fixed here and in
#   .github/workflows/deploy.yml (scripts_test.go checks both agree).
# - the deployer service account DEPLOY_SA_NAME, which only such tokens can
#   impersonate. It gets no project role, only these, each on one resource:
#     roles/run.developer            the Cloud Run service
#     roles/iam.serviceAccountUser   the runtime service account
#     roles/artifactregistry.writer  the Docker repository
#     roles/secretmanager.viewer     each of the four secrets (metadata: the
#                                    version numbers, never the values)
# The deployer cannot create services or change who may invoke one; that is
# why the service must exist first.
set -euo pipefail
# shellcheck source=lib/gcp.sh
. "$(dirname "$0")/lib/gcp.sh"
load_config
need gcloud

[[ -n ${CD_REPO:-} && -n ${CD_REPO_ID:-} && -n ${CD_OWNER_ID:-} ]] ||
	die "set CD_REPO, CD_REPO_ID and CD_OWNER_ID in $CONFIG (see deploy.env.example)"

ISSUER=https://token.actions.githubusercontent.com
WORKFLOW=.github/workflows/deploy.yml
BRANCH=main
ENVIRONMENT=production

# The values are validated in load_config: none can contain a quote.
condition="assertion.repository_id == '$CD_REPO_ID'"
condition+=" && assertion.repository_owner_id == '$CD_OWNER_ID'"
condition+=" && assertion.ref == 'refs/heads/$BRANCH'"
condition+=" && assertion.environment == '$ENVIRONMENT'"
condition+=" && assertion.workflow_ref == '$CD_REPO/$WORKFLOW@refs/heads/$BRANCH'"
condition+=" && assertion.runner_environment == 'github-hosted'"
mapping=google.subject=assertion.sub,attribute.repository_id=assertion.repository_id
member=serviceAccount:$DEPLOY_SA_EMAIL

[[ -n $(gc run services list --region="$REGION" --filter="metadata.name=$SERVICE" --format='value(metadata.name)') ]] ||
	die "service $SERVICE does not exist in $REGION yet; deploy it once with scripts/deploy.sh"
for key in "${SECRET_KEYS[@]}"; do
	gc secrets describe "$(secret_id "$key")" >/dev/null 2>&1 || die "secret $(secret_id "$key") is missing; run scripts/gcp-secrets.sh $key"
done

say "project $PROJECT_ID, account $(account)"
say "provider $WIF_POOL/$WIF_PROVIDER accepts GitHub tokens where $condition"
say "deployer $DEPLOY_SA_EMAIL"
confirm "Set up keyless deploys from $CD_REPO ($BRANCH, environment $ENVIRONMENT)?"

# The APIs Google's guide lists for federation from deployment pipelines.
mut services enable iam.googleapis.com cloudresourcemanager.googleapis.com \
	iamcredentials.googleapis.com sts.googleapis.com
number=$(gc projects describe "$PROJECT_ID" --format='value(projectNumber)')
[[ $number =~ ^[0-9]+$ ]] || die "could not read the project number of $PROJECT_ID"
pool=projects/$number/locations/global/workloadIdentityPools/$WIF_POOL
provider=$pool/providers/$WIF_PROVIDER

# state <describe command...>: ACTIVE, DELETED (restorable for 30 days,
# and its ID cannot be reused meanwhile) or empty when it does not exist.
state() { gc "$@" --format='value(state)' 2>/dev/null || true; }

case $(state iam workload-identity-pools describe "$WIF_POOL" --location=global) in
"") mut iam workload-identity-pools create "$WIF_POOL" --location=global --display-name="email-mcp GitHub deploys" ;;
ACTIVE) say "pool $WIF_POOL exists" ;;
*) die "pool $WIF_POOL is deleted; restore it: gcloud iam workload-identity-pools undelete $WIF_POOL --location=global" ;;
esac

# The pool must hold no provider but ours (see above). A failing list stops
# the script rather than skipping the check.
listed=$(gc iam workload-identity-pools providers list --workload-identity-pool="$WIF_POOL" --location=global \
	--format='value(name.basename())') || die "cannot list the providers of pool $WIF_POOL"
others=""
for p in $listed; do
	[[ $p == "$WIF_PROVIDER" ]] || others+=${others:+, }$p
done
[[ -z $others ]] || die "pool $WIF_POOL also holds the provider(s) $others, whose tokens would map to the same principals; set WIF_POOL to a pool used only for this service"

oidc=(--workload-identity-pool="$WIF_POOL" --location=global --issuer-uri="$ISSUER"
	--attribute-mapping="$mapping" --attribute-condition="$condition")
case $(state iam workload-identity-pools providers describe "$WIF_PROVIDER" --workload-identity-pool="$WIF_POOL" --location=global) in
"") mut iam workload-identity-pools providers create-oidc "$WIF_PROVIDER" "${oidc[@]}" --display-name="GitHub deploy" ;;
ACTIVE) mut iam workload-identity-pools providers update-oidc "$WIF_PROVIDER" "${oidc[@]}" ;;
*) die "provider $WIF_PROVIDER is deleted; restore it: gcloud iam workload-identity-pools providers undelete $WIF_PROVIDER --workload-identity-pool=$WIF_POOL --location=global" ;;
esac

if gc iam service-accounts describe "$DEPLOY_SA_EMAIL" >/dev/null 2>&1; then
	say "$DEPLOY_SA_EMAIL exists"
else
	mut iam service-accounts create "$DEPLOY_SA_NAME" --display-name="email-mcp deployer (GitHub Actions)"
fi

# A new service account can take a while to become visible to IAM.
retry() {
	local i
	for i in 1 2 3 4 5 6; do
		"$@" && return 0
		[[ $i == 6 ]] && return 1
		say "retrying in 10 s"
		sleep 10
	done
}

retry mut iam service-accounts add-iam-policy-binding "$DEPLOY_SA_EMAIL" --role=roles/iam.workloadIdentityUser \
	--member="principalSet://iam.googleapis.com/$pool/attribute.repository_id/$CD_REPO_ID" >/dev/null
retry mut run services add-iam-policy-binding "$SERVICE" --region="$REGION" \
	--member="$member" --role=roles/run.developer >/dev/null
retry mut iam service-accounts add-iam-policy-binding "$SA_EMAIL" \
	--member="$member" --role=roles/iam.serviceAccountUser >/dev/null
retry mut artifacts repositories add-iam-policy-binding "$REPOSITORY" --location="$REGION" \
	--member="$member" --role=roles/artifactregistry.writer >/dev/null
for key in "${SECRET_KEYS[@]}"; do
	retry mut secrets add-iam-policy-binding "$(secret_id "$key")" \
		--member="$member" --role=roles/secretmanager.viewer >/dev/null
done

printf '%s\n' "" "Done. In GitHub, create the environment $ENVIRONMENT (Settings > Environments) with:" \
	"  Deployment branches   Selected branches: $BRANCH" \
	"  Variable GCP_WIF_PROVIDER   $provider" \
	"  Variable GCP_DEPLOY_SA      $DEPLOY_SA_EMAIL" \
	"  Secret   DEPLOY_ENV         the content of deploy.env" \
	"" "Or with the GitHub CLI:" \
	"  gh api -X PUT repos/$CD_REPO/environments/$ENVIRONMENT -F 'deployment_branch_policy[protected_branches]=false' -F 'deployment_branch_policy[custom_branch_policies]=true'" \
	"  gh api -X POST repos/$CD_REPO/environments/$ENVIRONMENT/deployment-branch-policies -f name=$BRANCH -f type=branch" \
	"  gh variable set GCP_WIF_PROVIDER --repo $CD_REPO --env $ENVIRONMENT --body $provider" \
	"  gh variable set GCP_DEPLOY_SA --repo $CD_REPO --env $ENVIRONMENT --body $DEPLOY_SA_EMAIL" \
	"  gh secret set DEPLOY_ENV --repo $CD_REPO --env $ENVIRONMENT < deploy.env"
