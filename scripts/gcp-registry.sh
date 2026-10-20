#!/usr/bin/env bash
# Creates the Artifact Registry Docker repository (immutable tags) and
# applies deploy/cleanup-policy.json: keep the 2 newest images, delete the
# rest. That keeps storage far below the 0.5 GB free tier. Safe to re-run.
#
#   scripts/gcp-registry.sh
#
# Cleanup runs asynchronously (about daily), not at push time. Never roll
# Cloud Run back to a revision whose image has been cleaned up: with
# min-instances 0 it could not start.
set -euo pipefail
# shellcheck source=lib/gcp.sh
. "$(dirname "$0")/lib/gcp.sh"
load_config
need gcloud

POLICY=$ROOT/deploy/cleanup-policy.json
confirm "Create/update repository $REPOSITORY ($REGION) in project $PROJECT_ID as $(account)?"
if gc artifacts repositories describe "$REPOSITORY" --location="$REGION" >/dev/null 2>&1; then
	say "repository $REPOSITORY exists"
else
	mut artifacts repositories create "$REPOSITORY" --repository-format=docker --location="$REGION" \
		--immutable-tags --description="email-mcp images; cleanup keeps the newest 2"
fi
mut artifacts repositories set-cleanup-policies "$REPOSITORY" --location="$REGION" \
	--policy="$POLICY" --no-dry-run >/dev/null
say "done; next: scripts/gcp-secrets.sh all"
