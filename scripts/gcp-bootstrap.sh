#!/usr/bin/env bash
# One-time project setup: enables the APIs the service needs and creates
# its runtime service account. The account gets no project roles; it can
# read only its own secrets (scripts/gcp-secrets.sh grants that per secret).
# Safe to re-run.
#
#   scripts/gcp-bootstrap.sh
set -euo pipefail
# shellcheck source=lib/gcp.sh
. "$(dirname "$0")/lib/gcp.sh"
load_config
need gcloud

confirm "Enable APIs and create $SA_EMAIL in project $PROJECT_ID as $(account)?"
mut services enable run.googleapis.com artifactregistry.googleapis.com secretmanager.googleapis.com iam.googleapis.com
if gc iam service-accounts describe "$SA_EMAIL" >/dev/null 2>&1; then
	say "$SA_EMAIL exists"
else
	mut iam service-accounts create "$RUNTIME_SA_NAME" \
		--display-name="email-mcp runtime (reads its own secrets only)"
fi
say "done; next: scripts/gcp-registry.sh"
