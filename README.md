# generic-email-mcp

A single-user MCP server in Go that lets claude.ai read one IMAP mailbox
(Strato by default) and create and send mail. It runs on Google Cloud Run's
free tier. There is no web UI: one mailbox, one owner, one OAuth client
(claude.ai).

> **Status: all five phases built** (mail core, MCP tools, HTTP + OAuth, test
> hardening, packaging). The deploy scripts have been validated locally
> against gcloud 570.0.0 with fakes, but never run against a real project.
> The first real deploy and the checks in `docs/INSPECTOR.md` Parts B and C
> are still open (`docs/VERIFY.md`).

- [Setup](#setup)
- [Connecting claude.ai](#connecting-claudeai)
- [Operating](#operating)
- [Security model](#security-model)
- [Costs and budget alert](#costs-and-budget-alert)
- [Configuration reference](#configuration-reference)
- [Tools](#tools)
- [Development](#development)

## Setup

**You need:**

- a Google Cloud project with billing enabled;
- the gcloud CLI (validated with 570.0.0);
- Docker with BuildKit (Docker ≥ 23);
- Go 1.27.3, only for hashing the owner password;
- git, curl, jq and bash (3.2 or later; macOS's default works).

All scripts read `deploy.env`, show what they will change and ask first.
`YES=1` skips the question. Re-running any of them is safe.

```sh
# 0. Configuration (deploy.env is git-ignored and must never hold secrets)
cp deploy.env.example deploy.env && $EDITOR deploy.env

# 1. Sign in; let Docker push to Artifact Registry in your region
gcloud auth login
gcloud auth configure-docker europe-west1-docker.pkg.dev

# 2. Generate the token signing key and the OAuth client ID and secret.
#    They are printed once and saved nowhere. Put OAUTH_CLIENT_ID into
#    deploy.env, and keep the client ID and secret for step 6.
scripts/gen-secrets.sh

# 3. Enable the APIs and create the runtime service account (no project roles)
scripts/gcp-bootstrap.sh

# 4. Create the Docker repository with a cleanup policy that keeps the newest 2 images
scripts/gcp-registry.sh

# 5. Store the four secrets in Secret Manager. Input is hidden. For the
#    owner password the script stores only its argon2id hash.
scripts/gcp-secrets.sh all

# 6. Build, push and deploy. The first run takes two steps: setup mode to
#    learn the URL, then BASE_URL is set. It ends by printing the connector
#    URL and client ID.
scripts/deploy.sh

# 7. Set up the budget alert (see Costs and budget alert)
```

What each script does:

| Script | Effect |
|---|---|
| `gen-secrets.sh` | Generates 32 random bytes each for the signing key and client secret, plus a 96-bit client ID. Refuses to run unless stdout is a terminal, so the values can't land in a file. |
| `gcp-bootstrap.sh` | Enables `run`, `artifactregistry`, `secretmanager` and `iam`. Creates the service account `RUNTIME_SA_NAME` with no roles. |
| `gcp-registry.sh` | Creates the Docker repository with immutable tags and applies `deploy/cleanup-policy.json` (keep the 2 newest, delete the rest, enforced rather than dry-run). |
| `gcp-secrets.sh` | Creates each secret in `REGION` (user-managed replication), adds a version from a hidden prompt or stdin, and grants `roles/secretmanager.secretAccessor` on that one secret to the runtime account. |
| `deploy.sh` | Builds a linux/amd64 image tagged with the git commit and refuses a dirty tree unless `ALLOW_DIRTY=1`. Pushes it, then deploys it by digest with every flag, variable and secret set explicitly. Secrets are pinned to the newest enabled version number. Finally it checks `/healthz`, the metadata and the 401 challenge. |

**Cloud Run settings** (in `scripts/deploy.sh`):

| Flag | Why |
|---|---|
| `--allow-unauthenticated` | claude.ai connects from the internet. All authentication is in the app. If your organization forbids `allUsers` (domain restricted sharing), set `PUBLIC_ACCESS=no-invoker-iam-check`. |
| `--min-instances=0` | Scale to zero, so it costs nothing while idle. |
| `--max-instances=1 --max=1` | One instance per revision and per service. Send-cap and token-rotation locks are per process, and the cost under attack is bounded (D21, D30, VERIFY H3). |
| `--cpu=1 --memory=256Mi --execution-environment=gen1` | gen2 needs at least 512 MiB. |
| `--cpu-throttling` | Request-based billing, which has the free tier that includes requests. |
| `--timeout=60` | Tool calls are capped at 45 s inside the app. |
| `--service-account=<runtime SA>` | Not the default compute account, which has Editor. |
| `--set-secrets=…:<version>` | Secret values are resolved at instance start; Google recommends pinning versions for that. |

## Connecting claude.ai

In claude.ai, open **Settings → Connectors → Add custom connector**:

1. **URL:** `https://<service-host>/mcp`, exactly as `scripts/deploy.sh`
   printed it. The host must match `BASE_URL`.
2. Under **Advanced settings**, enter the **OAuth Client ID**
   (`OAUTH_CLIENT_ID`) and **OAuth Client Secret** from step 2.
3. Click **Add**, then **Connect**. A login window opens on `/authorize`.
   Sign in as `owner` (`AUTHORIZE_USERNAME`) with the owner password from
   step 5. Claude then lists the seven tools.
4. Recommended: set `mail_send_draft` to always ask for approval.

If the browser shows no password dialog, set `AUTHORIZE_LOGIN=form` in
`deploy.env` and run `scripts/deploy.sh` again (VERIFY C1). Before trusting
the setup with real mail, run the checks in `docs/INSPECTOR.md` Parts B
and C.

## Operating

| Task | How |
|---|---|
| Deploy a new version | Commit, then `scripts/deploy.sh`. |
| Rotate a secret | `scripts/gcp-secrets.sh <NAME>`, then `scripts/deploy.sh`. Versions are pinned, so the new one is used from that deploy on. Once it serves, destroy the old version (`gcloud secrets versions destroy N --secret=…`): Secret Manager bills active versions above 6. |
| Revoke every token | Increase `TOKEN_EPOCH` in `deploy.env`, then `scripts/deploy.sh`. claude.ai asks you to log in again. |
| Roll back | `gcloud run services update-traffic SERVICE --region=REGION --to-revisions=REVISION=100`. Only to a revision whose image is one of the 2 kept; with scale-to-zero, an older revision cannot start. |
| Logs | Cloud Logging, service `SERVICE`. They contain no addresses, subjects, bodies, IDs or tokens (D20). |
| Remove everything | Delete the Cloud Run service, the repository, the four secrets and the service account. The mailbox folders `MCP-Send-Ledger` and `MCP-Auth-State` can be deleted in webmail. |

`BASE_URL` stays fixed across deploys. `deploy.sh` keeps the value the
service already has, because changing it invalidates every token and the
connector. Set `BASE_URL` in `deploy.env` only to move deliberately.

## Security model

**Assets:**

- the mailbox (read access, and sending as you);
- the mailbox password;
- the OAuth client secret, token signing key and owner password.

**Trust:**

- You trust Google Cloud (Cloud Run, Secret Manager, IAM), Anthropic
  (claude.ai sees what the tools return) and Strato.
- Everything else reaching the public URL is untrusted. So is all mail
  content: anyone can send you an email.

| Threat | Controls |
|---|---|
| Anyone on the internet calls `/mcp` | A bearer token is required: HS256 JWT with `typ` `at+jwt`, audience = this resource, issuer, epoch, 1 h lifetime. Only `/healthz` and the OAuth metadata are public. |
| Anyone tries to obtain tokens | One confidential client (ID + secret), no dynamic registration. Exact redirect URI allowlist (claude.ai's callback). PKCE S256 is mandatory; RFC 8707 resource binding and RFC 9207 `iss` are supported. The owner authenticates on `/authorize` (argon2id hash). Per-IP and global rate limits on `/authorize` and `/token`. |
| Stolen or replayed refresh token | Rotation on every use. Reusing an old token revokes the whole family, and this is recorded durably in the mailbox, so it survives restarts (D30). `TOKEN_EPOCH` revokes everything. |
| Prompt injection in an email | Mail content reaches the model only inside a fenced block with a random boundary, and tag look-alikes are neutralized. Hidden HTML and invisible Unicode are removed. Tool descriptions and server instructions forbid following mail content. The model cannot send on its own: see the next row. |
| The model is talked into sending mail | Only drafts created by this server, unchanged since (HMAC over the content), can be sent, and only with `confirm: true` after you approved. Claude's own tool approval adds a second gate. `SEND_ALLOWLIST` limits recipients and `MAX_SENDS_PER_DAY` caps volume; the cap is counted durably in the mailbox. From is always your address, and Bcc is never transmitted in the headers. |
| The model is talked into destroying mail | Impossible through this server: EXPUNGE, CLOSE, DELETE and STORE `\Deleted` are blocked on the wire; "delete" means moving to Trash. Reading never marks mail as read. The model cannot touch the ledger and auth-state folders. |
| Secret leakage | The secrets live in Secret Manager in your region. The runtime service account can read only those four and has no other role. The scripts refuse secrets in `deploy.env`, pass values only through pipes, and `gen-secrets.sh` writes nothing to disk. A redacting log handler is enforced by tests; the image has no shell. |
| Supply chain | Go modules pinned in `go.sum` and verified. govulncheck in the gate. Base images pinned by digest; distroless static, nonroot (65532), CGO-free static binary. CI actions are referenced by exact tag rather than commit SHA (your decision, D35). |
| Cost abuse / DoS | At most 1 instance and request size limits. Per-IP and global rate limits on `/authorize` and `/token` answer 429 before any password hashing. A forged bearer token costs one HMAC check. Budget alert (below). |

**Residual risks** (accepted or open):

- Whoever controls your claude.ai account can read your mail and send
  within the allowlist and cap. Use strong authentication there.
- Without `SEND_ALLOWLIST`, a manipulated model could draft mail to anyone;
  only your approval stops it. Set an allowlist.
- The mailbox password is your full Strato password; whether Strato offers
  app-specific passwords is unverified. Anyone with Secret Manager access
  in the project can read it, so keep project IAM minimal.
- Mail content you ask about is processed by Anthropic.
- During a rollout or traffic spike, Cloud Run can briefly run more than one
  instance. That could allow one extra send, or one refresh reuse that goes
  undetected (VERIFY H3).
- The owner password is the last line of defence on `/authorize`. Use 16 or
  more random characters; it is rate-limited and hashed with argon2id.

## Costs and budget alert

The deployment is designed to stay within the free tiers, which are per
billing account and monthly (checked against Google's pricing pages on
2026-10-20; VERIFY H5):

| Service | Free tier | This deployment |
|---|---|---|
| Cloud Run, request-based billing | 180,000 vCPU-s, 360,000 GiB-s, 2 M requests; priced at Tier 1 rates (europe-west1 is Tier 1) | idle costs nothing; each tool call is billed for its duration (a few seconds, mostly IMAP round trips), so even 1,000 calls a month use under 5 % of the free tier |
| Artifact Registry | 0.5 GB storage; same-region pulls are free | 2 images of about 12 MB compressed each |
| Secret Manager | 6 active versions, 10,000 accesses | 4 versions; 4 accesses per instance start |
| Cloud Logging | 50 GiB ingestion | a few KB per day |

**Budgets notify; they do not cap spending.** Create an alert at a small
amount (in your billing account's currency) so you hear about any charge
early:

```sh
PROJECT_ID=my-project-id
gcloud services enable billingbudgets.googleapis.com --project="$PROJECT_ID"
BILLING=$(gcloud billing projects describe "$PROJECT_ID" --format='value(billingAccountName.basename())')
gcloud billing budgets create --billing-account="$BILLING" --display-name="email-mcp" \
  --budget-amount=1 --filter-projects="projects/$PROJECT_ID" \
  --threshold-rule=percent=0.5 --threshold-rule=percent=0.9 \
  --threshold-rule=percent=1.0 --threshold-rule=percent=1.0,basis=forecasted-spend
```

Alerts are emailed to the billing account's administrators and users.
Google's documentation also describes a newer **spend cap** budget type (GA
on 2026-10-13). It pauses Cloud Run when the cap is reached; enforcement is
not instant and overages are still billed. It is set in the console or
through the Budget API, not with gcloud. The recipe above does not use it
(VERIFY H6).

## Configuration reference

`deploy.env` holds the deployment settings (`PROJECT_ID`, `REGION`,
`SERVICE`, `REPOSITORY`, `RUNTIME_SA_NAME`, `PUBLIC_ACCESS`) and the service
variables below. It is parsed as `KEY=value`, never executed; unknown keys
and secrets are rejected. Secrets (★) come from Secret Manager.

### Service

| Variable | Default | Notes |
|---|---|---|
| `BASE_URL` | set by `deploy.sh` | `https://<service-host>` without a path. Unset = setup mode (only `/healthz`) |
| `PORT` | `8080` | set by Cloud Run |
| `OAUTH_CLIENT_ID` | — (required) | 8–128 characters of `[A-Za-z0-9._~-]`; you enter it in claude.ai |
| `OAUTH_CLIENT_SECRET` ★ | — (required) | ≥ 32 characters; you enter it in claude.ai |
| `OAUTH_REDIRECT_URIS` | `https://claude.ai/api/mcp/auth_callback` | exact-match allowlist, comma separated |
| `TOKEN_SIGNING_KEY` ★ | — (required) | base64 of ≥ 32 random bytes; the keys for tokens, login form and draft IDs are derived from it |
| `TOKEN_EPOCH` | `1` | change it to revoke every issued token |
| `AUTHORIZE_PASSWORD_HASH` ★ | — (required) | argon2id from `email-mcp hash-password`, or bcrypt (cost ≥ 10) |
| `AUTHORIZE_LOGIN` | `basic` | `basic` (browser password prompt) or `form` (HTML form) |
| `AUTHORIZE_USERNAME` | `owner` | Basic-auth user name |
| `TRUSTED_PROXY_HOPS` | `1` | proxies that append to `X-Forwarded-For` (Cloud Run: 1) |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `AUTH_STATE` | `imap` | `imap`: refresh-token rotation and revocation survive restarts (mailbox folder); `memory`: in process only |
| `AUTH_STATE_FOLDER` | `MCP-Auth-State` | created on first login; the tools cannot move mail into or out of it |

### Mail

| Variable | Default | Notes |
|---|---|---|
| `MAIL_USERNAME` | — (required) | for Strato, the full address |
| `MAIL_PASSWORD` ★ | — (required) | |
| `MAIL_IMAP_ADDR` | `imap.strato.de:993` | implicit TLS only |
| `MAIL_SMTP_ADDR` | `smtp.strato.de:465` | implicit TLS only |
| `MAIL_FROM` | `MAIL_USERNAME` | bare address |
| `MAIL_FROM_NAME` | empty | display name |
| `MAIL_SMTP_HELO` | `[127.0.0.1]` | EHLO name |
| `MAIL_FOLDER_SENT` / `_DRAFTS` / `_TRASH` / `_ARCHIVE` | discovered | exact folder names; must exist |
| `MAIL_SAVE_SENT` | `true` | APPEND a copy to Sent after sending |
| `MAIL_MAX_BODY_BYTES` | `65536` | cap on returned body text |

### Send policy

| Variable | Default | Notes |
|---|---|---|
| `SEND_ALLOWLIST` | empty (no restriction) | exact addresses or domains (`example.org`, `@example.org`), comma or space separated; subdomains do not match; applies to To, Cc and Bcc |
| `MAX_SENDS_PER_DAY` | `20` | messages per rolling 24 h; `0` disables sending |
| `SEND_LEDGER` | `imap` | `imap`: sends counted durably in a mailbox folder (survives restarts); `memory`: in process only |
| `SEND_LEDGER_FOLDER` | `MCP-Send-Ledger` | created on first send; the tools cannot move mail into or out of it |

## Tools

| Tool | Effect |
|---|---|
| `mail_list_folders` | folders with role and counts |
| `mail_search` | one folder; from/to/subject/body/since/before/unread; newest first, max 100 |
| `mail_read` | one message as plain text plus attachment metadata; never marks it as read |
| `mail_create_draft` | saves a plain-text draft (optionally a reply); sends nothing |
| `mail_send_draft` | sends a draft from `mail_create_draft`; requires `confirm: true`; returns the exact recipients and subject |
| `mail_move` | moves messages; `destination: "trash"` is "delete" |
| `mail_mark_read` | marks read, or unread with `unread: true` |

## Development

Go 1.27.3 (`GOTOOLCHAIN=auto` downloads it). No test touches a real mailbox
or a cloud account.

```sh
scripts/check.sh                # gofmt, mod verify/tidy, vet, go test -race -shuffle=on, shellcheck (if installed), staticcheck, govulncheck
FUZZTIME=30s scripts/check.sh   # plus 30 s per fuzz target
scripts/image-check.sh          # build the production image and smoke-test it (needs Docker)
scripts/inspector-local.sh      # the real binary + MCP Inspector 2.11.0 CLI against a fake mailbox (Linux, needs Node ≥ 22.19, jq)
```

CI (`.github/workflows/ci.yml`) runs the gate, the image check and the
Inspector checklist on every push; the fuzz pass runs weekly. See
`docs/TESTING.md` for what each test proves.

| Path | Contents |
|---|---|
| `cmd/email-mcp` | the binary (`serve`, `hash-password`, `version`) |
| `internal/mail` | IMAP/SMTP core behind the `mail.Mailbox` interface |
| `internal/mcptools` | the MCP server and its seven tools |
| `internal/policy` | send allowlist and rolling 24 h send cap (durable via a mailbox ledger) |
| `internal/oauth` | OAuth 2.1 authorization server (one client, one owner) and token verifier |
| `internal/authstate` | durable token-family journal in the mailbox |
| `internal/server` | HTTP assembly: routes, limits, headers, setup mode |
| `internal/config` | loads all settings from the environment |
| `internal/logging` | redacting `slog` JSON handler for Cloud Logging |
| `internal/testutil` | in-process IMAP and SMTP servers over real TLS, for tests only; `TestDevMailbox` runs them for manual testing |
| `Dockerfile`, `.dockerignore` | multi-stage build onto distroless static, nonroot |
| `deploy.env.example`, `deploy/` | deployment configuration template and the registry cleanup policy |
| `scripts/` | quality gate, image check, Inspector checklist, GCP setup and deploy scripts, and their tests (`scripts_test.go`) |
| `tools/` | separate module pinning staticcheck and govulncheck |
| `docs/` | `DECISIONS.md` (choices and why), `VERIFY.md` (unconfirmed assumptions), `TESTING.md`, `INSPECTOR.md` |
