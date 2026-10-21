# Verification log

Every assumption that could not be confirmed from source code or tests.
Status: **open** (unconfirmed), **resolved** (confirmed, with how), or
**mitigated** (still unconfirmed, but the code handles both outcomes).

## Strato

Tests never touch a real mailbox. These items were checked on 2026-10-21 in
an owner-approved session against the deployed service and the real Strato
mailbox, through the claude.ai connector, covering the steps of
`docs/INSPECTOR.md` Part B. That session made these changes to the mailbox:
- created and sent one draft, with the owner's approval, to the account
  itself;
- moved the two copies of that mail, from Sent Items and INBOX, to Trash;
- set one message that was already unread to unread again, which changed
  nothing.

No mail content is recorded here. "Owner" marks items settled by the
owner's own observation or decision.

| # | Assumption | Status | How to check / impact |
|---|---|---|---|
| S1 | IMAP is `imap.strato.de:993`, implicit TLS | **resolved** (live, 2026-10-21) | Every tool call worked against the live mailbox (folder list, search, read, flags, move). |
| S2 | SMTP is `smtp.strato.de:465`, implicit TLS, offers `AUTH PLAIN` | **resolved** (live, 2026-10-21) | Two sends were delivered: one from claude.ai to an external address, and one verification mail to the account itself, which arrived in INBOX. |
| S3 | Login name is the full e-mail address (IMAP and SMTP) | **resolved** (live, 2026-10-21) | `MAIL_USERNAME` is the full address; IMAP and SMTP logins both succeed. |
| S4 | Server capabilities include `MOVE`, `UIDPLUS`, `SPECIAL-USE`, `LIST-EXTENDED`, `LIST-STATUS` | **resolved** for `MOVE` and `UIDPLUS` (live, 2026-10-21); the rest mitigated | The server moves only with MOVE (D8). Moves worked: the sent draft went to Trash, and two test copies were moved by `mail_move`. `mail_move` returned new IDs, which come from COPYUID data (UIDPLUS). Whether roles came from SPECIAL-USE or from the name heuristics was not recorded; both give the same result here (S5). |
| S5 | Folder names / SPECIAL-USE flags (likely `Sent`/`Drafts`/`Trash` or German names, possibly `INBOX.`-prefixed) | **resolved** (live, 2026-10-21) | Top-level `INBOX`, `Drafts`, `Sent Items`, `Trash`, `Archive`, `Spam`. All six roles were discovered without any `MAIL_FOLDER_*` override. No `INBOX.` prefix. |
| S6 | Strato does **not** auto-save submitted mail to Sent | **resolved** (live, 2026-10-21) | Each send left exactly one copy in `Sent Items` (38 → 39 for the verification mail). The default `MAIL_SAVE_SENT=true` is right. |
| S7 | Strato stores APPENDed drafts byte-exact (the draft HMAC covers the bytes) | **resolved** (live, 2026-10-21) | A draft created through the server was sent. Sending re-reads the draft and checks its HMAC over the stored bytes, so Strato kept them unchanged after normalization. The draft was then in Trash, and `Drafts` was empty. |
| S8 | SMTP accepts EHLO `[127.0.0.1]` from authenticated clients | **resolved** (live, 2026-10-21) | Both sends used the default HELO. |
| S9 | Strato SMTP sending limits (per-hour/day, recipients per message) | **closed** (owner, 2026-10-21) | The owner confirms Strato's limits are far above `MAX_SENDS_PER_DAY=20`. Recipients per message are capped at 50 here. |
| S10 | Non-ASCII search works (`SEARCH CHARSET UTF-8`) | **resolved** (live, 2026-10-21) | A subject search for `verlängert` returned 26 matches, the newest of them with that word in the subject. |
| S11 | Strato requires `From` = authenticated address | **resolved** (live, 2026-10-21) | From is always the account address, and Strato accepted both sends. Whether Strato would reject another From was not tested; the server never sends one. |
| S12 | Connection limits / rate limits on IMAP logins (one login per tool call) | **closed** (owner, 2026-10-21) | The owner confirms Strato's limits are far above this usage. No `[LIMIT]`/`[UNAVAILABLE]` errors appeared in a session of 14 consecutive tool calls. |

## go-imap v2.0.0-beta.8 (pre-release)

| # | Assumption | Status | Evidence |
|---|---|---|---|
| G1 | `Client.Move` falls back to COPY + STORE `\Deleted` + EXPUNGE without MOVE | **resolved** | Source `imapclient/move.go`; guarded (D8) and covered by `TestGuardBlocksLibraryMoveFallback`. |
| G2 | `Select(…, ReadOnly: true)` sends `EXAMINE` | **resolved** | Source `imapclient/select.go`; wire recording in `TestReadPlainNeverMarksSeen`. |
| G3 | The client resets socket deadlines per command | **resolved** | Source `imapclient/client.go` (`setReadTimeout`); hence context-driven close (D3). |
| G4 | BODYSTRUCTURE params are RFC 2047-decoded but not RFC 2231 | **resolved** | Source `readBodyFldParam`; local RFC 2231 decoding tested in `TestAttachmentMetadata`. |
| G5 | `imapmemserver` cannot store SPECIAL-USE attributes | **resolved** | Field is never assigned in source; test fixture wraps `List`. |
| G6 | `imapmemserver` sets `\Seen` on non-PEEK fetch even under EXAMINE | **resolved** | Source `imapmemserver/mailbox.go`; makes the no-seen test meaningful. |
| G7 | `imapmemserver` always sends APPENDUID | **resolved** | Source `imapserver/append.go`; fixture can suppress it to test the fallback. |
| G8 | Behaviour against a real Dovecot server matches the memserver | **resolved** for the operations used (live, 2026-10-21) | List, search (ASCII and UTF-8), read (EXAMINE + PEEK: reading left the message unread), STORE flags, APPEND, MOVE with COPYUID, and sending with the ledger all behaved as against the memserver. The pin stays (beta API). |

## MCP Go SDK v1.8.0

| # | Assumption | Status | Evidence |
|---|---|---|---|
| M1 | `mcp.NewStreamableHTTPHandler`, `auth.RequireBearerToken`, `auth.ProtectedResourceMetadataHandler` exist with these names | **resolved** | Present in v1.8.0 source (`mcp/streamable.go`, `auth/auth.go`); the metadata handler takes `*oauthex.ProtectedResourceMetadata`. |
| M2 | A stateless Streamable HTTP mode exists | **resolved** | `StreamableHTTPOptions.Stateless` (no `Mcp-Session-Id`, temporary session per request, GET/DELETE → 405). Phase 3 uses it, so restarts lose nothing. `--max-instances 1` stays: the send-policy and token-journal mutexes serialize only within one process (H3). |
| M3 | A typed tool output would add `structuredContent` that bypasses our wrapper | **resolved** | `toolForErr` in `mcp/server.go`; we return text only, and tests assert `structuredContent` is absent. |
| M4 | The SDK logs only lifecycle data (session IDs, errors), never tool arguments | **resolved** | All `Logger` calls in `mcp/*.go` reviewed; output is still routed through the redacting handler. |

## claude.ai client behaviour

| # | Assumption | Status | How to check / fallback |
|---|---|---|---|
| C1 | The OAuth popup shows the browser's HTTP Basic dialog for `/authorize` | **resolved** (owner, 2026-10-21) | The owner connected the claude.ai connector with `AUTHORIZE_LOGIN=basic`. The form fallback was not needed. The Claude mobile apps were not tested. |
| C2 | claude.ai uses the refresh token and stores the rotated one | **resolved** (owner, 2026-10-21) | After about an hour without interaction, longer than the 1 h access-token lifetime, the tools worked again without a new login. `MCP-Auth-State` holds the durable token-family journal. |
| C3 | Discovery paths claude.ai requests | **resolved: works** (2026-10-21) | Discovery succeeded. Both variants stay served; which one claude.ai used was not recorded. |
| C4 | claude.ai asks before calling tools marked `destructiveHint`, and lets the user set `mail_send_draft` to "always ask" | **resolved** (owner, 2026-10-21) | Approval was asked before sending. |
| C5 | claude.ai passes tool `content` text to the model | **resolved: works** (2026-10-21) | Tool results reach the model with the fenced `untrusted_email_content` blocks intact. |
| C6 | claude.ai sends `resource` = the configured server URL (RFC 8707) | **resolved: works** (2026-10-21) | Token issuance succeeded. Anything other than an exact or trailing-slash match would have been `invalid_target`. |
| C7 | claude.ai's token endpoint authentication method | **resolved: works** (2026-10-21) | Login and refresh succeeded. Which of the two methods claude.ai used was not recorded; both stay supported. |
| C8 | claude.ai accepts `application/json` responses from Streamable HTTP | **resolved** (2026-10-21) | All seven tools were called successfully through the connector. |
| C9 | claude.ai calls `/token` and `/mcp` server-to-server (no `Sec-Fetch-Site: cross-site`), so cross-origin protection does not block it | **resolved** (2026-10-21) | No 403. The token exchange and every tool call succeeded. |

## Cloud Run and Google Cloud

Checked against Google's documentation on 2026-10-20 (docs.cloud.google.com;
quotes and URLs are in the Phase 5 research notes, summarized here). Every
gcloud command line in `scripts/` and the README was also replayed offline
against gcloud 570.0.0, with no network and no credentials: each failed only
at "no active account", so all flags and values passed argument parsing.

| # | Assumption | Status | Notes |
|---|---|---|---|
| H1 | The front end appends the client IP as the last `X-Forwarded-For` entry (`TRUSTED_PROXY_HOPS=1`) | open | Only affects per-IP rate limiting; the global limit holds regardless. |
| H2 | SIGTERM grace period is 10 s | open | Shutdown is bounded to 8 s; `scripts/image-check.sh` I10 shows a clean exit 0 on SIGTERM. |
| H3 | `--max-instances 1` means at most one instance at a time | **resolved: false, accepted** | Docs: instances "can be exceeded for a brief period due to circumstances such as traffic spikes", and "during a deployment, the total number of instances for the service can exceed the maximum instances per revision". The deploy now also sets the service-level `--max=1`, which Google recommends. Remaining effect, briefly: one extra send at cap−1, or one refresh reuse undetected. |
| H4 | Which URL form `status.url` returns (deterministic `SERVICE-PROJECT_NUMBER.REGION.run.app` or hash-based `….a.run.app`) | **resolved** (first deploy, 2026-10-21) | `status.url` was the hash-based form, and the `run.googleapis.com/urls` annotation listed the deterministic one first. `deploy.sh` set `BASE_URL` to the deterministic URL as designed. Later deploys keep it (tested). |
| H5 | Free tiers: Cloud Run 180k vCPU-s, 360k GiB-s, 2M requests (request-based, per billing account, Tier 1 pricing); Artifact Registry 0.5 GB; Secret Manager 6 active versions and 10k accesses; same-region registry → Cloud Run transfer free | **resolved** (docs) | Active versions = enabled + disabled; destroy old ones after rotating. europe-west1 is Tier 1, europe-west3 Tier 2. |
| H6 | Budgets only notify | **resolved, with an addition** | Alerts-only budgets don't cap spending. Since 2026-10-13 (GA per Google's release notes) a spend-cap budget can pause Cloud Run; it is set up in the console or the Budget API only. Not automated here. |
| H7 | gen2 needs ≥ 512 MiB, so 256 MiB means gen1 | **resolved** (docs) | Set explicitly: `--execution-environment=gen1`. |
| H8 | Secrets exposed as env vars are read at instance start; pinning versions is recommended | **resolved** (docs) | `deploy.sh` pins the newest enabled version by number. A failed secret read prevents the instance from starting (fail closed). |
| H9 | `--allow-unauthenticated` works in the target project | **resolved** for `generic-email-mcp` (2026-10-21) | gcloud reported "Setting IAM Policy… Done"; the project has no organization policy blocking `allUsers`. In an organization with domain restricted sharing (`iam.allowedPolicyMemberDomains`), set `PUBLIC_ACCESS=no-invoker-iam-check` instead. An organization can block that too (`run.managed.requireInvokerIam`). |
| H10 | Cloud Run accepts the image: linux/amd64, single-platform manifest, nonroot numeric user, port 8080 | **resolved** (first deploy, 2026-10-21) | Both revisions became ready in seconds, and the default TCP startup probe on 8080 succeeded on the first attempt. Observed: gcloud 575 sets `run.googleapis.com/startup-cpu-boost: true` by default. That is a gcloud default, not a leftover from an earlier revision; it shortens cold starts and is billed only during startup. |
| H11 | The first real deploy works end to end | **resolved, with a fix** (2026-10-21) | Both steps deployed: setup mode, then `BASE_URL` set, with the instance logging `status: ready`. The post-deploy check failed because `/healthz` never reached the container (H13), so the metadata and 401 checks were not run. With the health endpoint at `/health`, the next deploy runs all checks. Then run `docs/INSPECTOR.md` Part B. |
| H12 | The stdout logs need no `roles/logging.logWriter` on the runtime account | resolved (docs, implicit) | Logs on stdout are "picked up automatically". The runtime account has no roles. |
| H13 | The container sees every path it serves | **resolved: false for `/healthz`, fixed** (2026-10-21) | Cloud Run's known issues: "You can't use the following URL paths: Paths starting with `/_ah/`; Some paths ending with `z`. To prevent conflicts with reserved paths, we recommend avoiding all paths that end in `z`." On the first deploy, `deploy.sh` polled `/healthz` for a minute and the request log shows none of those requests, while `/health` and `/favicon.ico` from a browser did arrive. The health endpoint is now `/health`. `TestNoCloudRunReservedPaths` checks every route against both rules. |

## Deploy scripts

| # | Assumption | Status | Notes |
|---|---|---|---|
| K1 | The scripts run on bash 3.2 (macOS default) | **resolved** | All 30 script tests pass with bash 3.2.57 first in `PATH` (the Docker Hub `bash:3.2` binary); a bash-4-only construct fails under it, so the run really used 3.2. |
| K2 | The BSD userland on macOS (`head -c`, `base64`, `od`, `tr`, `date -u +…`, `seq`) behaves like GNU for the options used | open | Only POSIX options or ones both implement are used; not run on macOS. |
| K3 | claude.ai's connector dialog: Settings → Connectors → Add custom connector, with OAuth client ID/secret under Advanced settings | open | From the owner's description; labels may differ. |

## Automatic deploys from GitHub

Checked on 2026-10-21 against Google's and GitHub's documentation. Where the
documentation is silent, the gcloud 590.0.0 source and the `actions/runner`
source were read. Every gcloud command line of all scripts, and the README
commands, was replayed offline against gcloud 590.0.0 (and 570.0.0), with no
network, an empty configuration and no credentials in the environment.
Each failed only at "no active account" or at refreshing tokens, so every
flag passed argument parsing; a deliberately bad flag was rejected. Nothing
here has run against a real project or a real GitHub runner yet.

| # | Assumption | Status | Notes |
|---|---|---|---|
| W1 | `roles/run.developer` on the service (plus `serviceAccountUser` on the runtime account and Artifact Registry access) is enough for `gcloud run deploy` to update the service | open (first CI deploy) | Google's deploying page lists exactly these as the required roles, and the role can be granted on a service. Two gaps remain. In the gcloud source, deploy waits on `run.operations.get` for the operation named in the response, and whether a service-level grant covers that is not documented. The secrets page lists `run.admin` on the service, which the main page does not. If the first CI deploy fails with a permission error on operations, add a project-level custom role holding only `run.operations.get`: `gcloud iam roles create runOperationsGet --project=P --permissions=run.operations.get`, then `gcloud projects add-iam-policy-binding P --member=serviceAccount:email-mcp-deploy@P.iam.gserviceaccount.com --role=projects/P/roles/runOperationsGet`. |
| W2 | For a `workflow_run` job, the OIDC token carries `ref` = `refs/heads/main`, `workflow_ref` = `…/.github/workflows/deploy.yml@refs/heads/main` and `environment` = `production` | partly resolved | `ref`: resolved, because `GITHUB_REF` is the default branch for `workflow_run` (docs). `environment` and `workflow_ref` are documented claims, but their value for `workflow_run` is only implied. If they differ, STS rejects the token (fail closed) and the log names the condition. |
| W3 | `google.subject` (≤ 127 bytes) can hold `sub` | **resolved** | Repositories created after 2026-07-15 get GitHub's immutable `sub`, which includes the numeric IDs. For this one (created 2026-10-20) that is `repo:anux-linux@838468/generic-email-mcp@1427120410:environment:production`, 74 bytes. The condition does not use `sub`. |
| W4 | `::add-mask::` written to stderr is processed | **resolved** (runner source) | `ScriptHandler` feeds stdout and stderr each into an `OutputManager`, which runs `TryProcessCommand` on any line containing a command, whatever the stream. |
| W5 | `gcloud auth login --cred-file` accepts the URL-sourced external-account file with impersonation, and gcloud and its Docker credential helper use it | open (first CI deploy) | Documented ("external account configuration file … generated by … create-cred-config"). Offline, gcloud 590 accepted the file and reached the token refresh. `configure-docker` honours `DOCKER_CONFIG` (checked offline). |
| W6 | The pinned gcloud 590.0.0 archive is Google's | **resolved** 2026-10-21 | Google publishes a SHA-256 only for the current unversioned file (`351ed4a2…`). The downloaded unversioned file matched it, and its tar is byte-identical to that of the versioned `google-cloud-cli-590.0.0-linux-x86_64.tar.gz` (SHA-256 `1503a6fc…`). That file's MD5 also matches the Cloud Storage object's `md5Hash`. An independent download by the research agent got the same values. |
| W7 | The environment's branch policy cannot be bypassed through `workflow_run` | **resolved** (docs) | The policy is matched against `GITHUB_REF`, which for `workflow_run` is always the default branch. So the real gate is the job's `if:` (`event == push`, `conclusion == success`, `head_sha == github.sha`) and the provider condition. |
| W8 | `roles/secretmanager.viewer` on a secret allows listing versions but not reading values | **resolved** (docs) | It contains `versions.list` and `versions.get` but not `versions.access`. |
| W9 | Omitting the public-access flag keeps the existing setting | **resolved** (gcloud source) | `allow_unauthenticated` "None means to retain the current value"; no `setIamPolicy` call is made. The invoker-check annotation changes only when its flag is given. |
| W10 | The deployer needs no Secret Manager permission for `--set-secrets` | **resolved** (docs, source) | Cloud Run checks that the service identity can access the secrets; gcloud makes no Secret Manager call. |
| W11 | The first automatic deploy works end to end | open | After `scripts/gcp-github.sh` and the GitHub environment are set up, merge to `main` and watch the `deploy` run. |
| W12 | A pool's providers share its principals, so another provider in the pool could bypass our condition | **resolved** (docs), mitigated | Google's best practices: "use a single provider per workload identity pool" to avoid subject collisions. The pool is dedicated by default (`email-mcp`, provider `github`), and `gcp-github.sh` refuses a pool holding any other provider (tested, mutation-checked). |

## MCP Inspector

| # | Assumption | Status |
|---|---|---|
| I1 | A generic, spec-following MCP client completes this server's OAuth flow (discovery, static client with secret, PKCE S256, RFC 8707 `resource`, RFC 9207 `iss`, rotation) and uses all tools | **resolved** — MCP Inspector 2.11.0 CLI, `scripts/inspector-local.sh`, 41/41 checks (2026-10-20). Says nothing about claude.ai itself (C1–C9). |

## Authorization state

| # | Assumption | Status |
|---|---|---|
| A1 | Refresh-token reuse detection must survive restarts | **resolved** — durable journal in the mailbox (D30); tested across simulated restarts against the IMAP test server |
| A2 | Strato allows creating `MCP-Auth-State` at top level | **resolved** (live, 2026-10-21) — created on the first login, now holding 2 journal entries |

## Dependencies

| # | Item | Status |
|---|---|---|
| V1 | govulncheck module-level finding GO-2026-5932 (`golang.org/x/crypto/openpgp` unmaintained) | **resolved** — the package is not imported (symbol and package scans clean); no fixed version exists |
| V2 | CI action tags `actions/checkout@v7.0.1`, `actions/setup-go@v7.0.0` point at the intended code | open, accepted | Tags are mutable (D35); resolved via `git ls-remote` on 2026-10-20. |
| V3 | Base image digests (`golang:1.27.3-trixie`, `distroless/static-debian13:nonroot`) are current | **resolved** 2026-10-20 | Resolved with `docker buildx imagetools inspect`; refresh periodically for security updates and re-run `scripts/image-check.sh`. |

## Policy

| # | Assumption | Status |
|---|---|---|
| P1 | The daily send cap must survive restarts | **resolved** — durable IMAP ledger (D21); tested across simulated restarts |
| P2 | Strato allows creating the top-level folder `MCP-Send-Ledger` (Courier-style servers may require an `INBOX.` prefix) | **resolved** (live, 2026-10-21) — created on the first send; one entry per send (2 after two sends) |
| P3 | Strato honours `SEARCH HEADER <field> ""` as "field present" (RFC 3501) | **resolved** (live, 2026-10-21) — the ledger read-back counted both sends (`sends_remaining_24h: 18` with a cap of 20) |
