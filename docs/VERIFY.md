# Verification log

Every assumption that could not be confirmed from source code or tests.
Status: **open** (unconfirmed), **resolved** (confirmed, with how), or
**mitigated** (still unconfirmed, but the code handles both outcomes).

## Strato (needs a real account — not testable here)

None of these can be confirmed without credentials; tests never touch a real
mailbox. Suggested manual checks are read-only. `docs/INSPECTOR.md` Part B
checks most of them in one session against the deployed service (its last
column names the items).

| # | Assumption | Status | How to check / impact |
|---|---|---|---|
| S1 | IMAP is `imap.strato.de:993`, implicit TLS | open | `openssl s_client -connect imap.strato.de:993 -quiet` then `a CAPABILITY`, `a LOGOUT`. Override: `MAIL_IMAP_ADDR`. |
| S2 | SMTP is `smtp.strato.de:465`, implicit TLS, offers `AUTH PLAIN` | open | `openssl s_client -connect smtp.strato.de:465 -quiet`, `EHLO [127.0.0.1]`, read the `AUTH` line, `QUIT`. Override: `MAIL_SMTP_ADDR`. |
| S3 | Login name is the full e-mail address (IMAP and SMTP) | open | First real login. |
| S4 | Server capabilities include `MOVE`, `UIDPLUS`, `SPECIAL-USE`, `LIST-EXTENDED`, `LIST-STATUS` | mitigated | Without MOVE, move/delete is refused (by design, D8). Without UIDPLUS the draft UID is found via Message-ID search (tested). Without SPECIAL-USE/LIST-STATUS: name heuristics and STATUS fallback (tested). |
| S5 | Folder names / SPECIAL-USE flags (likely `Sent`/`Drafts`/`Trash` or German names, possibly `INBOX.`-prefixed) | mitigated | Both layouts are handled; set `MAIL_FOLDER_SENT/DRAFTS/TRASH/ARCHIVE` if discovery picks wrong. Check with `a LIST "" "*" RETURN (SPECIAL-USE)` after login. |
| S6 | Strato does **not** auto-save submitted mail to Sent | open | If it does, set `MAIL_SAVE_SENT=false` to avoid duplicates. |
| S7 | Strato stores APPENDed drafts byte-exact (the draft HMAC covers the bytes) | mitigated | CRLF/LF and trailing newlines are normalized. If Strato rewrites headers, sending fails safe with `ErrDraftInvalid`, never sends a modified draft. |
| S8 | SMTP accepts EHLO `[127.0.0.1]` from authenticated clients | open | Override with `MAIL_SMTP_HELO`. |
| S9 | Strato SMTP sending limits (per-hour/day, recipients per message) | open | Unknown; keep `MAX_SENDS_PER_DAY` (Phase 2, default 20) below it. Recipients per message are capped at 50 here. |
| S10 | Non-ASCII search works (`SEARCH CHARSET UTF-8`) | open | go-imap adds `CHARSET UTF-8` automatically for non-ASCII terms on IMAP4rev1 (source, resolved); server support unknown. |
| S11 | Strato requires `From` = authenticated address | mitigated | The code always uses the account address (`MAIL_FROM` defaults to the username). |
| S12 | Connection limits / rate limits on IMAP logins (one login per tool call) | open | Watch for `[LIMIT]`/`[UNAVAILABLE]` errors under bursty use. |

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
| G8 | Behaviour against a real Dovecot server matches the memserver | open | Only testable against a real server (S4/S5). The beta API may change before v2.0.0; the version is pinned. |

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
| C1 | The OAuth popup shows the browser's HTTP Basic dialog for `/authorize` | open | Connect once. If no dialog appears or the flow stalls, set `AUTHORIZE_LOGIN=form` (single-field HTML form with CSRF protection, D26) and redeploy. Also check the Claude mobile apps if used there. |
| C2 | claude.ai uses the refresh token and stores the rotated one | open | Leave the connector idle > 1 h, then use a tool: must work without re-login. Logs show `grant_type: refresh_token`. |
| C3 | Discovery paths claude.ai requests | mitigated | Both plain and `/mcp`-suffixed variants of both well-known documents are served. |
| C4 | claude.ai asks before calling tools marked `destructiveHint`, and lets the user set `mail_send_draft` to "always ask" | open | |
| C5 | claude.ai passes tool `content` text to the model | mitigated: only text content is sent |
| C6 | claude.ai sends `resource` = the configured server URL (RFC 8707) | mitigated | Optional; exact or trailing-slash match accepted; anything else is `invalid_target`. |
| C7 | claude.ai's token endpoint authentication method | mitigated | Both `client_secret_basic` and `client_secret_post` work. |
| C8 | claude.ai accepts `application/json` responses from Streamable HTTP | open | Allowed by the spec; if not, set `JSONResponse: false` (one line in `internal/server`). |
| C9 | claude.ai calls `/token` and `/mcp` server-to-server (no `Sec-Fetch-Site: cross-site`), so cross-origin protection does not block it | open | Symptom would be 403 on `/mcp`. |

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
| H4 | Which URL form `status.url` returns (deterministic `SERVICE-PROJECT_NUMBER.REGION.run.app` or hash-based `….a.run.app`) | open, **mitigated** | Undocumented and reported to vary. On the first deploy, `deploy.sh` picks the deterministic URL from the `run.googleapis.com/urls` annotation (falling back to `status.url`). Later deploys keep the `BASE_URL` already deployed, so it never flips (tested). |
| H5 | Free tiers: Cloud Run 180k vCPU-s, 360k GiB-s, 2M requests (request-based, per billing account, Tier 1 pricing); Artifact Registry 0.5 GB; Secret Manager 6 active versions and 10k accesses; same-region registry → Cloud Run transfer free | **resolved** (docs) | Active versions = enabled + disabled; destroy old ones after rotating. europe-west1 is Tier 1, europe-west3 Tier 2. |
| H6 | Budgets only notify | **resolved, with an addition** | Alerts-only budgets don't cap spending. Since 2026-10-13 (GA per Google's release notes) a spend-cap budget can pause Cloud Run; it is set up in the console or the Budget API only. Not automated here. |
| H7 | gen2 needs ≥ 512 MiB, so 256 MiB means gen1 | **resolved** (docs) | Set explicitly: `--execution-environment=gen1`. |
| H8 | Secrets exposed as env vars are read at instance start; pinning versions is recommended | **resolved** (docs) | `deploy.sh` pins the newest enabled version by number. A failed secret read prevents the instance from starting (fail closed). |
| H9 | `--allow-unauthenticated` works in the target project | open | It fails under domain restricted sharing (`iam.allowedPolicyMemberDomains`, enforced by default for organizations created since 2024-05-03). Then set `PUBLIC_ACCESS=no-invoker-iam-check` (GA since 2025-03-28). An org can block that too (`run.managed.requireInvokerIam`). |
| H10 | Cloud Run accepts the image: linux/amd64, single-platform manifest, nonroot numeric user, port 8080 | **resolved** (docs) / open (first deploy) | Docs: linux/amd64 only. `scripts/image-check.sh` checks platform, user, no shell, one layer on the pinned base, setup and full mode, SIGTERM and logs (12/12 locally). |
| H11 | The first real deploy works end to end | open | Not executed (Phase 5 rule). After it, run `docs/INSPECTOR.md` Part B. |
| H12 | The stdout logs need no `roles/logging.logWriter` on the runtime account | resolved (docs, implicit) | Logs on stdout are "picked up automatically". The runtime account has no roles. |

## Deploy scripts

| # | Assumption | Status | Notes |
|---|---|---|---|
| K1 | The scripts run on bash 3.2 (macOS default) | **resolved** | All 17 script tests pass with bash 3.2.57 first in `PATH` (the Docker Hub `bash:3.2` binary); a bash-4-only construct fails under it, so the run really used 3.2. |
| K2 | The BSD userland on macOS (`head -c`, `base64`, `od`, `tr`, `date -u +…`, `seq`) behaves like GNU for the options used | open | Only POSIX options or ones both implement are used; not run on macOS. |
| K3 | claude.ai's connector dialog: Settings → Connectors → Add custom connector, with OAuth client ID/secret under Advanced settings | open | From the owner's description; labels may differ. |

## MCP Inspector

| # | Assumption | Status |
|---|---|---|
| I1 | A generic, spec-following MCP client completes this server's OAuth flow (discovery, static client with secret, PKCE S256, RFC 8707 `resource`, RFC 9207 `iss`, rotation) and uses all tools | **resolved** — MCP Inspector 2.11.0 CLI, `scripts/inspector-local.sh`, 41/41 checks (2026-10-20). Says nothing about claude.ai itself (C1–C9). |

## Authorization state

| # | Assumption | Status |
|---|---|---|
| A1 | Refresh-token reuse detection must survive restarts | **resolved** — durable journal in the mailbox (D30); tested across simulated restarts against the IMAP test server |
| A2 | Strato allows creating `MCP-Auth-State` at top level | open — like P2; on failure `/token` answers 503; set `AUTH_STATE_FOLDER` (e.g. `INBOX.MCP-Auth-State`) |

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
| P2 | Strato allows creating the top-level folder `MCP-Send-Ledger` (Courier-style servers may require an `INBOX.` prefix) | open — on failure sends are refused; set `SEND_LEDGER_FOLDER` (e.g. `INBOX.MCP-Send-Ledger`) |
| P3 | Strato honours `SEARCH HEADER <field> ""` as "field present" (RFC 3501) | mitigated — if not, the read-back check refuses every send (fail closed) instead of disabling the cap; `SEND_LEDGER=memory` would then be the fallback |
