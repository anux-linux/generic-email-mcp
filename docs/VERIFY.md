# Verification log

Every assumption that could not be confirmed from source code or tests.
Status: **open** (unconfirmed), **resolved** (confirmed, with how), or
**mitigated** (still unconfirmed, but the code handles both outcomes).

## Strato (needs a real account — not testable here)

None of these can be confirmed without credentials; tests never touch a real
mailbox. Suggested manual checks are read-only.

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
| M2 | A stateless Streamable HTTP mode exists | **resolved** | `StreamableHTTPOptions.Stateless` (no `Mcp-Session-Id`, temporary session per request, GET/DELETE → 405). Phase 3 uses it, so restarts lose nothing. `--max-instances 1` stays for the in-memory send cap (P1). |
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

## Cloud Run

| # | Assumption | Status | How to check |
|---|---|---|---|
| H1 | The front end appends the client IP as the last `X-Forwarded-For` entry (`TRUSTED_PROXY_HOPS=1`) | open | Only affects per-IP rate limiting; the global limit holds regardless. |
| H2 | SIGTERM grace period is 10 s | open | Shutdown is bounded to 8 s. |

## Authorization state

| # | Assumption | Status |
|---|---|---|
| A1 | Refresh-token reuse detection must survive restarts | **resolved** — durable journal in the mailbox (D30); tested across simulated restarts against the IMAP test server |
| A2 | Strato allows creating `MCP-Auth-State` at top level | open — like P2; on failure `/token` answers 503; set `AUTH_STATE_FOLDER` (e.g. `INBOX.MCP-Auth-State`) |

## Dependencies

| # | Item | Status |
|---|---|---|
| V1 | govulncheck module-level finding GO-2026-5932 (`golang.org/x/crypto/openpgp` unmaintained) | **resolved** — the package is not imported (symbol and package scans clean); no fixed version exists |

## Policy

| # | Assumption | Status |
|---|---|---|
| P1 | The daily send cap must survive restarts | **resolved** — durable IMAP ledger (D21); tested across simulated restarts |
| P2 | Strato allows creating the top-level folder `MCP-Send-Ledger` (Courier-style servers may require an `INBOX.` prefix) | open — on failure sends are refused; set `SEND_LEDGER_FOLDER` (e.g. `INBOX.MCP-Send-Ledger`) |
| P3 | Strato honours `SEARCH HEADER <field> ""` as "field present" (RFC 3501) | mitigated — if not, the read-back check refuses every send (fail closed) instead of disabling the cap; `SEND_LEDGER=memory` would then be the fallback |
