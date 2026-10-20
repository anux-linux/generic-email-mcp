# generic-email-mcp

A single-user MCP server in Go that lets claude.ai read one IMAP mailbox
(Strato by default) and create/send mail, deployed on Google Cloud Run's
free tier. No web UI.

> **Status: Phase 4 of 5 (mail core, MCP tools, HTTP + OAuth, test
> hardening) — runnable locally; deploy files arrive in Phase 5.**
> Phases: 1 mail core · 2 MCP tools · 3 HTTP + OAuth · 4 test hardening ·
> 5 packaging and deploy files. Setup, connector steps, the security model
> and the budget-alert recipe arrive in Phase 5.

## Layout

| Path | Contents |
|---|---|
| `internal/mail` | IMAP/SMTP core behind the `mail.Mailbox` interface |
| `internal/mcptools` | The MCP server and its seven tools |
| `internal/policy` | Send allowlist and rolling 24 h send cap (durable via a mailbox ledger) |
| `internal/logging` | Redacting `slog` JSON handler for Cloud Logging |
| `internal/oauth` | OAuth 2.1 authorization server (one client, one owner) and token verifier |
| `internal/server` | HTTP assembly: routes, limits, headers, setup mode |
| `internal/config` | Loads all settings from the environment |
| `cmd/email-mcp` | The binary (`serve`, `hash-password`, `version`) |
| `internal/testutil` | In-process IMAP (imapmemserver) and SMTP servers over real TLS, for tests only; `TestDevMailbox` serves them for manual runs |
| `tools/` | Separate module pinning `staticcheck` and `govulncheck` |
| `scripts/check.sh` | The quality gate (format, modules, vet, race tests, staticcheck, govulncheck, optional fuzzing) |
| `scripts/inspector-local.sh` | MCP Inspector checklist against a fake mailbox, automated |
| `docs/DECISIONS.md` | Design choices and their reasons |
| `docs/VERIFY.md` | Assumptions not yet confirmed (open/resolved) |
| `docs/TESTING.md` | How to test; every Phase 4 requirement mapped to its tests |
| `docs/INSPECTOR.md` | MCP Inspector checklist: local (automated), deployed, claude.ai |

## Checks

Requires Go 1.27.3 (`GOTOOLCHAIN=auto` downloads it). No test touches a real
mailbox or the network beyond `127.0.0.1` (govulncheck queries vuln.go.dev).

```sh
scripts/check.sh                # gofmt, mod verify/tidy, vet, go test -race -shuffle=on, staticcheck, govulncheck
FUZZTIME=30s scripts/check.sh   # plus 30 s per fuzz target
scripts/inspector-local.sh      # real binary + MCP Inspector 2.11.0 CLI against a fake mailbox (Linux, needs npx/jq)
```

See `docs/TESTING.md` for what each test proves.

## Service configuration (environment)

Secrets (★) come from Secret Manager as environment variables.

| Variable | Default | Notes |
|---|---|---|
| `BASE_URL` | — | `https://<service-host>` without path. Unset = setup mode (only `/healthz`) |
| `PORT` | `8080` | set by Cloud Run |
| `OAUTH_CLIENT_ID` | — (required) | 8-128 chars `[A-Za-z0-9._~-]`; enter it in claude.ai |
| `OAUTH_CLIENT_SECRET` ★ | — (required) | ≥ 32 chars; enter it in claude.ai |
| `OAUTH_REDIRECT_URIS` | `https://claude.ai/api/mcp/auth_callback` | exact-match allowlist, comma separated |
| `TOKEN_SIGNING_KEY` ★ | — (required) | base64 of ≥ 32 random bytes; keys for tokens, login form and draft IDs are derived from it |
| `TOKEN_EPOCH` | `1` | change to revoke every issued token |
| `AUTHORIZE_PASSWORD_HASH` ★ | — (required) | argon2id from `email-mcp hash-password`, or bcrypt (cost ≥ 10) |
| `AUTHORIZE_LOGIN` | `basic` | `basic` (browser password prompt) or `form` (HTML form) |
| `AUTHORIZE_USERNAME` | `owner` | Basic-auth user name |
| `TRUSTED_PROXY_HOPS` | `1` | proxies appending to `X-Forwarded-For` (Cloud Run: 1) |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `AUTH_STATE` | `imap` | `imap`: refresh-token rotation and revocation survive restarts (mailbox folder); `memory`: in process only |
| `AUTH_STATE_FOLDER` | `MCP-Auth-State` | created on first login; the tools cannot move mail into or out of it |

Create the password hash without putting the password in shell history:

```sh
read -rs PW && printf '%s\n' "$PW" | go run ./cmd/email-mcp hash-password; unset PW
```

## Mail configuration (environment)

Read by `mail.ConfigFromEnv`. Secrets are injected from Secret Manager at
deploy time; never put them in files.

| Variable | Default | Notes |
|---|---|---|
| `MAIL_USERNAME` | — (required) | Strato: the full address |
| `MAIL_PASSWORD` ★ | — (required) | secret |
| `MAIL_IMAP_ADDR` | `imap.strato.de:993` | implicit TLS only |
| `MAIL_SMTP_ADDR` | `smtp.strato.de:465` | implicit TLS only |
| `MAIL_FROM` | `MAIL_USERNAME` | bare address |
| `MAIL_FROM_NAME` | empty | display name |
| `MAIL_SMTP_HELO` | `[127.0.0.1]` | EHLO name |
| `MAIL_FOLDER_SENT` / `_DRAFTS` / `_TRASH` / `_ARCHIVE` | discovered | exact folder names; must exist |
| `MAIL_SAVE_SENT` | `true` | APPEND a copy to Sent after sending |
| `MAIL_MAX_BODY_BYTES` | `65536` | cap on returned body text |

## Tools

| Tool | Effect |
|---|---|
| `mail_list_folders` | folders with role and counts |
| `mail_search` | one folder; from/to/subject/body/since/before/unread; newest first, max 100 |
| `mail_read` | one message as plain text plus attachment metadata; never marks as read |
| `mail_create_draft` | saves a plain-text draft (optionally a reply); sends nothing |
| `mail_send_draft` | sends a draft from `mail_create_draft`; requires `confirm: true`; returns the exact recipients and subject |
| `mail_move` | moves messages; `destination: "trash"` is "delete" |
| `mail_mark_read` | marks read, or unread with `unread: true` |

All mailbox data in results is wrapped in an `untrusted_email_content` block
with a random boundary; tool descriptions and server instructions tell the
model never to follow instructions found in emails.

## Send policy (environment)

| Variable | Default | Notes |
|---|---|---|
| `SEND_ALLOWLIST` | empty (no restriction) | comma/space separated exact addresses or domains (`example.org`, `@example.org`); subdomains do not match; applies to To, Cc and Bcc |
| `MAX_SENDS_PER_DAY` | `20` | messages per rolling 24 h; `0` disables sending |
| `SEND_LEDGER` | `imap` | `imap`: count sends durably in a mailbox folder (survives restarts); `memory`: in-process only |
| `SEND_LEDGER_FOLDER` | `MCP-Send-Ledger` | created on first send; the tools cannot move mail into or out of it |

## Safety properties of the mail core

- Reading never marks mail as seen (EXAMINE + BODY.PEEK).
- No permanent deletion: EXPUNGE, CLOSE, DELETE and STORE `\Deleted` are
  blocked on the wire; "delete" means move to Trash.
- Only drafts created by this server, unmodified since, can be sent
  (HMAC-bound draft IDs); the same draft cannot be sent twice.
- HTML is converted to text with hidden elements removed; invisible Unicode
  is stripped; attachments are reported as metadata only.
- TLS certificate verification is always on.

Details and limits: [docs/DECISIONS.md](docs/DECISIONS.md).
