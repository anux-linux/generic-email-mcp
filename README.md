# generic-email-mcp

A single-user MCP server in Go that lets claude.ai read one IMAP mailbox
(Strato by default) and create/send mail, deployed on Google Cloud Run's
free tier. No web UI.

> **Status: Phase 2 of 5 (mail core + MCP tools) — not deployable yet.**
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
| `internal/testutil` | In-process IMAP (imapmemserver) and SMTP servers over real TLS, for tests only |
| `tools/` | Separate module pinning `staticcheck` and `govulncheck` |
| `docs/DECISIONS.md` | Design choices and their reasons |
| `docs/VERIFY.md` | Assumptions not yet confirmed (open/resolved) |

## Checks

Requires Go 1.27.3 (`GOTOOLCHAIN=auto` downloads it). No test touches a real
mailbox or the network beyond `127.0.0.1`.

```sh
go test -race ./...
go vet ./...
go tool -modfile=tools/go.mod staticcheck ./...
go tool -modfile=tools/go.mod govulncheck ./...
```

## Mail configuration (environment)

Read by `mail.ConfigFromEnv`. Secrets are injected from Secret Manager at
deploy time; never put them in files.

| Variable | Default | Notes |
|---|---|---|
| `MAIL_USERNAME` | — (required) | Strato: the full address |
| `MAIL_PASSWORD` | — (required) | secret |
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
