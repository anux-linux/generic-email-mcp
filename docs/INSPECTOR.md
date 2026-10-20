# MCP Inspector checklist

Tool: **`@modelcontextprotocol/inspector@2.11.0`** (npm, published
2026-10-14), CLI mode. Always run it with the pinned version, never
`@latest`. Flags and exit codes below are from the 2.11.0 CLI docs and were
exercised end to end on 2026-10-20 (Part A, 41/41 checks).

Inspector CLI exit codes used below: `0` success, `3` authentication
required, `5` tool error (`isError: true`).

## Before you start

- **Use the CLI or TUI, not the web UI.** The web UI runs the token
  exchange in the browser, which needs CORS on `/token`. The metadata
  documents allow CORS; `/token` does not, on purpose (D33).
- **Redirect URI.** The CLI and TUI receive the code on
  `http://127.0.0.1:6276/oauth/callback`. The server accepts it only while it
  is listed in `OAUTH_REDIRECT_URIS`. Add it only for the test and remove it
  afterwards; in production only `https://claude.ai/api/mcp/auth_callback`
  stays.
- **Token storage.** The Inspector keeps OAuth state and tokens in
  `MCP_STORAGE_DIR` (`oauth.json`, `secrets.json`). Without an OS keychain
  the secrets file is plaintext (mode 0600). Use a throwaway directory and
  delete it afterwards, or set `MCP_INSPECTOR_SECRET_KEY`.
- **Client secret on the command line.** `--client-secret` is visible in
  the process list. Run it on a single-user machine and read the secret into
  a variable without echoing it (Part B).
- **Logging in.** When the server answers 401, the CLI prints
  `Please navigate to: …/authorize?…` and opens the browser. Log in with the
  owner credentials (`AUTHORIZE_USERNAME`, default `owner`, and the password
  whose hash is in `AUTHORIZE_PASSWORD_HASH`); the CLI then prints
  `Authorization complete.` Without a TTY, set `MCP_AUTO_OPEN_ENABLED=true`.

## Part A — local, against a fake mailbox (automated)

```sh
scripts/inspector-local.sh          # exit 0 = every check passed
KEEP=1 scripts/inspector-local.sh   # keep the work dir (logs, Inspector output)
```

Needs Go, Node ≥ 22 (`npx`), curl, jq and Linux. The binary trusts the dev
CA through `SSL_CERT_FILE`, which Go honours only on Linux; on macOS run it
in a Linux container. Nothing leaves 127.0.0.1 except npm downloading the
pinned Inspector. Every run generates throwaway secrets and deletes them on
exit.

What it does:

1. Starts the dev mailbox (`TestDevMailbox` in
   `internal/testutil/devmailbox_test.go`): the IMAP and SMTP test servers on
   loopback, seeded with five fake messages.
2. Starts the real binary with `BASE_URL=http://127.0.0.1:8080`,
   `SEND_ALLOWLIST=example.net`, `MAX_SENDS_PER_DAY=2` and the Inspector
   callback added to `OAUTH_REDIRECT_URIS`.
3. Runs the Inspector CLI. For the owner login it plays the browser:
   Basic credentials on `/authorize`, then the loopback callback.

| ID | Check | Expected |
|---|---|---|
| A1 | `--method tools/list` (first run: OAuth login) | exit 0; the client's authorize request carries PKCE S256, `scope=mail`, `resource=…/mcp`; the redirect carries `iss` |
| A2 | tool count | 7 |
| A3 | annotations | `mail_send_draft` destructive + open-world, not read-only; list/search/read read-only |
| A4 | `tools/list --strict` | exit 0, no schema portability warnings |
| B1 | `mail_list_folders` | roles inbox, drafts, sent, trash, archive, junk |
| B2 | `mail_search {"unread_only":true}` | 3 matches |
| B3 | `mail_read` the HTML digest | hidden `display:none` / `font-size:0` text absent |
| B4 | `mail_read` the injection mail | exactly one real opening and one real closing `untrusted_email_content` tag; the closing tag is the last line; injected tags show a fullwidth `＜` |
| B5 | `mail_read` the ISO-8859-1 multipart mail | subject `Grüße`, body decoded, attachment as metadata only |
| B6 | unread search again | still 3 (reading never sets `\Seen`) |
| B7 | `mail_search {"folder":"Projects"}` | 1 match |
| C1 | `mail_create_draft` with To and Bcc | `draft_id` starts with `d1.` |
| C2 | `mail_send_draft` with `confirm: false` | exit 5, `Error (invalid_input)` |
| C3 | `mail_send_draft` without `confirm` | exit 5, schema validation error |
| C4 | SMTP | nothing sent yet |
| C5 | `mail_send_draft` with `confirm: true` | `status: sent`, `saved_to_sent`, `draft_moved_to_trash`, `sends_remaining_24h: 1` |
| C6 | SMTP log of the dev mailbox | recipients To + Bcc; no `Bcc:` header transmitted |
| C7 | send the same draft again | `Error (already_sent)` |
| C8 | draft ID with a forged MAC | `Error (draft_invalid)` |
| C9 | draft to `eve@evil.example` | result contains `WARNING: sending this draft will be refused` |
| C10 | send it | `Error (policy)` |
| C11 | send the draft from C8 with its real ID | sent, `sends_remaining_24h: 0` (the forged attempt did not use up the draft) |
| C12 | third send | `Error (policy)`: daily send limit |
| C13 | SMTP | exactly 2 messages |
| D1 | `mail_mark_read` | `updated: 1` |
| D2 | `mail_mark_read {"ids": null}` | exit 5, schema validation error |
| D3, D4 | `mail_move` into `MCP-Send-Ledger` / `MCP-Auth-State` | `Error (protected)` |
| D5 | `mail_move` of a ledger entry out of `MCP-Send-Ledger` | `Error (protected)` |
| D6 | `mail_move … "destination":"trash"` | `destination_folder: Trash` |
| D7 | `mail_read` with the old ID | `Error (not_found)` |
| D8 | unknown argument (`{"query":"x"}`) | exit 5, schema validation error |
| H1 | `GET /.well-known/oauth-protected-resource/mcp` | `resource` = `<base>/mcp`, `authorization_servers` = `[<base>]` |
| H2 | `GET /.well-known/oauth-authorization-server` | `code_challenge_methods_supported: ["S256"]`, `authorization_response_iss_parameter_supported: true`, no `registration_endpoint` |
| H3 | `POST /mcp` without a token | 401, `WWW-Authenticate: Bearer resource_metadata="…"` |
| H4 | `POST /mcp` with a forged token | 401 |
| H5 | `/token` with a wrong client secret | 401 `invalid_client` |
| H6 | `/authorize` with an unregistered `redirect_uri` (valid owner credentials) | 400, no redirect |
| H7 | `/authorize` with a wrong owner password | 401, no code |
| R1 | restart with `TOKEN_EPOCH=2`, then `--stored-auth-only --method tools/list` | exit 3: access token rejected, refresh answered `invalid_grant` |
| L1 | server log | no addresses, subjects, bodies, message or draft IDs, tokens, codes or secrets |

To repeat a step by hand, run `KEEP=1 scripts/inspector-local.sh`. Then
start `email-mcp` with the environment from `<workdir>/mbox/devmailbox.env`
and use the commands in Part B with `--server-url http://127.0.0.1:8080/mcp`.

## Part B — deployed service (manual, after Phase 5)

This part uses the **real mailbox**: every step is read-only except B8,
which sends one message to your own address. It also resolves the open
Strato items in `docs/VERIFY.md`; write the results there.

**B0. Allow the Inspector callback temporarily.** Redeploy with
`OAUTH_REDIRECT_URIS=https://claude.ai/api/mcp/auth_callback,http://127.0.0.1:6276/oauth/callback`.
Make sure your own address is covered by `SEND_ALLOWLIST`.

**Shell setup** (bash; nothing is written outside the temporary directory):

```sh
export MCP_STORAGE_DIR="$(mktemp -d)" MCP_INSPECTOR_SECRET_STORE=file
S=https://<service-host>
read -rp 'client id: ' CLIENT_ID; read -rsp 'client secret: ' CLIENT_SECRET; echo
I() { npx -y @modelcontextprotocol/inspector@2.11.0 --cli --server-url "$S/mcp" --transport http \
        --client-id "$CLIENT_ID" --client-secret "$CLIENT_SECRET" "$@"; }
C() { I --stored-auth-only --method tools/call --tool-name "$1" --tool-args-json "$2"; }
```

| # | Command | Expected | Resolves |
|---|---|---|---|
| B1 | `curl -sS $S/.well-known/oauth-protected-resource/mcp`; `curl -sS $S/.well-known/oauth-authorization-server`; `curl -si -X POST $S/mcp` | as H1–H3, `https` URLs; the 401 also has `Strict-Transport-Security` | — |
| B2 | `I --method tools/list` | browser opens `/authorize` and shows the Basic dialog (or the form with `AUTHORIZE_LOGIN=form`); after login, `Authorization complete.`, 7 tools | — |
| B3 | `I --stored-auth-only --method tools/list --strict` | exit 0, no warnings | — |
| B4 | `C mail_list_folders '{}'` | INBOX, Drafts, Sent and Trash (archive and junk if present) carry the right `role`. A wrong or missing role → set `MAIL_FOLDER_*` | S1, S3, S4, S5 |
| B5 | `C mail_search '{"unread_only":true,"limit":5}'` | the newest unread messages, as in webmail | S1 |
| B6 | `C mail_read '{"id":"<id from B5>"}'`, then reload webmail | content shown; the message is **still unread** in webmail | S1, G8 |
| B7 | `C mail_search '{"subject":"<a word with umlauts>"}'` | matches as in webmail | S10 |
| B8 | `C mail_create_draft '{"to":["<your address>"],"subject":"MCP Inspector test","body":"test"}'`; `C mail_send_draft '{"draft_id":"<id>","confirm":false}'`; then the same with `"confirm":true` | the draft appears in webmail Drafts; `confirm:false` is refused; then `status: sent`, the mail arrives, exactly **one** copy in Sent, the draft is in Trash, the folder `MCP-Send-Ledger` exists | S2, S6, S7, S8, S11, P2 |
| B9 | `C mail_search '{"folder":"sent","subject":"MCP Inspector test"}'`, then `C mail_move '{"ids":["<that id>"],"destination":"trash"}'` | moved to Trash. Without MOVE support the server refuses it with an error, by design (D8) | S4 |
| B10 | `C mail_mark_read '{"ids":["<id from B5>"],"unread":true}'` | still unread in webmail | — |
| B11 | `I --stored-auth-only --method tools/list` again after > 1 h | works without login (refresh rotation); the folder `MCP-Auth-State` exists | A2 |
| B12 | redeploy with `TOKEN_EPOCH` incremented, then `I --stored-auth-only --method tools/list` | exit 3 | — |

**Cleanup**

1. Redeploy without the loopback redirect URI.
2. If you did not do B12, increment `TOKEN_EPOCH` anyway: it revokes the
   Inspector's tokens. The server has no RFC 7009 revocation endpoint, so
   `--relogin` only deletes the local copy.
3. Run `rm -rf "$MCP_STORAGE_DIR"; unset CLIENT_SECRET`.
4. Optional: delete the test mail and draft in webmail.

## Part C — claude.ai acceptance (after Part B)

Connect the connector as described in the README (URL `https://<service>/mcp`
plus the client ID and secret), then record the results in
`docs/VERIFY.md` C1–C9:

- The login popup shows the Basic dialog or the form (C1).
- Asking "list my mail folders" works (C3, C5, C7, C8, C9).
- Claude asks before `mail_send_draft`, and you can set it to "always ask"
  (C4).
- Leave it idle for over an hour, then use a tool: no new login is needed,
  and the logs show `grant_type: refresh_token` (C2).
