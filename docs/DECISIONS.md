# Decisions

Each entry: the choice, and why. Newest phase last. Open questions live in
[VERIFY.md](VERIFY.md).

## Phase 1 — mail core

### D1. Toolchain and dependencies
- Go **1.27.3** (latest stable on 2026-10-20), set in `go.mod` (`go 1.27.3`).
- Runtime dependencies, all exact versions in `go.mod`/`go.sum`:

  | Module | Version | Used for |
  |---|---|---|
  | `github.com/emersion/go-imap/v2` | `v2.0.0-beta.8` (pre-release, pinned) | IMAP client; `imapmemserver` for tests |
  | `github.com/emersion/go-message` | `v0.18.2` | MIME parsing/composition, charsets |
  | `golang.org/x/net` | `v0.61.0` | `html` parser (HTML → text) |
  | `golang.org/x/text` | `v0.43.0` | Windows-1252 fallback decoding |
  | `github.com/emersion/go-sasl` | `v0.0.0-20241020182733-b788ff22d5a6` | indirect (go-imap) |
- **SMTP uses `net/smtp` over `tls.Dialer`, not `wneessen/go-mail`.** We must
  submit the exact bytes of the verified draft (see D7). `net/smtp` does that
  directly, is in the standard library, and `smtp.PlainAuth` already refuses
  to send credentials over a non-TLS connection. go-mail would add a
  dependency and re-serialize the message.
- Dev tools live in a **separate module** `tools/go.mod` using Go `tool`
  directives (`staticcheck` v0.8.2 = 2026.2.2, `govulncheck` v1.9.0). Keeping
  them out of the main module keeps their dependencies out of the
  application's module graph and out of `govulncheck`'s scope. Run with
  `go tool -modfile=tools/go.mod staticcheck ./...`.

### D2. Package layout
- `internal/mail`: the mail core. `Mailbox` interface (consumed by the MCP
  layer in Phase 2, which tests against fakes) and `*Client`, the IMAP/SMTP
  implementation. No HTTP, MCP or logging inside.
- `internal/testutil`: in-process IMAP (imapmemserver) and SMTP servers over
  real TLS with an ephemeral CA. Imported only from tests.

### D3. Stateless connections and timeouts
- Every `Client` method dials, logs in, works, `LOGOUT`s and closes. No pool,
  no IDLE, no cached state (Cloud Run instances are ephemeral and may run
  with `--max-instances 1` and scale to zero).
- Folder discovery runs on every call that needs a role (one `LIST`, cheap);
  no cache means no stale-role bugs.
- Timeouts: dial 10 s; go-imap's own per-response read timeout (30 s);
  overall deadline from the caller's context, or 45 s if it has none. On
  cancellation `context.AfterFunc` closes the connection, which aborts any
  pending command (go-imap resets socket deadlines per command, so socket
  deadlines alone cannot bound a call). SMTP: socket deadline = context
  deadline (default 60 s). Logout is bounded to 2 s.

### D4. TLS
- Implicit TLS only: IMAPS 993 and submissions 465 (RFC 8314). No STARTTLS
  code path exists, so there is no downgrade/stripping surface.
- Verification cannot be disabled: `Config.Validate` rejects
  `InsecureSkipVerify`, and the effective config forces it to `false`, sets
  `ServerName` from the configured host and `MinVersion` TLS 1.2. Tests use a
  real TLS stack with an ephemeral CA passed as `RootCAs`.
- EHLO name defaults to the address literal `[127.0.0.1]` (what Thunderbird
  does) so the container hostname is not disclosed; override with
  `MAIL_SMTP_HELO`.

### D5. Message IDs
- `m1.<base64url(folder)>.<uidvalidity>.<uid>`; canonical decimal (no signs,
  no leading zeros), folder must be valid UTF-8 without NUL/CR/LF, ≤ 1024
  bytes; whole ID ≤ 2048 bytes.
- **UIDVALIDITY is compared on every use**; a mismatch is `ErrStaleID`, so an
  ID can never silently address a different message after renumbering.
- Plain message IDs are not signed: the server holds exactly one account, so
  a forged ID can only address the owner's own mail, and every use is
  re-validated against the server.

### D6. Reading never marks mail as seen
- Read paths use `EXAMINE` (read-only select) **and** `BODY.PEEK[...]`.
  Either alone would suffice; both guard against server quirks. The test
  server sets `\Seen` on non-PEEK fetches even under EXAMINE, so the test
  `TestReadPlainNeverMarksSeen` would catch a regression.

### D7. Drafts and sending
- **Draft IDs are authenticated**:
  `d1.<folder>.<uidvalidity>.<uid>.<base64url(HMAC-SHA256)>` where the MAC
  covers a label, the account, folder, UIDVALIDITY, UID and SHA-256 of the
  stored bytes (line endings normalized). Consequences:
  - only drafts created by `CreateDraft` can be sent (no list to keep; works
    across restarts);
  - a draft edited after creation (webmail, another client, or an APPEND by a
    prompt-injected model) is refused — what the user reviewed is what is
    sent;
  - the ID must point into the Drafts folder and the message must carry
    `\Draft` and not `\Deleted`.
  The HMAC key (`Config.DraftKey`, ≥ 32 bytes) is supplied by the caller;
  Phase 3 derives it from the Secret Manager signing key with a separate
  label.
- **Send order**: verify MAC → parse (From must equal the account address;
  1–50 recipients from To/Cc/Bcc) → `SendPolicy.Admit` (allowlist/daily cap,
  Phase 2) → SMTP → APPEND copy to Sent (`\Seen`) → MOVE draft to Trash.
  Recipients are rejected at `RCPT` before `DATA`, so a rejection delivers to
  nobody.
- **After SMTP accepts, the call never returns an error**; Sent/Trash
  problems become `Warnings`. Otherwise the model could retry and send twice.
- If the connection fails after the final `.` of `DATA` but before the reply,
  the server may have accepted the message. That returns
  `ErrDeliveryUnknown` (never a plain failure) and keeps the draft locked in
  this process, so an automatic retry cannot double-send; the user decides.
- **Replay protection**: an in-process registry blocks the same draft
  concurrently or twice; moving the draft to Trash invalidates the ID for
  any later process (UIDs are never reused under one UIDVALIDITY). A policy
  reservation is not refunded when SMTP fails (conservative).
- The transmitted message has `Bcc` removed; the Sent copy keeps it for the
  owner. `Date` is refreshed at send time; everything else is byte-identical
  to the verified draft.
- Composition: `text/plain; charset=utf-8`, quoted-printable, RFC 2047
  headers, CRLF, random 160-bit Message-ID at the account's domain.
  Addresses must be ASCII (no SMTPUTF8); groups are flattened to members;
  duplicates across To/Cc/Bcc dropped. Subject is single-lined (CR/LF cannot
  inject headers). **Invisible Unicode is stripped from subject and body** so
  hidden payloads (e.g. tag-character "ASCII smuggling") cannot be
  exfiltrated in a mail the user reviewed. Control characters are rejected.
- Replies (`InReplyTo` = message ID): `In-Reply-To` = original Message-ID,
  `References` = original References (or single In-Reply-To) + Message-ID,
  capped at 20 (first + last 19, RFC 5322 §3.6.4). Defaults: Subject
  `Re: <original>` (not doubled for Re:/AW:/Antw:), To = Reply-To or From.

### D8. No permanent deletion, enforced three ways
1. **Code**: nothing calls EXPUNGE, UID EXPUNGE, CLOSE, DELETE or STORE
   `\Deleted`. "Delete" is a MOVE to Trash; moving within Trash is a no-op.
   `SELECT`/`EXAMINE`/`LOGOUT` close the previous mailbox *without*
   expunging (RFC 3501 §6.4.2).
2. **Transport guard** (`guardConn`): a wrapper on the IMAP socket parses
   the client→server stream (skipping literal payloads `{N}`, `{N+}`,
   `~{N}`) and refuses to transmit those commands; the connection is killed
   and the call fails with `ErrForbidden`. This matters because
   **go-imap's `Client.Move` silently falls back to COPY + STORE \Deleted +
   EXPUNGE** when the server lacks MOVE. We additionally refuse `Move` up
   front on such servers (`ErrUnsupported`).
3. **Tests**: static source scan (`TestNoDestructiveCallsInSource`), wire
   recording over a full workflow (`TestNoDestructiveIMAPCommands`), and
   direct attempts through the library (`TestGuardBlocksDirectExpunge`,
   `TestGuardBlocksLibraryMoveFallback`) proving the server state is
   unchanged.
- Messages flagged `\Deleted` by other clients are excluded from search.

### D9. Body extraction
- Structure comes from `BODYSTRUCTURE`; only selected text parts are
  fetched, with `BODY.PEEK[part]<0.N>`. **Attachment bytes are never
  downloaded**; metadata (part number, filename, type, approx. decoded size,
  inline flag) comes from BODYSTRUCTURE. RFC 2231 filenames
  (`filename*=utf-8''…`, continuations) are decoded locally because go-imap
  passes them raw.
- Part selection: inline `text/plain`/`text/html` without filename are body
  parts; in `multipart/alternative` exactly one branch is used, preferring
  **text/plain over HTML** (plain text cannot hide content), last-wins on
  ties (RFC 2046). At most 8 text parts per message; the fetch budget
  (1 MiB) is split across them.
- Decoding: transfer encoding and charset via go-message (+ its charset
  table); truncated base64 tails are repaired so the decodable prefix
  survives; undeclared or invalid UTF-8 falls back to Windows-1252.
- Output text is capped (default 64 KiB, `MAIL_MAX_BODY_BYTES`) on a rune
  boundary; `BodyTruncated` reports any cut.

### D10. Hidden-content removal (best effort)
- All output text (bodies, subjects, names, filenames) is stripped of
  invisible characters: Unicode Cc/Cf (zero-width, bidi overrides, BOM, soft
  hyphen, **tag characters U+E0000–E007F**), variation selectors (incl.
  U+E0100–E01EF), CGJ, Hangul fillers. Side effect: ZWJ emoji sequences
  render as separate emoji.
- HTML → text with `x/net/html`. Dropped: `head`, `script`, `style`, media,
  forms, `iframe`/`object`, comments, images (alt text is a known hiding
  place); elements with `hidden`; inline styles `display:none`,
  `visibility:hidden|collapse`, `opacity<0.1`, `font-size≤2px`,
  `color:transparent`/zero-alpha, zero-size boxes with `overflow:hidden`,
  `clip:rect(0…)`, `clip-path:inset(50%|100%)`, `transform:scale(0)`,
  `text-indent≤-500px`, off-screen absolute/fixed positioning,
  `mso-hide:all`; class/id selectors hidden by *top-level* `<style>` rules
  (rules inside `@media` are conditional and ignored). `aria-hidden` is not
  treated as hidden (it is visible to sighted readers).
- Known gaps: text coloured like its background, complex CSS selectors,
  external stylesheets, text in images. This is defence in depth only; the
  primary control is Phase 2's untrusted-content wrapper and tool
  descriptions.

### D11. Folder discovery
- Per role (Drafts, Sent, Trash, Archive, Junk): explicit override
  (`MAIL_FOLDER_*`, must exist and be selectable — a wrong override fails
  loudly instead of silently falling back) → SPECIAL-USE attribute
  (`RETURN (SPECIAL-USE)` when LIST-EXTENDED is available, plain LIST
  attributes otherwise) → well-known English/German names on the leaf
  component. Ties: shallowest (INBOX children count as top level for
  Courier-style `INBOX.Sent`), then name priority, then shortest, then
  lexicographic. A folder gets at most one role.
- Counts via LIST-STATUS when available, else pipelined STATUS (≤ 200
  folders).

### D12. Search semantics
- One folder per call (default INBOX); criteria are ANDed; From/To/Subject
  are header substring matches, Body is `BODY`; Since/Before use the received
  date (INTERNALDATE) at day granularity. Results are newest first by UID
  (no SORT extension needed), default 20, max 100, with the total count.

### D13. Errors and secrecy
- Sentinel errors plus `ErrorKind(err)` — a fixed, log-safe classification
  for Phase 2 logging. Server text is dropped where it can echo the username
  or recipient addresses (IMAP LOGIN, SMTP replies keep only the code).
- The mail core never logs. go-imap's `DebugWriter` (which would capture
  credentials) is never set.
