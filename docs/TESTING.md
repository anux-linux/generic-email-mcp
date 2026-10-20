# Testing

## Running

```sh
scripts/check.sh                 # the gate: run before every commit
FUZZTIME=30s scripts/check.sh    # plus 30 s of fuzzing per target (13 targets)
scripts/inspector-local.sh       # MCP Inspector checklist, Part A (docs/INSPECTOR.md)
```

`scripts/check.sh` stops at the first failure. It runs, in order:

1. `gofmt -l` (must be empty);
2. `go mod verify` and `go mod tidy -diff`, for the main module and for
   `tools/`;
3. `go vet ./...`;
4. `go test -race -count=1 -shuffle=on ./...`;
5. staticcheck v0.8.2 and govulncheck v1.9.0, pinned in `tools/go.mod` and
   run as `go tool -modfile=tools/go.mod …`.

`SKIP_VULN=1` skips govulncheck when vuln.go.dev is unreachable.

To run a single fuzz target:

```sh
go test -run '^$' -fuzz '^FuzzParseID$' -fuzztime 60s ./internal/mail
```

A crashing input is written to `testdata/fuzz/<Target>/`. Commit it with the
fix: plain `go test` then replays it as a regression seed. Five such seeds
are committed.

## No real mailbox, no cloud

- Every mail test uses the in-process servers in `internal/testutil`:
  - the go-imap `imapmemserver` behind real TLS, with SPECIAL-USE emulation
    and optional capability sets (Dovecot-like or minimal IMAP4rev1);
  - a stub ESMTP server with implicit TLS and AUTH PLAIN, which records
    messages and can reject recipients or drop the connection after DATA.
- The servers listen on 127.0.0.1:0 and use an ephemeral self-signed CA.
  Clients trust only that CA, and certificate verification is never
  disabled (`TestIMAPVerifiesCertificate` and `TestSMTPVerifiesCertificate`
  check that a wrong CA fails).
- No test reads credentials from the environment. Configuration tests pass
  their own `getenv` functions.
- Nothing calls gcloud or any Google API. The only network access is
  govulncheck (vuln.go.dev) and, for `scripts/inspector-local.sh`, npm
  downloading the pinned Inspector.
- `TestDevMailbox` is not a test. It is a dev tool that runs the same
  fixtures until interrupted, is skipped unless `DEVMAILBOX=1`, and is used
  by `scripts/inspector-local.sh`.

## Phase 4 requirements → tests

Package paths are relative to `internal/` unless noted.

### Unit tests: MIME handling

| Behaviour | Tests |
|---|---|
| Choosing body parts from BODYSTRUCTURE (plain vs HTML, nested multipart, attachments) | `mail.TestPlanBody`, `mail.TestAttachmentMetadata` (RFC 2231/2047 filenames) |
| Transfer encodings and charsets (base64, QP, ISO-8859-x, Windows-1252 fallback, broken base64) | `mail.TestDecodeTextPart`, `mail.FuzzDecodeTextPart` (always valid UTF-8) |
| HTML → text, hidden-content removal | `mail.TestHTMLToTextStructure`, `…RemovesHiddenContent`, `…KeepsBorderlineVisible`, `…InvisibleUnicode`, `…Limit`, `…Malformed`, `mail.FuzzHTMLToText` (a `display:none` marker never leaks, whatever follows), `mail.FuzzParseHiddenCSS` |
| Invisible Unicode, control characters, header cleaning | `mail.TestCleanText*`, `mail.TestCleanHeader`, `mail.TestTruncateBytesRuneBoundary`, `mail.TestTidyLines`, `mail.FuzzCleanText` (idempotent, single-line headers) |
| Outgoing message (From must be the account, Bcc stripped, Date refreshed) | `mail.TestPrepareOutgoingRejectsForeignFrom`, `mail.TestPrepareOutgoingStripsBccRefreshesDate`, `mail.FuzzPrepareOutgoing` (no Bcc ever transmitted) |
| Full messages over IMAP | `mail.TestReadPlainNeverMarksSeen`, `mail.TestReadHTMLStripsHidden`, `mail.TestReadMultipartAttachmentsCharsets`, `mail.TestReadBodyCap` |
| Message and draft IDs (canonical, UIDVALIDITY-checked, MAC-bound) | `mail.TestMsgRefRoundTrip`, `mail.TestParseIDRejectsMalformed`, `mail.TestParseDraftRefRequiresDraftID`, `mail.TestDraftMACBindsEverything`, `mail.FuzzParseID` (every accepted ID has exactly one spelling) |

### Unit tests: folder discovery

| Behaviour | Tests |
|---|---|
| SPECIAL-USE attributes, case-insensitive | `mail.TestResolveRolesSpecialUse`, `mail.TestResolveRolesCaseInsensitiveAttrs` |
| Name heuristics (English/German names, Courier `INBOX.` layout), ranking and ties | `mail.TestResolveRolesWellKnownNames`, `…CourierLayout`, `…NameRankAndTies` |
| `\Noselect`, overrides, missing roles, one role per folder | `mail.TestResolveRolesSkipsNoSelect`, `…Overrides`, `…Missing`, `…OneRolePerFolder` |
| Against the IMAP server (LIST-STATUS and the minimal-server fallback) | `mail.TestListFolders`, `mail.TestListFoldersMinimalServer` |

### Integration: IMAP memserver and stub SMTP

| Area | Tests |
|---|---|
| Search, read, stale/missing/invalid IDs | `mail.TestSearch`, `mail.TestSearchErrors`, `mail.TestReadStaleMissingInvalid` |
| Drafts and sending, including without UIDPLUS, forgeries, SMTP failures, post-send warnings, delivery-unknown lock | `mail.TestCreateAndSendDraft`, `…CreateDraftWithoutUIDPLUS`, `…SendDraftRejectsForgeries`, `…SendDraftPolicyAndSMTPFailure`, `…SendDraftWarnsInsteadOfFailingAfterSubmit`, `…SendDraftDeliveryUnknownBlocksRetry`, `…ReplyThreading`, `…CreateDraftValidation` |
| Move, mark, refusal without MOVE | `mail.TestMove`, `mail.TestMoveRefusedWithoutMOVE`, `mail.TestMarkRead` |
| TLS, authentication, timeouts | `mail.TestIMAPAuthFailure`, `mail.TestIMAPVerifiesCertificate`, `mail.TestIMAPTimeout`, `mail.TestSMTP*` (5 tests) |
| Durable send ledger and record store | `mail.TestLedger*`, `mail.TestSendRecordsLedgerAndStillTrashesDraft`, `mail.TestRecordStore*`, `mail.TestStateFolder*` |
| All seven tools end to end against both servers | `mcptools.TestEndToEndToolsAgainstMailServers` |
| **Concurrency** (`-race`): parallel sessions read, flag, archive and draft at once; one draft sent from 8 sessions → delivered once; 15 drafts sent twice each → exactly the remaining cap delivered, each once; logs stay clean | `mcptools.TestConcurrentToolCalls`. Mutation-checked: removing the policy mutex or the per-draft guard makes it fail. |
| Durable refresh-reuse detection across restarts | `authstate.TestReuseDetectedAcrossRestartsWithIMAP` |
| Binary: serve, graceful shutdown, config errors | `cmd/email-mcp.TestServeAndGracefulShutdown`, `…ConfigErrorExitsWithoutLeakingSecrets`, `…HashPasswordCommand`, `…UsageAndVersion` |

### OAuth

| Requirement | Tests |
|---|---|
| Wrong `redirect_uri` | `oauth.TestAuthorizeNeverRedirectsToUnregisteredURI` (400 and no redirect for: other host, trailing slash, extra query, http downgrade, case change, missing, repeated; unknown or missing client), `oauth.TestRedirectURIMustMatchAtTokenEndpoint`, `oauth.FuzzAuthorize` (never redirects off the registered callback), Inspector H6 |
| Bad PKCE | `oauth.TestAuthorizeErrorRedirects` (missing, `plain`, short, repeated challenge), `oauth.TestBadPKCEConsumesCode` (wrong verifier → `invalid_grant`, and the code is gone), `oauth.TestTokenEndpointRequestValidation` (verifier syntax) |
| Replayed / expired code | `oauth.TestReplayedCodeRevokesIssuedTokens` (replay → `invalid_grant`, and the first exchange's tokens are revoked), `oauth.TestExpiredCode`, `oauth.TestConcurrentCodeRedemption` (16 parallel redemptions: one wins, its tokens are then revoked) |
| Wrong audience | `oauth.TestForgedAndMisboundAccessTokens` ("wrong audience", "issuer as aud"), `oauth.TestAuthorizeErrorRedirects` ("wrong resource" → `invalid_target`), `oauth.TestTokenEndpointRequestValidation` (`invalid_target`) |
| Refresh rotation | `oauth.TestRefreshRotationAndReuseDetection` (rotated; old token reuse kills the family including access tokens; other families unaffected), `oauth.TestConcurrentRefresh`, `oauth.TestConcurrentIndependentFamilies`, `oauth.TestRefreshTokenExpiry`, `oauth.TestReuseDetectionSurvivesRestart`, `oauth.TestRotationContinuesAcrossRestart`, `oauth.TestDurableJournalRejectsUnknownFamily`, `oauth.TestJournalOutage` (503, nothing revoked), `authstate.TestReuseDetectedAcrossRestartsWithIMAP` |
| Bad client secret | `oauth.TestClientAuthentication` (wrong secret via POST body and via Basic, no authentication, both methods at once, failure rate limit), Inspector H5 |
| Missing / forged bearer token | `oauth.TestForgedAndMisboundAccessTokens` (alg none, HS512, wrong key/issuer/typ/epoch/client/scope, expired, no expiry, future iat), `oauth.FuzzVerifyAccessToken` (nothing unsigned is accepted; one generic error), `oauth.TestEpochChangeRevokesAllTokens`, `server.TestEndToEndOAuthAndMCP` (401 + `resource_metadata`), `server.TestInvalidBearerResponseIsGeneric`, Inspector H3, H4, R1 |
| Owner login | `oauth.TestBasicLogin`, `oauth.TestFormLogin` (CSP `form-action`, CSRF token bound to the `__Host-mcp_login` cookie, cross-site POST refused), `oauth.TestLoginFailuresAreRateLimited`, `oauth.TestPasswordHashes`, `oauth.FuzzParseHash` (bounded argon2 parameters) |
| Token endpoint robustness | `oauth.FuzzTokenEndpoint` (never 5xx, never 200 without a valid grant) |

### Safety

| Requirement | Tests |
|---|---|
| Send without `confirm: true` fails | `mcptools.TestSendRequiresConfirmTrue` (false, missing, string `"true"`), `mcptools.TestEndToEndToolsAgainstMailServers` (nothing reaches SMTP), Inspector C2–C4 |
| Allowlist enforced | `policy.TestAllowlist`, `policy.TestInvalidAllowlistEntries`, `policy.TestRejectedAllowlistDoesNotConsumeQuota`, `mcptools.TestCreateDraftWarnsOnPolicy`, `mail.TestSendDraftPolicyAndSMTPFailure`, e2e, Inspector C9–C10 |
| Daily cap enforced | `policy.TestRollingDailyCap`, `policy.TestCapZeroDisablesSending`, `policy.TestConcurrentAdmitIsAtomic`, `policy.TestLedgerIsSourceOfTruth`, `policy.TestLedgerFailuresFailClosed`, `policy.TestDurableCapAcrossRestart`, `mcptools.TestConcurrentToolCalls`, e2e, Inspector C11–C13 |
| No code path performs EXPUNGE | static: `mail.TestNoDestructiveCallsInSource` (no `Expunge`, `UIDExpunge`, `UnselectAndExpunge` or `Delete` call anywhere in production source); wire: `mail.TestNoDestructiveIMAPCommands` (records every command of every operation); guard: `mail.TestGuardBlocksDestructiveCommands`, `…SplitWrites`, `…ChecksCommandAfterLiteral`, `mail.TestGuardBlocksLibraryMoveFallback`, `mail.TestGuardBlocksDirectExpunge`, `mail.FuzzGuard` (no forbidden command reaches the wire, however it is split) |
| Logs contain no bodies, addresses or tokens (slog handler) | `logging.TestHandlerRedactsAndScrubs`, `logging.TestWithAttrsAndGroupsAreRedacted`, `logging.TestScrubCapsLength`, `logging.TestScrubKeepsOrdinaryText`, `logging.FuzzScrub` (no address or JWT survives); log leak checks in `mcptools.TestErrorMappingAndLogging`, `mcptools.TestEndToEndToolsAgainstMailServers`, `mcptools.TestConcurrentToolCalls`, `server.TestEndToEndOAuthAndMCP`, `cmd/email-mcp.TestConfigErrorExitsWithoutLeakingSecrets`; Inspector L1 (the real binary's log after the full checklist) |
| Untrusted mailbox content stays inside one fenced block | `mcptools.TestUntrustedWrappingCannotBeEscaped`, `mcptools.FuzzUntrustedWrapping`, Inspector B4 |
| Tool schemas strict and portable | `mcptools.TestToolList` (no extra properties; one JSON type per property), Inspector A4 |

### Static analysis and vulnerabilities

`go vet`, staticcheck and govulncheck run in `scripts/check.sh`.
govulncheck reports one module-level finding: GO-2026-5932,
`golang.org/x/crypto/openpgp`. That package is not imported, so the finding
is not reachable (VERIFY V1).

### Manual MCP Inspector checklist

See `docs/INSPECTOR.md`:

- Part A is automated in `scripts/inspector-local.sh` (41 checks).
- Part B covers the deployed service.
- Part C covers acceptance in claude.ai.
