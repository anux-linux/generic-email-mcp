package mail

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-message/textproto"
)

// SendLedger durably records sends so limits survive restarts. SendDraft
// passes one bound to its IMAP session to SendPolicy.Admit, or nil when no
// ledger is configured.
type SendLedger interface {
	// Recent returns up to limit recorded send times at or after since,
	// oldest first.
	Recent(ctx context.Context, since time.Time, limit int) ([]time.Time, error)
	// Record durably records a send at t.
	Record(ctx context.Context, t time.Time) error
}

// ErrProtected is returned for operations on the send ledger folder.
var ErrProtected = errors.New("the send ledger folder is protected: it enforces MAX_SENDS_PER_DAY")

// DefaultLedgerFolder is created on first use.
const DefaultLedgerFolder = "MCP-Send-Ledger"

// ledgerHeader carries the send time (RFC 3339, UTC) of a ledger entry.
const ledgerHeader = "X-Generic-Email-MCP-Send"

// imapLedger stores one small message per send in a dedicated folder. Entries
// carry no recipients or content. The tools cannot move entries out (Move
// refuses the folder) and nothing can delete them, so the model cannot reset
// the count; the mailbox owner can, from any mail client.
type imapLedger struct {
	s       *session
	folder  string
	account string
}

// Recent searches the ledger for entries, newest UIDs first, and parses
// their timestamps. A missing folder means no sends were recorded yet.
func (l *imapLedger) Recent(_ context.Context, since time.Time, limit int) ([]time.Time, error) {
	if limit <= 0 {
		return nil, nil
	}
	if _, err := l.s.examine(l.folder); err != nil {
		if errors.Is(err, ErrFolderNotFound) {
			return nil, nil
		}
		return nil, err
	}
	// SINCE has day granularity in the server's time zone; a one-day margin
	// keeps the pre-filter safe, the header timestamp decides.
	found, err := l.s.c.UIDSearch(&imap.SearchCriteria{
		Since:   dateOnly(since).AddDate(0, 0, -1),
		Header:  []imap.SearchCriteriaHeaderField{{Key: ledgerHeader, Value: ""}},
		NotFlag: []imap.Flag{imap.FlagDeleted},
	}, nil).Wait()
	if err != nil {
		return nil, fmt.Errorf("%w: ledger search: %w", ErrUpstream, err)
	}
	uids := found.AllUIDs()
	slices.Sort(uids)
	slices.Reverse(uids)
	if len(uids) > limit {
		uids = uids[:limit] // entries are appended in time order
	}
	if len(uids) == 0 {
		return nil, nil
	}
	section := &imap.FetchItemBodySection{Specifier: imap.PartSpecifierHeader, HeaderFields: []string{ledgerHeader}, Peek: true}
	bufs, err := l.s.c.Fetch(imap.UIDSetNum(uids...), &imap.FetchOptions{
		UID: true, BodySection: []*imap.FetchItemBodySection{section},
	}).Collect()
	if err != nil {
		return nil, fmt.Errorf("%w: ledger fetch: %w", ErrUpstream, err)
	}
	var times []time.Time
	for _, b := range bufs {
		h, err := textproto.ReadHeader(bufio.NewReader(bytes.NewReader(b.FindBodySection(section))))
		if err != nil {
			continue
		}
		t, err := time.Parse(time.RFC3339, strings.TrimSpace(h.Get(ledgerHeader)))
		if err == nil && !t.Before(since) {
			times = append(times, t)
		}
	}
	slices.SortFunc(times, time.Time.Compare)
	return times, nil
}

// Record appends one entry, creating the folder if needed.
func (l *imapLedger) Record(_ context.Context, t time.Time) error {
	raw := ledgerEntry(l.account, t)
	err := l.appendEntry(raw, t)
	var imapErr *imap.Error
	if errors.As(err, &imapErr) && imapErr.Code == imap.ResponseCodeTryCreate {
		if cerr := l.s.c.Create(l.folder, nil).Wait(); cerr != nil {
			return fmt.Errorf("%w: create ledger folder: %w", ErrUpstream, cerr)
		}
		err = l.appendEntry(raw, t)
	}
	if err != nil {
		return fmt.Errorf("%w: ledger append: %w", ErrUpstream, err)
	}
	return nil
}

func (l *imapLedger) appendEntry(raw []byte, t time.Time) error {
	cmd := l.s.c.Append(l.folder, int64(len(raw)), &imap.AppendOptions{Flags: []imap.Flag{imap.FlagSeen}, Time: t})
	if _, err := cmd.Write(raw); err != nil {
		return err
	}
	if err := cmd.Close(); err != nil {
		return err
	}
	_, err := cmd.Wait()
	return err
}

// ledgerEntry renders an entry. account is a validated ASCII address.
func ledgerEntry(account string, t time.Time) []byte {
	return fmt.Appendf(nil, "Date: %s\r\n"+
		"From: <%s>\r\n"+
		"To: <%s>\r\n"+
		"Subject: [generic-email-mcp] send ledger entry\r\n"+
		"%s: %s\r\n"+
		"MIME-Version: 1.0\r\n"+
		"Content-Type: text/plain; charset=us-ascii\r\n"+
		"\r\n"+
		"This message records one e-mail sent through generic-email-mcp.\r\n"+
		"It enforces MAX_SENDS_PER_DAY across restarts. Entries older than\r\n"+
		"24 hours no longer count and may be deleted.\r\n",
		t.Format(time.RFC1123Z), account, account, ledgerHeader, t.UTC().Format(time.RFC3339))
}

// isLedger reports whether folder is the configured ledger folder.
func (cl *Client) isLedger(folder string) bool {
	return cl.cfg.LedgerFolder != "" && folder == cl.cfg.LedgerFolder
}
