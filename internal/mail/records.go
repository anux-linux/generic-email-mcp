package mail

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	nettextproto "net/textproto"
	"slices"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-message/textproto"
)

// DefaultStateFolder holds the OAuth token-family journal.
const DefaultStateFolder = "MCP-Auth-State"

// Record is one machine record: lower-case field names [a-z0-9-], values
// printable ASCII without spaces. Stored as X-MCP-<field> headers of a tiny
// message.
type Record map[string]string

const recordPrefix = "x-mcp-"

// RecordStore keeps records in a dedicated folder that the tools cannot
// move mail into or out of (like the send ledger). Each call opens one IMAP
// connection; callers serialize writes.
type RecordStore struct {
	cl     *Client
	folder string
}

// Records returns the store in the configured state folder, or nil when
// none is configured (AUTH_STATE=memory).
func (cl *Client) Records() *RecordStore {
	if cl.cfg.StateFolder == "" {
		return nil
	}
	return &RecordStore{cl: cl, folder: cl.cfg.StateFolder}
}

func validRecordKey(k string) bool {
	if k == "" || len(k) > 32 {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func validRecordValue(v string) bool {
	if v == "" || len(v) > 256 {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] <= ' ' || v[i] >= 0x7f {
			return false
		}
	}
	return true
}

func headerKey(field string) string { return nettextproto.CanonicalMIMEHeaderKey(recordPrefix + field) }

// Update finds the newest (by UID) records whose field equals value, passes
// up to newest of them (oldest first) to decide, and appends the record
// decide returns, if any — all in one IMAP session. It returns decide's
// error, or a storage error.
func (rs *RecordStore) Update(ctx context.Context, field, value string, newest int, decide func([]Record) (Record, error)) error {
	if !validRecordKey(field) || !validRecordValue(value) || newest < 1 {
		return fmt.Errorf("%w: bad record query", ErrInvalidInput)
	}
	return rs.cl.withSession(ctx, func(s *session) error {
		found, err := rs.find(s, field, value, time.Time{}, newest)
		if err != nil {
			return err
		}
		rec, derr := decide(found)
		if rec != nil {
			if err := rs.append(s, rec); err != nil {
				return err
			}
		}
		return derr
	})
}

// Find returns all records whose field equals value and that were stored
// on or after since (day granularity), oldest first.
func (rs *RecordStore) Find(ctx context.Context, field, value string, since time.Time) ([]Record, error) {
	if !validRecordKey(field) || !validRecordValue(value) {
		return nil, fmt.Errorf("%w: bad record query", ErrInvalidInput)
	}
	var out []Record
	err := rs.cl.withSession(ctx, func(s *session) error {
		var err error
		out, err = rs.find(s, field, value, since, 1000)
		return err
	})
	return out, err
}

// checkFolder refuses a state folder that is also a role folder (e.g.
// AUTH_STATE_FOLDER=Sent would hide records among real mail).
func (rs *RecordStore) checkFolder(s *session) error {
	roles, _, err := s.roles(rs.cl.cfg.Folders)
	if err != nil {
		return err
	}
	if r := roles.roleOf(rs.folder); r != RoleNone {
		return fmt.Errorf("%w: the auth state folder must not be the %s folder", ErrInvalidInput, r)
	}
	return nil
}

func (rs *RecordStore) find(s *session, field, value string, since time.Time, limit int) ([]Record, error) {
	if err := rs.checkFolder(s); err != nil {
		return nil, err
	}
	if _, err := s.examine(rs.folder); err != nil {
		if errors.Is(err, ErrFolderNotFound) {
			return nil, nil // nothing stored yet
		}
		return nil, err
	}
	criteria := &imap.SearchCriteria{
		Header:  []imap.SearchCriteriaHeaderField{{Key: headerKey(field), Value: value}},
		NotFlag: []imap.Flag{imap.FlagDeleted},
	}
	if !since.IsZero() {
		criteria.Since = dateOnly(since).AddDate(0, 0, -1) // server-timezone margin
	}
	data, err := s.c.UIDSearch(criteria, nil).Wait()
	if err != nil {
		return nil, fmt.Errorf("%w: record search: %w", ErrUpstream, err)
	}
	uids := data.AllUIDs()
	slices.Sort(uids)
	if len(uids) > limit {
		uids = uids[len(uids)-limit:]
	}
	if len(uids) == 0 {
		return nil, nil
	}
	section := &imap.FetchItemBodySection{Specifier: imap.PartSpecifierHeader, Peek: true}
	bufs, err := s.c.Fetch(imap.UIDSetNum(uids...), &imap.FetchOptions{UID: true, BodySection: []*imap.FetchItemBodySection{section}}).Collect()
	if err != nil {
		return nil, fmt.Errorf("%w: record fetch: %w", ErrUpstream, err)
	}
	slices.SortFunc(bufs, func(a, b *imapclient.FetchMessageBuffer) int { return cmp.Compare(a.UID, b.UID) })
	var out []Record
	for _, b := range bufs {
		rec := parseRecord(b.FindBodySection(section))
		if rec[field] == value { // SEARCH HEADER is a substring match
			out = append(out, rec)
		}
	}
	return out, nil
}

func parseRecord(raw []byte) Record {
	h, err := textproto.ReadHeader(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return nil
	}
	rec := Record{}
	for f := h.Fields(); f.Next(); {
		if k, ok := strings.CutPrefix(strings.ToLower(f.Key()), recordPrefix); ok {
			rec[k] = strings.TrimSpace(f.Value())
		}
	}
	return rec
}

func (rs *RecordStore) append(s *session, rec Record) error {
	keys := make([]string, 0, len(rec))
	for k, v := range rec {
		if !validRecordKey(k) || !validRecordValue(v) {
			return fmt.Errorf("%w: bad record field", ErrInvalidInput)
		}
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var nonce [8]byte
	_, _ = rand.Read(nonce[:])
	now := rs.cl.now()
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "Date: %s\r\nFrom: <%s>\r\nTo: <%s>\r\nSubject: [generic-email-mcp] state record\r\nMessage-ID: <%s.state@generic-email-mcp.invalid>\r\n",
		now.Format(time.RFC1123Z), rs.cl.cfg.FromAddress, rs.cl.cfg.FromAddress, hex.EncodeToString(nonce[:]))
	for _, k := range keys {
		fmt.Fprintf(&buf, "%s: %s\r\n", headerKey(k), rec[k])
	}
	buf.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\n" +
		"Authorization state of generic-email-mcp (refresh-token rotation and revocation).\r\n" +
		"Moving or deleting these messages logs the connected client out.\r\n")
	raw := buf.Bytes()

	appendOnce := func() error {
		cmd := s.c.Append(rs.folder, int64(len(raw)), &imap.AppendOptions{Flags: []imap.Flag{imap.FlagSeen}, Time: now})
		if _, err := cmd.Write(raw); err != nil {
			return err
		}
		if err := cmd.Close(); err != nil {
			return err
		}
		_, err := cmd.Wait()
		return err
	}
	err := appendOnce()
	var imapErr *imap.Error
	if errors.As(err, &imapErr) && imapErr.Code == imap.ResponseCodeTryCreate {
		if cerr := s.c.Create(rs.folder, nil).Wait(); cerr != nil {
			return fmt.Errorf("%w: create state folder: %w", ErrUpstream, cerr)
		}
		err = appendOnce()
	}
	if err != nil {
		return fmt.Errorf("%w: record append: %w", ErrUpstream, err)
	}
	return nil
}
