package testutil

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
)

// Capability profiles for IMAPServer.
var (
	// CapsDovecotLike resembles a typical Dovecot 2.3 IMAP4rev1 server.
	CapsDovecotLike = imap.CapSet{
		imap.CapIMAP4rev1:        {},
		imap.CapUIDPlus:          {},
		imap.CapMove:             {},
		imap.CapSpecialUse:       {},
		imap.CapCreateSpecialUse: {},
		imap.CapListExtended:     {},
		imap.CapListStatus:       {},
		imap.CapNamespace:        {},
		imap.CapESearch:          {},
		imap.CapLiteralPlus:      {},
		imap.CapChildren:         {},
		imap.CapStatusSize:       {},
		imap.CapUnselect:         {},
		imap.CapSASLIR:           {},
		imap.CapEnable:           {},
	}
	// CapsMinimal is bare IMAP4rev1: no MOVE, UIDPLUS, SPECIAL-USE or
	// LIST-STATUS.
	CapsMinimal = imap.CapSet{imap.CapIMAP4rev1: {}}
)

// IMAPServer is an in-memory IMAP server over implicit TLS. Unlike plain
// imapmemserver it reports SPECIAL-USE attributes registered via AddFolder.
type IMAPServer struct {
	Addr     string
	Username string
	Password string

	user      *imapmemserver.User
	clientTLS *tls.Config

	mu          sync.Mutex
	specialUse  map[string][]imap.MailboxAttr
	noAppendUID bool
}

// DisableAppendUID makes APPEND omit the APPENDUID response code, like a
// server without UIDPLUS.
func (s *IMAPServer) DisableAppendUID() {
	s.mu.Lock()
	s.noAppendUID = true
	s.mu.Unlock()
}

// StartIMAP starts a server with one user and an INBOX. caps nil means
// CapsDovecotLike.
func StartIMAP(t testing.TB, certs *TLS, caps imap.CapSet) *IMAPServer {
	t.Helper()
	if caps == nil {
		caps = CapsDovecotLike
	}
	s := &IMAPServer{
		Username:   "user@example.org",
		Password:   "test-password-not-a-secret",
		clientTLS:  certs.Client,
		specialUse: map[string][]imap.MailboxAttr{},
	}
	s.user = imapmemserver.NewUser(s.Username, s.Password)
	if err := s.user.Create("INBOX", nil); err != nil {
		t.Fatal(err)
	}

	srv := imapserver.New(&imapserver.Options{
		NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return &specialUseSession{srv: s}, nil, nil
		},
		Caps:      caps,
		TLSConfig: certs.Server,
		Logger:    log.New(io.Discard, "", 0),
	})
	ln, err := tls.Listen("tcp", "127.0.0.1:0", certs.Server)
	if err != nil {
		t.Fatal(err)
	}
	s.Addr = ln.Addr().String()
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := srv.Serve(ln); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("imap serve: %v", err)
		}
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		<-done
	})
	return s
}

// AddFolder creates a folder, optionally with SPECIAL-USE attributes.
func (s *IMAPServer) AddFolder(t testing.TB, name string, attrs ...imap.MailboxAttr) {
	t.Helper()
	if err := s.user.Create(name, nil); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.specialUse[name] = attrs
	s.mu.Unlock()
}

// AddMessage appends a raw RFC 5322 message and returns its UID.
func (s *IMAPServer) AddMessage(t testing.TB, folder, raw string, date time.Time, flags ...imap.Flag) imap.UID {
	t.Helper()
	data, err := s.user.Append(folder, bytes.NewReader([]byte(raw)), &imap.AppendOptions{Flags: flags, Time: date})
	if err != nil {
		t.Fatal(err)
	}
	return data.UID
}

// UIDValidity returns the folder's UIDVALIDITY.
func (s *IMAPServer) UIDValidity(t testing.TB, folder string) uint32 {
	t.Helper()
	st, err := s.user.Status(folder, &imap.StatusOptions{UIDValidity: true})
	if err != nil {
		t.Fatal(err)
	}
	return st.UIDValidity
}

// RecreateFolder deletes and re-creates folder, which changes its
// UIDVALIDITY (simulates server-side renumbering).
func (s *IMAPServer) RecreateFolder(t testing.TB, name string) {
	t.Helper()
	if err := s.user.Delete(name); err != nil {
		t.Fatal(err)
	}
	if err := s.user.Create(name, nil); err != nil {
		t.Fatal(err)
	}
}

// MessageInfo is a snapshot of one stored message.
type MessageInfo struct {
	UID   imap.UID
	Flags []imap.Flag
	Raw   []byte
}

// HasFlag reports whether the message carries flag.
func (m MessageInfo) HasFlag(flag imap.Flag) bool {
	for _, f := range m.Flags {
		if f == flag {
			return true
		}
	}
	return false
}

// Messages returns all messages in folder, read through an independent
// IMAP client connection (EXAMINE + BODY.PEEK, so nothing changes).
func (s *IMAPServer) Messages(t testing.TB, folder string) []MessageInfo {
	t.Helper()
	c, err := imapclient.DialTLS(s.Addr, &imapclient.Options{TLSConfig: s.clientTLS})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Login(s.Username, s.Password).Wait(); err != nil {
		t.Fatal(err)
	}
	sel, err := c.Select(folder, &imap.SelectOptions{ReadOnly: true}).Wait()
	if err != nil {
		t.Fatal(err)
	}
	if sel.NumMessages == 0 {
		return nil
	}
	section := &imap.FetchItemBodySection{Peek: true}
	var all imap.SeqSet
	all.AddRange(1, sel.NumMessages)
	bufs, err := c.Fetch(all, &imap.FetchOptions{UID: true, Flags: true, BodySection: []*imap.FetchItemBodySection{section}}).Collect()
	if err != nil {
		t.Fatal(err)
	}
	out := make([]MessageInfo, 0, len(bufs))
	for _, b := range bufs {
		out = append(out, MessageInfo{UID: b.UID, Flags: b.Flags, Raw: b.FindBodySection(section)})
	}
	return out
}

// specialUseSession wraps the memserver session to report SPECIAL-USE
// attributes, which imapmemserver cannot store.
type specialUseSession struct {
	*imapmemserver.UserSession
	srv *IMAPServer
}

func (s *specialUseSession) Login(username, password string) error {
	if err := s.srv.user.Login(username, password); err != nil {
		return err
	}
	s.UserSession = imapmemserver.NewUserSession(s.srv.user)
	return nil
}

func (s *specialUseSession) Close() error {
	if s.UserSession == nil {
		return nil
	}
	return s.UserSession.Close()
}

func (s *specialUseSession) Append(mailbox string, r imap.LiteralReader, options *imap.AppendOptions) (*imap.AppendData, error) {
	data, err := s.UserSession.Append(mailbox, r, options)
	s.srv.mu.Lock()
	hide := s.srv.noAppendUID
	s.srv.mu.Unlock()
	if hide {
		return nil, err
	}
	return data, err
}

func (s *specialUseSession) List(w *imapserver.ListWriter, ref string, patterns []string, options *imap.ListOptions) error {
	s.srv.mu.Lock()
	names := []string{"INBOX"}
	attrsOf := make(map[string][]imap.MailboxAttr, len(s.srv.specialUse))
	for name, attrs := range s.srv.specialUse {
		names = append(names, name)
		attrsOf[name] = attrs
	}
	s.srv.mu.Unlock()
	sort.Strings(names)

	if len(patterns) == 0 {
		return w.WriteList(&imap.ListData{Attrs: []imap.MailboxAttr{imap.MailboxAttrNoSelect}, Delim: '/'})
	}
	for _, name := range names {
		match := false
		for _, p := range patterns {
			if imapserver.MatchList(name, '/', ref, p) {
				match = true
				break
			}
		}
		if !match {
			continue
		}
		su := attrsOf[name]
		if options.SelectSpecialUse && len(su) == 0 {
			continue
		}
		// Like Dovecot, report special-use attributes even without
		// RETURN (SPECIAL-USE).
		data := &imap.ListData{Mailbox: name, Delim: '/', Attrs: append([]imap.MailboxAttr(nil), su...)}
		if options.ReturnStatus != nil {
			st, err := s.UserSession.Status(name, options.ReturnStatus)
			if err != nil {
				return err
			}
			data.Status = st
		}
		if err := w.WriteList(data); err != nil {
			return err
		}
	}
	return nil
}
