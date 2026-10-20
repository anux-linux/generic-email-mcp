package mail

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"net"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-message/charset"
)

const (
	logoutTimeout = 2 * time.Second
	// defaultOpTimeout bounds a call whose context has no deadline.
	defaultOpTimeout = 45 * time.Second
)

// session is one authenticated IMAP connection, used for a single call.
type session struct {
	c    *imapclient.Client
	caps imap.CapSet
}

// withSession dials, authenticates, runs fn and logs out. The connection is
// closed when ctx is done, which aborts any pending command.
func (cl *Client) withSession(ctx context.Context, fn func(*session) error) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultOpTimeout)
		defer cancel()
	}
	conn, err := cl.dialIMAP(ctx)
	if err != nil {
		return ctxErr(ctx, fmt.Errorf("imap connect: %w", err))
	}
	guard := newGuardConn(conn)
	guard.onCommand = cl.onIMAPCommand
	c := imapclient.New(guard, &imapclient.Options{
		WordDecoder: &mime.WordDecoder{CharsetReader: charset.Reader},
	})
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer func() {
		stop()
		_ = c.Close()
	}()

	if err := c.WaitGreeting(); err != nil {
		return ctxErr(ctx, fmt.Errorf("%w: imap greeting: %w", ErrUpstream, err))
	}
	if c.State() == imap.ConnStateNotAuthenticated {
		if err := c.Login(cl.cfg.Username, cl.cfg.Password).Wait(); err != nil {
			var imapErr *imap.Error
			if errors.As(err, &imapErr) {
				// Server text is dropped: it may echo the username.
				return ErrAuth
			}
			return ctxErr(ctx, fmt.Errorf("%w: imap login: %w", ErrUpstream, err))
		}
	}
	s := &session{c: c, caps: c.Caps()}
	if s.caps == nil {
		return ctxErr(ctx, fmt.Errorf("%w: imap capabilities unavailable", ErrUpstream))
	}

	err = fn(s)
	if gerr := guard.blocked(); gerr != nil {
		return gerr
	}

	if ctx.Err() == nil {
		done := make(chan struct{})
		go func() {
			_ = c.Logout().Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(logoutTimeout):
		}
	}
	return ctxErr(ctx, err)
}

func (cl *Client) dialIMAP(ctx context.Context) (net.Conn, error) {
	host, _, err := net.SplitHostPort(cl.cfg.IMAPAddr)
	if err != nil {
		return nil, err
	}
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: cl.cfg.DialTimeout},
		Config:    cl.cfg.tlsConfig(host, "imap"),
	}
	return d.DialContext(ctx, "tcp", cl.cfg.IMAPAddr)
}

// examine opens folder read-only. Reads always use EXAMINE so no server-side
// flag can change as a side effect.
func (s *session) examine(folder string) (*imap.SelectData, error) {
	return s.open(folder, true)
}

// selectRW opens folder read-write (flag changes, MOVE).
func (s *session) selectRW(folder string) (*imap.SelectData, error) {
	return s.open(folder, false)
}

func (s *session) open(folder string, readOnly bool) (*imap.SelectData, error) {
	data, err := s.c.Select(folder, &imap.SelectOptions{ReadOnly: readOnly}).Wait()
	if err != nil {
		var imapErr *imap.Error
		if errors.As(err, &imapErr) && imapErr.Type == imap.StatusResponseTypeNo {
			return nil, fmt.Errorf("%w: %q", ErrFolderNotFound, folder)
		}
		return nil, fmt.Errorf("%w: select: %w", ErrUpstream, err)
	}
	return data, nil
}

// openRef opens the folder of ref and verifies its UIDVALIDITY.
func (s *session) openRef(ref msgRef, readOnly bool) error {
	data, err := s.open(ref.Folder, readOnly)
	if err != nil {
		return err
	}
	if data.UIDValidity != ref.UIDValidity {
		return ErrStaleID
	}
	return nil
}

// list returns all folders. Special-use attributes are requested when the
// server supports it; counts are included via LIST-STATUS when available.
func (s *session) list(withStatus bool) ([]folderEntry, error) {
	opts := &imap.ListOptions{}
	if s.caps.Has(imap.CapSpecialUse) && s.caps.Has(imap.CapListExtended) {
		opts.ReturnSpecialUse = true
	}
	if withStatus && s.caps.Has(imap.CapListStatus) {
		opts.ReturnStatus = &imap.StatusOptions{NumMessages: true, NumUnseen: true}
	}
	data, err := s.c.List("", "*", opts).Collect()
	if err != nil {
		return nil, fmt.Errorf("%w: list: %w", ErrUpstream, err)
	}
	entries := make([]folderEntry, 0, len(data))
	for _, d := range data {
		if d.Mailbox == "" {
			continue
		}
		entries = append(entries, folderEntry{Name: d.Mailbox, Delim: d.Delim, Attrs: d.Attrs, Status: d.Status})
	}
	return entries, nil
}

// roles runs folder discovery on this session.
func (s *session) roles(ov FolderOverrides) (roleMap, []folderEntry, error) {
	entries, err := s.list(false)
	if err != nil {
		return roleMap{}, nil, err
	}
	return resolveRoles(entries, ov), entries, nil
}
