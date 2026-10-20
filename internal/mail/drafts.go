package mail

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	netmail "net/mail"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-message"
	gomail "github.com/emersion/go-message/mail"
	"github.com/emersion/go-message/textproto"
)

const (
	maxRecipients   = 50
	maxSubjectRunes = 500
	maxDraftBody    = 256 << 10
	maxDraftBytes   = 1 << 20
	maxReferences   = 20
	maxMsgIDLen     = 250
)

// CreateDraft composes a plain-text message and APPENDs it to the Drafts
// folder with \Draft and \Seen. The returned ID authenticates the exact
// stored bytes.
func (cl *Client) CreateDraft(ctx context.Context, in DraftInput) (*Draft, error) {
	nd, err := normalizeDraft(in)
	if err != nil {
		return nil, err
	}
	var replyRef *msgRef
	if in.InReplyTo != "" {
		ref, err := parseRef(in.InReplyTo)
		if err != nil {
			return nil, err
		}
		replyRef = &ref
	}
	var out *Draft
	err = cl.withSession(ctx, func(s *session) error {
		roles, _, err := s.roles(cl.cfg.Folders)
		if err != nil {
			return err
		}
		drafts, err := roles.get(RoleDrafts)
		if err != nil {
			return err
		}
		if replyRef != nil {
			if err := s.applyReply(*replyRef, &nd); err != nil {
				return err
			}
		}
		if err := nd.checkRecipients(); err != nil {
			return err
		}
		now := cl.now()
		raw, msgID, err := cl.compose(nd, now)
		if err != nil {
			return err
		}
		ref, err := s.appendDraft(drafts, raw, msgID, now)
		if err != nil {
			return err
		}
		mac := draftMAC(cl.cfg.DraftKey, cl.cfg.Username, ref, raw)
		out = &Draft{
			ID:        formatDraftID(ref, mac),
			Folder:    drafts,
			MessageID: msgID,
			From:      Address{Name: cl.cfg.FromName, Email: cl.cfg.FromAddress},
			To:        toAddresses(nd.to),
			Cc:        toAddresses(nd.cc),
			Bcc:       toAddresses(nd.bcc),
			Subject:   nd.subject,
			InReplyTo: nd.inReplyTo,
			Body:      nd.body,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// normalizedDraft is validated draft input.
type normalizedDraft struct {
	to, cc, bcc []*netmail.Address
	subject     string
	body        string
	inReplyTo   string
	references  []string
}

func normalizeDraft(in DraftInput) (normalizedDraft, error) {
	var nd normalizedDraft
	seen := map[string]bool{}
	var err error
	if nd.to, err = parseRecipients(in.To, seen); err != nil {
		return nd, err
	}
	if nd.cc, err = parseRecipients(in.Cc, seen); err != nil {
		return nd, err
	}
	if nd.bcc, err = parseRecipients(in.Bcc, seen); err != nil {
		return nd, err
	}
	if !utf8.ValidString(in.Subject) || utf8.RuneCountInString(in.Subject) > maxSubjectRunes {
		return nd, fmt.Errorf("%w: subject must be valid text of at most %d characters", ErrInvalidInput, maxSubjectRunes)
	}
	nd.subject = cleanHeader(in.Subject, maxSubjectRunes)
	if !utf8.ValidString(in.Body) || len(in.Body) > maxDraftBody {
		return nd, fmt.Errorf("%w: body must be valid UTF-8 of at most %d bytes", ErrInvalidInput, maxDraftBody)
	}
	for _, r := range in.Body {
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' || r == 0x7f {
			return nd, fmt.Errorf("%w: body contains control characters", ErrInvalidInput)
		}
	}
	// Invisible characters are stripped so the reviewed text is exactly what
	// recipients see (no hidden payloads, e.g. Unicode tag characters).
	nd.body = cleanText(in.Body)
	if nd.body != "" && !strings.HasSuffix(nd.body, "\n") {
		nd.body += "\n" // SMTP DATA ends with CRLF anyway; store what is sent
	}
	return nd, nil
}

func (nd *normalizedDraft) checkRecipients() error {
	n := len(nd.to) + len(nd.cc) + len(nd.bcc)
	if n == 0 {
		return fmt.Errorf("%w: at least one recipient is required", ErrInvalidInput)
	}
	if n > maxRecipients {
		return fmt.Errorf("%w: at most %d recipients", ErrInvalidInput, maxRecipients)
	}
	return nil
}

// parseRecipients parses RFC 5322 address strings (groups are flattened to
// their members), rejecting non-ASCII addresses (no SMTPUTF8) and dropping
// duplicates across To/Cc/Bcc.
func parseRecipients(list []string, seen map[string]bool) ([]*netmail.Address, error) {
	var out []*netmail.Address
	for _, entry := range list {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if len(entry) > 1000 || strings.ContainsAny(entry, "\r\n\x00") {
			return nil, fmt.Errorf("%w: malformed address", ErrInvalidInput)
		}
		addrs, err := netmail.ParseAddressList(entry)
		if err != nil {
			return nil, fmt.Errorf("%w: malformed address", ErrInvalidInput)
		}
		for _, a := range addrs {
			if !isASCII(a.Address) || !strings.Contains(a.Address, "@") || len(a.Address) > 254 {
				return nil, fmt.Errorf("%w: addresses must be ASCII user@domain", ErrInvalidInput)
			}
			key := strings.ToLower(a.Address)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, &netmail.Address{Name: cleanHeader(a.Name, 200), Address: a.Address})
		}
	}
	if len(out) > maxRecipients {
		return nil, fmt.Errorf("%w: at most %d recipients", ErrInvalidInput, maxRecipients)
	}
	return out, nil
}

// applyReply fills threading headers and defaults from the original.
func (s *session) applyReply(ref msgRef, nd *normalizedDraft) error {
	if err := s.openRef(ref, true); err != nil {
		return err
	}
	refsSection := &imap.FetchItemBodySection{
		Specifier:    imap.PartSpecifierHeader,
		HeaderFields: []string{"References"},
		Peek:         true,
	}
	bufs, err := s.c.Fetch(imap.UIDSetNum(ref.UID), &imap.FetchOptions{
		UID:         true,
		Envelope:    true,
		BodySection: []*imap.FetchItemBodySection{refsSection},
	}).Collect()
	if err != nil {
		return fmt.Errorf("%w: fetch: %w", ErrUpstream, err)
	}
	b := findUID(bufs, ref.UID)
	if b == nil || b.Envelope == nil {
		return ErrNotFound
	}
	env := b.Envelope
	if validMsgID(env.MessageID) {
		nd.inReplyTo = env.MessageID
		var refs []string
		if raw := b.FindBodySection(refsSection); len(raw) > 0 {
			h, err := textproto.ReadHeader(bufio.NewReader(bytes.NewReader(raw)))
			if err == nil {
				mh := gomail.Header{Header: message.Header{Header: h}}
				refs, _ = mh.MsgIDList("References")
			}
		}
		if len(refs) == 0 && len(env.InReplyTo) == 1 {
			refs = env.InReplyTo
		}
		refs = slices.DeleteFunc(slices.Clone(refs), func(id string) bool { return !validMsgID(id) })
		refs = append(refs, env.MessageID)
		if len(refs) > maxReferences {
			refs = append(refs[:1], refs[len(refs)-maxReferences+1:]...)
		}
		nd.references = refs
	}
	if nd.subject == "" {
		nd.subject = replySubject(cleanHeader(env.Subject, maxSubjectRunes))
	}
	if len(nd.to) == 0 {
		src := env.ReplyTo
		if len(src) == 0 {
			src = env.From
		}
		used := map[string]bool{}
		for _, l := range [][]*netmail.Address{nd.cc, nd.bcc} {
			for _, a := range l {
				used[strings.ToLower(a.Address)] = true
			}
		}
		for _, a := range src {
			if addr := a.Addr(); addr != "" && isASCII(addr) && !used[strings.ToLower(addr)] {
				nd.to = append(nd.to, &netmail.Address{Name: cleanHeader(a.Name, 200), Address: addr})
				break
			}
		}
	}
	return nil
}

func replySubject(orig string) string {
	lower := strings.ToLower(orig)
	for _, p := range []string{"re:", "aw:", "antw:"} {
		if strings.HasPrefix(lower, p) {
			return orig
		}
	}
	return truncateRunes("Re: "+orig, maxSubjectRunes)
}

// validMsgID accepts msg-id content (without brackets) that is safe to
// re-emit in a header.
func validMsgID(id string) bool {
	if id == "" || len(id) > maxMsgIDLen || !strings.Contains(id, "@") {
		return false
	}
	for i := 0; i < len(id); i++ {
		if c := id[i]; c <= ' ' || c >= 0x7f || c == '<' || c == '>' {
			return false
		}
	}
	return true
}

var msgIDEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// compose renders the draft as an RFC 5322 message with CRLF line endings,
// a quoted-printable UTF-8 text/plain body and RFC 2047 encoded headers.
func (cl *Client) compose(nd normalizedDraft, now time.Time) ([]byte, string, error) {
	var rnd [20]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, "", err
	}
	domain := cl.cfg.FromAddress[strings.LastIndexByte(cl.cfg.FromAddress, '@')+1:]
	msgID := strings.ToLower(msgIDEncoding.EncodeToString(rnd[:])) + "@" + domain

	var h gomail.Header
	h.SetDate(now)
	h.SetAddressList("From", []*gomail.Address{{Name: cl.cfg.FromName, Address: cl.cfg.FromAddress}})
	h.SetAddressList("To", nd.to)
	h.SetAddressList("Cc", nd.cc)
	h.SetAddressList("Bcc", nd.bcc)
	h.SetSubject(nd.subject)
	h.SetMessageID(msgID)
	if nd.inReplyTo != "" {
		h.SetMsgIDList("In-Reply-To", []string{nd.inReplyTo})
		h.SetMsgIDList("References", nd.references)
	}
	h.SetContentType("text/plain", map[string]string{"charset": "utf-8"})

	var buf bytes.Buffer
	w, err := gomail.CreateSingleInlineWriter(&buf, h)
	if err != nil {
		return nil, "", err
	}
	if _, err := io.WriteString(w, nd.body); err != nil {
		return nil, "", err
	}
	if err := w.Close(); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), msgID, nil
}

// appendDraft stores raw in folder and returns its location. Without
// UIDPLUS the UID is recovered by searching for the unique Message-ID.
func (s *session) appendDraft(folder string, raw []byte, msgID string, now time.Time) (msgRef, error) {
	cmd := s.c.Append(folder, int64(len(raw)), &imap.AppendOptions{
		Flags: []imap.Flag{imap.FlagDraft, imap.FlagSeen},
		Time:  now,
	})
	if _, err := cmd.Write(raw); err != nil {
		return msgRef{}, fmt.Errorf("%w: append: %w", ErrUpstream, err)
	}
	if err := cmd.Close(); err != nil {
		return msgRef{}, fmt.Errorf("%w: append: %w", ErrUpstream, err)
	}
	data, err := cmd.Wait()
	if err != nil {
		return msgRef{}, fmt.Errorf("%w: append: %w", ErrUpstream, err)
	}
	if data.UID != 0 && data.UIDValidity != 0 {
		return msgRef{folder, data.UIDValidity, data.UID}, nil
	}
	sel, err := s.examine(folder)
	if err != nil {
		return msgRef{}, err
	}
	found, err := s.c.UIDSearch(&imap.SearchCriteria{
		Header: []imap.SearchCriteriaHeaderField{{Key: "Message-ID", Value: "<" + msgID + ">"}},
	}, nil).Wait()
	if err != nil {
		return msgRef{}, fmt.Errorf("%w: search: %w", ErrUpstream, err)
	}
	uids := found.AllUIDs()
	if len(uids) == 0 {
		return msgRef{}, fmt.Errorf("%w: appended draft not found", ErrUpstream)
	}
	return msgRef{folder, sel.UIDValidity, slices.Max(uids)}, nil
}

// SendDraft submits a draft created by CreateDraft. It verifies the draft's
// HMAC over the exact stored bytes, applies the send policy, submits via
// SMTP, then (best effort, reported as warnings) saves a copy to Sent and
// moves the draft to Trash so the same ID cannot be sent again.
func (cl *Client) SendDraft(ctx context.Context, draftID string) (*SendResult, error) {
	ref, mac, err := parseDraftRef(draftID)
	if err != nil {
		return nil, err
	}
	key := ref.String()
	if !cl.sent.begin(key, cl.now()) {
		return nil, ErrAlreadySent
	}
	sent, locked := false, false
	defer func() {
		if !sent && !locked {
			cl.sent.abort(key)
		}
	}()

	var res *SendResult
	err = cl.withSession(ctx, func(s *session) error {
		roles, _, err := s.roles(cl.cfg.Folders)
		if err != nil {
			return err
		}
		drafts, err := roles.get(RoleDrafts)
		if err != nil {
			return err
		}
		if ref.Folder != drafts {
			return ErrDraftInvalid
		}
		raw, err := s.loadDraft(ref)
		if err != nil {
			return err
		}
		if !hmac.Equal(mac, draftMAC(cl.cfg.DraftKey, cl.cfg.Username, ref, raw)) {
			return ErrDraftInvalid
		}
		out, err := prepareOutgoing(raw, cl.cfg.FromAddress, cl.now())
		if err != nil {
			return err
		}
		if err := cl.policy.Admit(ctx, out.rcpts); err != nil {
			return fmt.Errorf("%w: %w", ErrPolicy, err)
		}
		if err := cl.sender.Send(ctx, cl.cfg.FromAddress, out.rcpts, out.transmit); err != nil {
			if errors.Is(err, ErrDeliveryUnknown) {
				// Possibly delivered: keep this draft locked in-process so
				// an automatic retry cannot send it twice.
				cl.sent.commit(key, cl.now())
				sent = false
				locked = true
			}
			return err
		}
		sent = true
		cl.sent.commit(key, cl.now())
		res = &out.result

		// The message is out. Nothing below may turn this into an error.
		if cl.cfg.SaveSent {
			if folder, err := roles.get(RoleSent); err != nil {
				res.Warnings = append(res.Warnings, "not saved to Sent: "+ErrorKind(err))
			} else if _, err := s.appendSent(folder, out.sentCopy, cl.now()); err != nil {
				res.Warnings = append(res.Warnings, "not saved to Sent: "+ErrorKind(err))
			} else {
				res.SavedToSent = true
			}
		}
		if trash, err := roles.get(RoleTrash); err != nil {
			res.Warnings = append(res.Warnings, "draft left in Drafts: no Trash folder")
		} else if !s.caps.Has(imap.CapMove) {
			res.Warnings = append(res.Warnings, "draft left in Drafts: server lacks MOVE")
		} else if _, err := s.c.Move(imap.UIDSetNum(ref.UID), trash).Wait(); err != nil {
			res.Warnings = append(res.Warnings, "draft left in Drafts: "+ErrorKind(err))
		} else {
			res.DraftMoved = true
		}
		return nil
	})
	if sent {
		// Post-send failures are already in Warnings; never report the
		// send itself as failed.
		return res, nil
	}
	if err != nil {
		return nil, err
	}
	return res, nil
}

// loadDraft fetches the stored draft bytes from the selected Drafts folder.
func (s *session) loadDraft(ref msgRef) ([]byte, error) {
	if err := s.openRef(ref, false); err != nil {
		if errors.Is(err, ErrStaleID) {
			return nil, ErrDraftInvalid
		}
		return nil, err
	}
	section := &imap.FetchItemBodySection{Peek: true, Partial: &imap.SectionPartial{Offset: 0, Size: maxDraftBytes + 1}}
	bufs, err := s.c.Fetch(imap.UIDSetNum(ref.UID), &imap.FetchOptions{
		UID:         true,
		Flags:       true,
		BodySection: []*imap.FetchItemBodySection{section},
	}).Collect()
	if err != nil {
		return nil, fmt.Errorf("%w: fetch draft: %w", ErrUpstream, err)
	}
	b := findUID(bufs, ref.UID)
	if b == nil {
		return nil, fmt.Errorf("%w: draft no longer exists (already sent or deleted?)", ErrNotFound)
	}
	isDraft := false
	for _, f := range b.Flags {
		switch {
		case strings.EqualFold(string(f), string(imap.FlagDeleted)):
			return nil, ErrDraftInvalid
		case strings.EqualFold(string(f), string(imap.FlagDraft)):
			isDraft = true
		}
	}
	raw := b.FindBodySection(section)
	if !isDraft || len(raw) == 0 || len(raw) > maxDraftBytes {
		return nil, ErrDraftInvalid
	}
	return raw, nil
}

func (s *session) appendSent(folder string, raw []byte, now time.Time) (*imap.AppendData, error) {
	cmd := s.c.Append(folder, int64(len(raw)), &imap.AppendOptions{Flags: []imap.Flag{imap.FlagSeen}, Time: now})
	if _, err := cmd.Write(raw); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUpstream, err)
	}
	if err := cmd.Close(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUpstream, err)
	}
	data, err := cmd.Wait()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUpstream, err)
	}
	return data, nil
}

// outgoing is a verified draft ready for submission.
type outgoing struct {
	rcpts    []string
	transmit []byte // Bcc removed, Date refreshed
	sentCopy []byte // Date refreshed, Bcc kept for the sender's records
	result   SendResult
}

// prepareOutgoing parses a verified draft. The From header must be the
// account address; recipients come from To, Cc and Bcc.
func prepareOutgoing(raw []byte, fromAddr string, now time.Time) (*outgoing, error) {
	br := bufio.NewReader(bytes.NewReader(raw))
	th, err := textproto.ReadHeader(br)
	if err != nil {
		return nil, ErrDraftInvalid
	}
	body, err := io.ReadAll(br)
	if err != nil {
		return nil, ErrDraftInvalid
	}
	h := gomail.Header{Header: message.Header{Header: th}}

	from, err := h.AddressList("From")
	if err != nil || len(from) != 1 || !strings.EqualFold(from[0].Address, fromAddr) {
		return nil, fmt.Errorf("%w: From is not the account address", ErrDraftInvalid)
	}
	out := &outgoing{}
	r := &out.result
	r.From = Address{Name: cleanHeader(from[0].Name, 200), Email: from[0].Address}
	seen := map[string]bool{}
	for _, f := range []struct {
		key string
		dst *[]Address
	}{{"To", &r.To}, {"Cc", &r.Cc}, {"Bcc", &r.Bcc}} {
		list, err := h.AddressList(f.key)
		if err != nil {
			return nil, fmt.Errorf("%w: malformed %s", ErrDraftInvalid, f.key)
		}
		for _, a := range list {
			if !isASCII(a.Address) || !strings.Contains(a.Address, "@") {
				return nil, fmt.Errorf("%w: unsupported address in %s", ErrDraftInvalid, f.key)
			}
			*f.dst = append(*f.dst, Address{Name: cleanHeader(a.Name, 200), Email: a.Address})
			if k := strings.ToLower(a.Address); !seen[k] {
				seen[k] = true
				out.rcpts = append(out.rcpts, a.Address)
			}
		}
	}
	if len(out.rcpts) == 0 || len(out.rcpts) > maxRecipients {
		return nil, fmt.Errorf("%w: needs 1 to %d recipients", ErrDraftInvalid, maxRecipients)
	}
	subject, _ := h.Subject()
	r.Subject = cleanHeader(subject, maxSubjectRunes)
	r.MessageID, _ = h.MessageID()

	h.SetDate(now)
	if out.sentCopy, err = renderMessage(h.Header.Header, body); err != nil {
		return nil, err
	}
	h.Del("Bcc")
	if out.transmit, err = renderMessage(h.Header.Header, body); err != nil {
		return nil, err
	}
	return out, nil
}

func renderMessage(h textproto.Header, body []byte) ([]byte, error) {
	var buf bytes.Buffer
	if err := textproto.WriteHeader(&buf, h); err != nil {
		return nil, err
	}
	buf.Write(body)
	return buf.Bytes(), nil
}

func toAddresses(in []*netmail.Address) []Address {
	out := make([]Address, len(in))
	for i, a := range in {
		out[i] = Address{Name: a.Name, Email: a.Address}
	}
	return out
}

// sentRegistry prevents the same draft from being sent twice by this
// process, including concurrently. Moving the draft to Trash after sending
// covers restarts.
type sentRegistry struct {
	mu sync.Mutex
	m  map[string]sentEntry
}

type sentEntry struct {
	done bool
	at   time.Time
}

const sentRetention = 7 * 24 * time.Hour

func newSentRegistry() *sentRegistry { return &sentRegistry{m: map[string]sentEntry{}} }

func (r *sentRegistry) begin(key string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, e := range r.m {
		if e.done && now.Sub(e.at) > sentRetention {
			delete(r.m, k)
		}
	}
	if _, ok := r.m[key]; ok {
		return false
	}
	r.m[key] = sentEntry{at: now}
	return true
}

func (r *sentRegistry) commit(key string, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[key] = sentEntry{done: true, at: now}
}

func (r *sentRegistry) abort(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.m[key]; ok && !e.done {
		delete(r.m, key)
	}
}
