package mail

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

const (
	maxQueryLen      = 256
	maxIDsPerCall    = 100
	maxListedFolders = 1000
	maxStatusFolders = 200
	maxHeaderRunes   = 500
	maxListedAddrs   = 50
)

// SendPolicy authorizes outgoing mail. Admit is called after the draft has
// been verified and before any SMTP connection is made; it must atomically
// check and record the attempt (e.g. against a daily cap) and be safe for
// concurrent use. ledger is the durable send record bound to the current
// IMAP session, or nil when none is configured.
type SendPolicy interface {
	Admit(ctx context.Context, recipients []string, ledger SendLedger) error
}

// Client implements Mailbox against one IMAP/SMTP account. It holds no
// connections: every method opens and closes its own.
type Client struct {
	cfg    Config
	policy SendPolicy
	sender Sender
	sent   *sentRegistry
	now    func() time.Time

	// onIMAPCommand observes every IMAP command name (tests).
	onIMAPCommand func(name string)
}

var _ Mailbox = (*Client)(nil)

// New validates cfg and returns a Client. policy is mandatory.
func New(cfg Config, policy SendPolicy) (*Client, error) {
	cfg.setDefaults()
	cfg.DraftKey = slices.Clone(cfg.DraftKey)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if policy == nil {
		return nil, errors.New("mail: send policy is required")
	}
	sender, err := newSMTPSender(&cfg)
	if err != nil {
		return nil, err
	}
	return &Client{cfg: cfg, policy: policy, sender: sender, sent: newSentRegistry(), now: time.Now}, nil
}

// ListFolders returns all folders with their roles, INBOX first.
func (cl *Client) ListFolders(ctx context.Context) ([]Folder, error) {
	var out []Folder
	err := cl.withSession(ctx, func(s *session) error {
		entries, err := s.list(true)
		if err != nil {
			return err
		}
		if len(entries) > maxListedFolders {
			entries = entries[:maxListedFolders]
		}
		roles := resolveRoles(entries, cl.cfg.Folders)
		if !s.caps.Has(imap.CapListStatus) {
			s.statusFallback(entries)
		}
		for _, e := range entries {
			f := Folder{Name: e.Name, Role: roles.roleOf(e.Name), Selectable: e.selectable()}
			if e.Status != nil {
				f.Messages = e.Status.NumMessages
				f.Unseen = e.Status.NumUnseen
			}
			out = append(out, f)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(out, func(a, b Folder) int {
		return cmp.Or(
			-cmp.Compare(boolInt(a.Role == RoleInbox), boolInt(b.Role == RoleInbox)),
			strings.Compare(a.Name, b.Name),
		)
	})
	return out, nil
}

// statusFallback fills counts with pipelined STATUS commands when the
// server lacks LIST-STATUS. Failures leave counts unknown.
func (s *session) statusFallback(entries []folderEntry) {
	type pending struct {
		i   int
		cmd *imapclient.StatusCommand
	}
	var cmds []pending
	for i, e := range entries {
		if !e.selectable() || len(cmds) >= maxStatusFolders {
			continue
		}
		cmds = append(cmds, pending{i, s.c.Status(e.Name, &imap.StatusOptions{NumMessages: true, NumUnseen: true})})
	}
	for _, p := range cmds {
		if data, err := p.cmd.Wait(); err == nil {
			entries[p.i].Status = data
		}
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Search runs UID SEARCH in one folder and returns the newest matches
// (highest UIDs) first. Messages flagged \Deleted by other clients are
// excluded.
func (cl *Client) Search(ctx context.Context, q SearchQuery) (*SearchResult, error) {
	criteria, folder, limit, err := buildCriteria(q)
	if err != nil {
		return nil, err
	}
	res := &SearchResult{Folder: folder}
	err = cl.withSession(ctx, func(s *session) error {
		if q.Role != RoleNone {
			roles, _, err := s.roles(cl.cfg.Folders)
			if err != nil {
				return err
			}
			if folder, err = roles.get(q.Role); err != nil {
				return err
			}
			res.Folder = folder
		}
		sel, err := s.examine(folder)
		if err != nil {
			return err
		}
		data, err := s.c.UIDSearch(criteria, nil).Wait()
		if err != nil {
			return fmt.Errorf("%w: search: %w", ErrUpstream, err)
		}
		uids := data.AllUIDs()
		slices.Sort(uids)
		slices.Reverse(uids)
		res.Total = len(uids)
		if len(uids) > limit {
			uids = uids[:limit]
		}
		res.Messages, err = s.fetchSummaries(folder, sel.UIDValidity, uids)
		return err
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

func buildCriteria(q SearchQuery) (*imap.SearchCriteria, string, int, error) {
	invalid := func(why string) (*imap.SearchCriteria, string, int, error) {
		return nil, "", 0, fmt.Errorf("%w: %s", ErrInvalidInput, why)
	}
	if q.Role != RoleNone && q.Folder != "" {
		return invalid("set folder or role, not both")
	}
	folder := q.Folder
	if folder == "" {
		folder = "INBOX"
	}
	if !validFolderName(folder) {
		return invalid("bad folder name")
	}
	limit := q.Limit
	switch {
	case limit == 0:
		limit = DefaultSearchLimit
	case limit < 0:
		return invalid("limit must be positive")
	case limit > MaxSearchLimit:
		limit = MaxSearchLimit
	}
	c := &imap.SearchCriteria{NotFlag: []imap.Flag{imap.FlagDeleted}}
	for _, f := range []struct{ key, val string }{{"From", q.From}, {"To", q.To}, {"Subject", q.Subject}, {"", q.Body}} {
		v := strings.TrimSpace(f.val)
		if v == "" {
			continue
		}
		if utf8.RuneCountInString(v) > maxQueryLen || !utf8.ValidString(v) || strings.ContainsAny(v, "\x00\r\n") {
			return invalid("search terms must be single-line text of at most 256 characters")
		}
		if f.key == "" {
			c.Body = append(c.Body, v)
		} else {
			c.Header = append(c.Header, imap.SearchCriteriaHeaderField{Key: f.key, Value: v})
		}
	}
	if !q.Since.IsZero() {
		c.Since = dateOnly(q.Since)
	}
	if !q.Before.IsZero() {
		c.Before = dateOnly(q.Before)
	}
	if !c.Since.IsZero() && !c.Before.IsZero() && !c.Before.After(c.Since) {
		return invalid("before must be after since")
	}
	if q.UnreadOnly {
		c.NotFlag = append(c.NotFlag, imap.FlagSeen)
	}
	return c, folder, limit, nil
}

func dateOnly(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

var summaryFetch = &imap.FetchOptions{
	UID:           true,
	Flags:         true,
	Envelope:      true,
	InternalDate:  true,
	RFC822Size:    true,
	BodyStructure: &imap.FetchItemBodyStructure{Extended: true},
}

// fetchSummaries fetches metadata for uids and returns it in uids order.
func (s *session) fetchSummaries(folder string, uidValidity uint32, uids []imap.UID) ([]Summary, error) {
	if len(uids) == 0 {
		return []Summary{}, nil
	}
	bufs, err := s.c.Fetch(imap.UIDSetNum(uids...), summaryFetch).Collect()
	if err != nil {
		return nil, fmt.Errorf("%w: fetch: %w", ErrUpstream, err)
	}
	byUID := make(map[imap.UID]*imapclient.FetchMessageBuffer, len(bufs))
	for _, b := range bufs {
		byUID[b.UID] = b
	}
	out := make([]Summary, 0, len(uids))
	for _, uid := range uids {
		if b, ok := byUID[uid]; ok {
			out = append(out, summaryOf(msgRef{folder, uidValidity, uid}, b))
		}
	}
	return out, nil
}

func summaryOf(ref msgRef, b *imapclient.FetchMessageBuffer) Summary {
	s := Summary{ID: ref.String(), Folder: ref.Folder, Date: b.InternalDate, Size: b.RFC822Size}
	if env := b.Envelope; env != nil {
		if !env.Date.IsZero() {
			s.Date = env.Date
		}
		s.Subject = cleanHeader(env.Subject, maxHeaderRunes)
		s.From = addrs(env.From)
		s.To = addrs(env.To)
		s.Cc = addrs(env.Cc)
	}
	for _, f := range b.Flags {
		switch {
		case strings.EqualFold(string(f), string(imap.FlagSeen)):
			s.Seen = true
		case strings.EqualFold(string(f), string(imap.FlagFlagged)):
			s.Flagged = true
		case strings.EqualFold(string(f), string(imap.FlagAnswered)):
			s.Answered = true
		case strings.EqualFold(string(f), string(imap.FlagDraft)):
			s.Draft = true
		}
	}
	if b.BodyStructure != nil {
		s.HasAttachments = len(planBody(b.BodyStructure).attachments) > 0
	}
	return s
}

func addrs(in []imap.Address) []Address {
	var out []Address
	for _, a := range in {
		if a.IsGroupStart() || a.IsGroupEnd() {
			continue
		}
		if len(out) == maxListedAddrs {
			break
		}
		out = append(out, Address{Name: cleanHeader(a.Name, 200), Email: cleanHeader(a.Addr(), 320)})
	}
	return out
}

// Read fetches one message. It uses EXAMINE and BODY.PEEK, so the message
// is never marked as seen.
func (cl *Client) Read(ctx context.Context, id string) (*Message, error) {
	ref, err := parseRef(id)
	if err != nil {
		return nil, err
	}
	var msg *Message
	err = cl.withSession(ctx, func(s *session) error {
		if err := s.openRef(ref, true); err != nil {
			return err
		}
		set := imap.UIDSetNum(ref.UID)
		bufs, err := s.c.Fetch(set, summaryFetch).Collect()
		if err != nil {
			return fmt.Errorf("%w: fetch: %w", ErrUpstream, err)
		}
		b := findUID(bufs, ref.UID)
		if b == nil {
			return ErrNotFound
		}
		msg = &Message{Summary: summaryOf(ref, b)}
		if env := b.Envelope; env != nil {
			msg.ReplyTo = addrs(env.ReplyTo)
			msg.MessageID = cleanHeader(env.MessageID, 250)
			for _, irt := range env.InReplyTo {
				msg.InReplyTo = append(msg.InReplyTo, cleanHeader(irt, 250))
			}
		}
		plan := planBody(b.BodyStructure)
		msg.Attachments = plan.attachments
		return s.readBody(set, ref.UID, plan, cl.cfg.MaxFetchBytes, cl.cfg.MaxBodyBytes, msg)
	})
	if err != nil {
		return nil, err
	}
	return msg, nil
}

func findUID(bufs []*imapclient.FetchMessageBuffer, uid imap.UID) *imapclient.FetchMessageBuffer {
	for _, b := range bufs {
		if b.UID == uid {
			return b
		}
	}
	return nil
}

// readBody fetches the planned text parts with BODY.PEEK (partial, capped)
// and fills msg.Body.
func (s *session) readBody(set imap.UIDSet, uid imap.UID, plan bodyPlan, maxFetch int64, maxBody int, msg *Message) error {
	if len(plan.texts) == 0 {
		return nil
	}
	msg.BodyTruncated = plan.droppedTexts > 0
	// Split the fetch budget across parts so total memory stays bounded.
	perPart := max(maxFetch/int64(len(plan.texts)), min(minPartFetch, maxFetch))
	opts := &imap.FetchOptions{UID: true}
	sections := make([]*imap.FetchItemBodySection, len(plan.texts))
	for i, tp := range plan.texts {
		sections[i] = &imap.FetchItemBodySection{
			Part:    tp.path,
			Peek:    true,
			Partial: &imap.SectionPartial{Offset: 0, Size: perPart},
		}
		opts.BodySection = append(opts.BodySection, sections[i])
	}
	bufs, err := s.c.Fetch(set, opts).Collect()
	if err != nil {
		return fmt.Errorf("%w: fetch body: %w", ErrUpstream, err)
	}
	b := findUID(bufs, uid)
	if b == nil {
		return ErrNotFound
	}
	var texts []string
	anyHTML := false
	for i, tp := range plan.texts {
		raw := b.FindBodySection(sections[i])
		if int64(tp.size) > perPart {
			msg.BodyTruncated = true
		}
		text := decodeTextPart(tp, raw)
		if tp.html {
			anyHTML = true
			t, hidden, truncated := htmlToText(text, maxBody)
			text = t
			msg.HiddenRemoved += hidden
			msg.BodyTruncated = msg.BodyTruncated || truncated
		} else {
			text = tidyLines(cleanText(text))
		}
		if text != "" {
			texts = append(texts, text)
		}
	}
	body, cut := truncateBytes(strings.Join(texts, bodyPartSeparator), maxBody)
	msg.Body = body
	msg.BodyTruncated = msg.BodyTruncated || cut
	msg.BodyFormat = "text/plain"
	if anyHTML {
		msg.BodyFormat = "text/html"
	}
	return nil
}

// Move moves messages to dest with UID MOVE. Servers without MOVE are
// refused: the COPY+STORE \Deleted+EXPUNGE fallback would permanently
// delete. Messages already in dest are left untouched.
func (cl *Client) Move(ctx context.Context, ids []string, dest Destination) (*MoveResult, error) {
	groups, order, err := groupRefs(ids)
	if err != nil {
		return nil, err
	}
	if (dest.Role == RoleNone) == (dest.Folder == "") {
		return nil, fmt.Errorf("%w: exactly one of destination role or folder is required", ErrInvalidInput)
	}
	if dest.Folder != "" && !validFolderName(dest.Folder) {
		return nil, fmt.Errorf("%w: bad folder name", ErrInvalidInput)
	}
	if cl.isProtected(dest.Folder) {
		return nil, ErrProtected
	}
	for _, folder := range order {
		if cl.isProtected(folder) {
			return nil, ErrProtected
		}
	}
	res := &MoveResult{}
	err = cl.withSession(ctx, func(s *session) error {
		roles, entries, err := s.roles(cl.cfg.Folders)
		if err != nil {
			return err
		}
		target, err := resolveDest(dest, roles, entries)
		if err != nil {
			return err
		}
		res.Folder = target
		if cl.isProtected(target) {
			return ErrProtected
		}
		if !s.caps.Has(imap.CapMove) {
			return fmt.Errorf("%w: server lacks MOVE; refusing the COPY+EXPUNGE fallback", ErrUnsupported)
		}
		if err := s.validateGroups(groups, order); err != nil {
			return err
		}
		newIDs := map[string]string{}
		for _, folder := range order {
			refs := groups[folder]
			if folder == target {
				for _, r := range refs {
					newIDs[r.String()] = r.String()
				}
				continue
			}
			if err := s.openRef(refs[0], false); err != nil {
				return err
			}
			data, err := s.c.Move(refSet(refs), target).Wait()
			if err != nil {
				return fmt.Errorf("%w: move: %w", ErrUpstream, err)
			}
			for src, dst := range moveMapping(data) {
				newIDs[msgRef{folder, refs[0].UIDValidity, src}.String()] = msgRef{target, data.UIDValidity, dst}.String()
			}
		}
		for _, id := range ids {
			ref, _ := parseRef(id)
			res.Moved = append(res.Moved, Moved{ID: id, NewID: newIDs[ref.String()]})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

func resolveDest(dest Destination, roles roleMap, entries []folderEntry) (string, error) {
	if dest.Role != RoleNone {
		return roles.get(dest.Role)
	}
	for _, e := range entries {
		if e.Name == dest.Folder {
			if !e.selectable() {
				return "", fmt.Errorf("%w: %q is not selectable", ErrFolderNotFound, dest.Folder)
			}
			return e.Name, nil
		}
	}
	return "", fmt.Errorf("%w: %q", ErrFolderNotFound, dest.Folder)
}

// moveMapping pairs source and destination UIDs from COPYUID data.
func moveMapping(d *imapclient.MoveData) map[imap.UID]imap.UID {
	out := map[imap.UID]imap.UID{}
	if d == nil || d.UIDValidity == 0 {
		return out
	}
	srcSet, ok1 := d.SourceUIDs.(imap.UIDSet)
	dstSet, ok2 := d.DestUIDs.(imap.UIDSet)
	if !ok1 || !ok2 {
		return out
	}
	src, ok1 := srcSet.Nums()
	dst, ok2 := dstSet.Nums()
	if !ok1 || !ok2 || len(src) != len(dst) {
		return out
	}
	for i := range src {
		out[src[i]] = dst[i]
	}
	return out
}

// MarkRead sets (read=true) or clears the \Seen flag.
func (cl *Client) MarkRead(ctx context.Context, ids []string, read bool) (*FlagResult, error) {
	groups, order, err := groupRefs(ids)
	if err != nil {
		return nil, err
	}
	op := imap.StoreFlagsDel
	if read {
		op = imap.StoreFlagsAdd
	}
	res := &FlagResult{}
	err = cl.withSession(ctx, func(s *session) error {
		if err := s.validateGroups(groups, order); err != nil {
			return err
		}
		for _, folder := range order {
			refs := groups[folder]
			if err := s.openRef(refs[0], false); err != nil {
				return err
			}
			store := &imap.StoreFlags{Op: op, Silent: true, Flags: []imap.Flag{imap.FlagSeen}}
			if err := s.c.Store(refSet(refs), store, nil).Close(); err != nil {
				return fmt.Errorf("%w: store: %w", ErrUpstream, err)
			}
			res.Updated += len(refs)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// groupRefs parses ids and groups them by folder, keeping first-seen order
// and dropping duplicates.
func groupRefs(ids []string) (map[string][]msgRef, []string, error) {
	if len(ids) == 0 || len(ids) > maxIDsPerCall {
		return nil, nil, fmt.Errorf("%w: between 1 and %d ids are required", ErrInvalidInput, maxIDsPerCall)
	}
	groups := map[string][]msgRef{}
	var order []string
	seen := map[msgRef]bool{}
	for _, id := range ids {
		ref, err := parseRef(id)
		if err != nil {
			return nil, nil, err
		}
		if seen[ref] {
			continue
		}
		seen[ref] = true
		if _, ok := groups[ref.Folder]; !ok {
			order = append(order, ref.Folder)
		}
		groups[ref.Folder] = append(groups[ref.Folder], ref)
	}
	return groups, order, nil
}

// validateGroups checks, before anything changes, that every folder's
// UIDVALIDITY matches and that every message exists.
func (s *session) validateGroups(groups map[string][]msgRef, order []string) error {
	for _, folder := range order {
		refs := groups[folder]
		sel, err := s.examine(folder)
		if err != nil {
			return err
		}
		for _, r := range refs {
			if r.UIDValidity != sel.UIDValidity {
				return ErrStaleID
			}
		}
		bufs, err := s.c.Fetch(refSet(refs), &imap.FetchOptions{UID: true}).Collect()
		if err != nil {
			return fmt.Errorf("%w: fetch: %w", ErrUpstream, err)
		}
		found := map[imap.UID]bool{}
		for _, b := range bufs {
			found[b.UID] = true
		}
		missing := 0
		for _, r := range refs {
			if !found[r.UID] {
				missing++
			}
		}
		if missing > 0 {
			return fmt.Errorf("%w: %d of %d messages in %q", ErrNotFound, missing, len(refs), folder)
		}
	}
	return nil
}

func refSet(refs []msgRef) imap.UIDSet {
	uids := make([]imap.UID, len(refs))
	for i, r := range refs {
		uids[i] = r.UID
	}
	return imap.UIDSetNum(uids...)
}
