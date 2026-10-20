// Package mail is the mail core: stateless IMAP access to a single mailbox
// and SMTP submission. It has no HTTP or MCP concerns.
//
// Safety properties enforced here (see docs/DECISIONS.md):
//   - one IMAP connection per call, implicit TLS with verification always on;
//   - reads use EXAMINE and BODY.PEEK, so reading never sets \Seen;
//   - no EXPUNGE, CLOSE, DELETE or STORE \Deleted is ever sent (guardConn);
//   - "delete" is a MOVE to Trash; MOVE without server support is refused;
//   - only drafts created by CreateDraft, unmodified, can be sent.
package mail

import (
	"context"
	"time"
)

// Mailbox is the mail-core API consumed by the MCP tool layer. *Client is the
// production implementation; tests of upper layers can use fakes.
type Mailbox interface {
	ListFolders(ctx context.Context) ([]Folder, error)
	Search(ctx context.Context, q SearchQuery) (*SearchResult, error)
	Read(ctx context.Context, id string) (*Message, error)
	CreateDraft(ctx context.Context, in DraftInput) (*Draft, error)
	SendDraft(ctx context.Context, draftID string) (*SendResult, error)
	Move(ctx context.Context, ids []string, dest Destination) (*MoveResult, error)
	MarkRead(ctx context.Context, ids []string, read bool) (*FlagResult, error)
}

// Role is the special use of a folder.
type Role string

// Folder roles. RoleNone marks an ordinary folder.
const (
	RoleNone    Role = ""
	RoleInbox   Role = "inbox"
	RoleDrafts  Role = "drafts"
	RoleSent    Role = "sent"
	RoleTrash   Role = "trash"
	RoleArchive Role = "archive"
	RoleJunk    Role = "junk"
)

// ParseRole maps a role keyword (case-insensitive) to a Role.
func ParseRole(s string) (Role, bool) {
	switch Role(lowerASCII(s)) {
	case RoleInbox:
		return RoleInbox, true
	case RoleDrafts:
		return RoleDrafts, true
	case RoleSent:
		return RoleSent, true
	case RoleTrash:
		return RoleTrash, true
	case RoleArchive:
		return RoleArchive, true
	case RoleJunk:
		return RoleJunk, true
	}
	return RoleNone, false
}

// Folder describes one IMAP mailbox.
type Folder struct {
	Name       string
	Role       Role
	Selectable bool
	// Messages and Unseen are nil when the server did not report them.
	Messages *uint32
	Unseen   *uint32
}

// Address is a decoded mailbox address.
type Address struct {
	Name  string
	Email string
}

// SearchQuery selects messages in one folder. All set criteria must match.
type SearchQuery struct {
	Folder  string // exact folder name; empty means INBOX unless Role is set
	Role    Role   // alternatively, the folder with this role
	From    string
	To      string
	Subject string
	Body    string
	// Since and Before compare against the server's received date
	// (INTERNALDATE) with day granularity: Since is inclusive, Before is
	// exclusive. Zero means unset.
	Since      time.Time
	Before     time.Time
	UnreadOnly bool
	Limit      int // 0 means DefaultSearchLimit; capped at MaxSearchLimit
}

// Search limits.
const (
	DefaultSearchLimit = 20
	MaxSearchLimit     = 100
)

// SearchResult holds the newest matching messages first.
type SearchResult struct {
	Folder   string
	Total    int // number of matches, may exceed len(Messages)
	Messages []Summary
}

// Summary is the metadata of one message.
type Summary struct {
	ID             string
	Folder         string
	Date           time.Time
	From           []Address
	To             []Address
	Cc             []Address
	Subject        string
	Seen           bool
	Flagged        bool
	Answered       bool
	Draft          bool
	HasAttachments bool
	Size           int64
}

// Message is a fully read message. Body is plain text: HTML is converted and
// hidden content removed. Attachments carry metadata only.
type Message struct {
	Summary
	ReplyTo   []Address
	MessageID string
	InReplyTo []string
	Body      string
	// BodyFormat is the source format of Body: "text/plain", "text/html"
	// (converted to text) or "" when the message has no text part.
	BodyFormat    string
	BodyTruncated bool
	// HiddenRemoved counts HTML elements dropped as hidden or invisible.
	HiddenRemoved int
	Attachments   []Attachment
}

// Attachment is metadata about a non-body MIME part. Content is never
// returned.
type Attachment struct {
	Part        string // IMAP part number, e.g. "2" or "1.3"
	Filename    string
	ContentType string
	Size        int64 // approximate decoded size in bytes
	Inline      bool
}

// DraftInput is a new plain-text draft. Addresses use RFC 5322 syntax
// ("Name <user@example.org>" or "user@example.org").
type DraftInput struct {
	To      []string
	Cc      []string
	Bcc     []string
	Subject string
	Body    string
	// InReplyTo is an optional message ID (from Search/Read) of the message
	// being answered. It sets In-Reply-To/References and, when empty,
	// defaults Subject to "Re: <original>" and To to the original Reply-To
	// or From.
	InReplyTo string
}

// Draft is the result of CreateDraft. ID is the only value SendDraft accepts.
type Draft struct {
	ID        string
	Folder    string
	MessageID string
	From      Address
	To        []Address
	Cc        []Address
	Bcc       []Address
	Subject   string
	InReplyTo string // Message-ID of the answered message, if any
	Body      string
}

// SendResult reports exactly what was submitted over SMTP.
type SendResult struct {
	MessageID   string
	From        Address
	To          []Address
	Cc          []Address
	Bcc         []Address
	Subject     string
	SavedToSent bool
	// DraftMoved is true when the sent draft was moved to Trash.
	DraftMoved bool
	// Warnings lists post-send problems. The message WAS sent; callers must
	// not retry.
	Warnings []string
}

// Destination of a move: either a Role or an exact folder name.
type Destination struct {
	Role   Role
	Folder string
}

// MoveResult maps each moved message to its new ID. NewID is empty when the
// server did not report the destination UID (no UIDPLUS).
type MoveResult struct {
	Folder string
	Moved  []Moved
}

// Moved is one moved message.
type Moved struct {
	ID    string
	NewID string
}

// FlagResult reports how many messages were updated.
type FlagResult struct {
	Updated int
}
