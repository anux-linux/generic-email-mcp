package mail

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/emersion/go-imap/v2"
)

// folderEntry is one LIST response, decoupled from the IMAP library.
type folderEntry struct {
	Name   string
	Delim  rune
	Attrs  []imap.MailboxAttr
	Status *imap.StatusData
}

func (e folderEntry) has(attr imap.MailboxAttr) bool {
	for _, a := range e.Attrs {
		if strings.EqualFold(string(a), string(attr)) {
			return true
		}
	}
	return false
}

func (e folderEntry) selectable() bool {
	return !e.has(imap.MailboxAttrNoSelect) && !e.has(imap.MailboxAttrNonExistent)
}

// leaf returns the last hierarchy component of the folder name.
func (e folderEntry) leaf() string {
	if e.Delim == 0 {
		return e.Name
	}
	if i := strings.LastIndex(e.Name, string(e.Delim)); i >= 0 {
		return e.Name[i+1:]
	}
	return e.Name
}

// depth is the hierarchy depth, with children of INBOX counted as top level
// (Courier-style "INBOX.Sent" layouts).
func (e folderEntry) depth() int {
	if e.Delim == 0 {
		return 0
	}
	d := strings.Count(e.Name, string(e.Delim))
	if strings.HasPrefix(strings.ToUpper(e.Name), "INBOX"+string(e.Delim)) {
		d--
	}
	return d
}

// discoverable roles in resolution order, with their SPECIAL-USE attribute.
var roleAttrs = []struct {
	role Role
	attr imap.MailboxAttr
}{
	{RoleDrafts, imap.MailboxAttrDrafts},
	{RoleSent, imap.MailboxAttrSent},
	{RoleTrash, imap.MailboxAttrTrash},
	{RoleArchive, imap.MailboxAttrArchive},
	{RoleJunk, imap.MailboxAttrJunk},
}

// wellKnownNames are fallbacks for servers without SPECIAL-USE, in priority
// order, compared case-insensitively against the folder's leaf name.
var wellKnownNames = map[Role][]string{
	RoleDrafts:  {"Drafts", "Draft", "Entwürfe", "Entwurf"},
	RoleSent:    {"Sent", "Sent Items", "Sent Messages", "Sent Mail", "Gesendet", "Gesendete Elemente", "Gesendete Objekte", "Gesendete Nachrichten"},
	RoleTrash:   {"Trash", "Deleted Items", "Deleted Messages", "Deleted", "Papierkorb", "Gelöschte Elemente", "Gelöschte Objekte", "Bin"},
	RoleArchive: {"Archive", "Archives", "Archiv"},
	RoleJunk:    {"Junk", "Spam", "Junk E-Mail", "Junk-E-Mail", "Bulk Mail"},
}

// roleMap is the outcome of folder discovery.
type roleMap struct {
	folders  map[Role]string
	problems map[Role]error
}

// get returns the folder for r or an error explaining why there is none.
func (m roleMap) get(r Role) (string, error) {
	if f, ok := m.folders[r]; ok {
		return f, nil
	}
	if err, ok := m.problems[r]; ok {
		return "", err
	}
	return "", fmt.Errorf("%w: no %s folder found; set it explicitly via MAIL_FOLDER_%s", ErrFolderNotFound, r, strings.ToUpper(string(r)))
}

// roleOf returns the role of folder name, if any.
func (m roleMap) roleOf(name string) Role {
	for r, f := range m.folders {
		if f == name {
			return r
		}
	}
	return RoleNone
}

// resolveRoles assigns folders to roles. Precedence per role: explicit
// override (must exist), then SPECIAL-USE attribute, then well-known name.
// Each folder gets at most one role. Ties are broken deterministically.
func resolveRoles(entries []folderEntry, ov FolderOverrides) roleMap {
	m := roleMap{folders: map[Role]string{RoleInbox: "INBOX"}, problems: map[Role]error{}}
	byName := make(map[string]folderEntry, len(entries))
	for _, e := range entries {
		byName[e.Name] = e
		if strings.EqualFold(e.Name, "INBOX") {
			m.folders[RoleInbox] = e.Name
		}
	}
	taken := map[string]bool{m.folders[RoleInbox]: true}

	assign := func(r Role, name string) {
		m.folders[r] = name
		taken[name] = true
	}

	// Overrides first so discovery never steals an explicitly pinned folder.
	for _, ra := range roleAttrs {
		name := ov.get(ra.role)
		if name == "" {
			continue
		}
		e, ok := byName[name]
		switch {
		case !ok:
			m.problems[ra.role] = fmt.Errorf("%w: MAIL_FOLDER_%s=%q does not exist on the server", ErrFolderNotFound, strings.ToUpper(string(ra.role)), name)
		case !e.selectable():
			m.problems[ra.role] = fmt.Errorf("%w: MAIL_FOLDER_%s=%q is not selectable", ErrFolderNotFound, strings.ToUpper(string(ra.role)), name)
		default:
			assign(ra.role, name)
		}
	}

	for _, ra := range roleAttrs {
		if _, done := m.folders[ra.role]; done || m.problems[ra.role] != nil {
			continue
		}
		var cands []folderEntry
		for _, e := range entries {
			if e.selectable() && !taken[e.Name] && e.has(ra.attr) {
				cands = append(cands, e)
			}
		}
		if best, ok := pickFolder(cands, nil); ok {
			assign(ra.role, best.Name)
		}
	}

	for _, ra := range roleAttrs {
		if _, done := m.folders[ra.role]; done || m.problems[ra.role] != nil {
			continue
		}
		names := wellKnownNames[ra.role]
		var cands []folderEntry
		for _, e := range entries {
			if e.selectable() && !taken[e.Name] && nameRank(names, e.leaf()) >= 0 {
				cands = append(cands, e)
			}
		}
		if best, ok := pickFolder(cands, names); ok {
			assign(ra.role, best.Name)
		}
	}
	return m
}

func nameRank(names []string, leaf string) int {
	for i, n := range names {
		if strings.EqualFold(n, leaf) {
			return i
		}
	}
	return -1
}

// pickFolder prefers shallow folders, then (for name matches) the
// higher-priority name, then the shorter and lexicographically smaller name.
func pickFolder(cands []folderEntry, names []string) (folderEntry, bool) {
	if len(cands) == 0 {
		return folderEntry{}, false
	}
	return slices.MinFunc(cands, func(a, b folderEntry) int {
		return cmp.Or(
			cmp.Compare(a.depth(), b.depth()),
			cmp.Compare(nameRank(names, a.leaf()), nameRank(names, b.leaf())),
			cmp.Compare(len(a.Name), len(b.Name)),
			strings.Compare(a.Name, b.Name),
		)
	}), true
}
