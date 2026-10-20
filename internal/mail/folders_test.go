package mail

import (
	"errors"
	"testing"

	"github.com/emersion/go-imap/v2"
)

func entry(name string, attrs ...imap.MailboxAttr) folderEntry {
	return folderEntry{Name: name, Delim: '/', Attrs: attrs}
}

func mustRole(t *testing.T, m roleMap, r Role, want string) {
	t.Helper()
	got, err := m.get(r)
	if err != nil {
		t.Fatalf("role %s: %v", r, err)
	}
	if got != want {
		t.Fatalf("role %s = %q, want %q", r, got, want)
	}
}

func TestResolveRolesSpecialUse(t *testing.T) {
	m := resolveRoles([]folderEntry{
		entry("INBOX"),
		entry("Sent"), // name match must lose against the attribute
		entry("Gesendet", imap.MailboxAttrSent),
		entry("Entwürfe", imap.MailboxAttrDrafts),
		entry("Papierkorb", imap.MailboxAttrTrash),
		entry("Archiv", imap.MailboxAttrArchive),
		entry("Spam", imap.MailboxAttrJunk),
	}, FolderOverrides{})
	mustRole(t, m, RoleInbox, "INBOX")
	mustRole(t, m, RoleSent, "Gesendet")
	mustRole(t, m, RoleDrafts, "Entwürfe")
	mustRole(t, m, RoleTrash, "Papierkorb")
	mustRole(t, m, RoleArchive, "Archiv")
	mustRole(t, m, RoleJunk, "Spam")
	if r := m.roleOf("Sent"); r != RoleNone {
		t.Fatalf("Sent got role %q", r)
	}
}

func TestResolveRolesCaseInsensitiveAttrs(t *testing.T) {
	m := resolveRoles([]folderEntry{entry("Out", "\\sent")}, FolderOverrides{})
	mustRole(t, m, RoleSent, "Out")
}

func TestResolveRolesWellKnownNames(t *testing.T) {
	m := resolveRoles([]folderEntry{
		entry("INBOX"), entry("Gesendete Objekte"), entry("Entwürfe"),
		entry("Gelöschte Elemente"), entry("Archive"), entry("Junk"),
	}, FolderOverrides{})
	mustRole(t, m, RoleSent, "Gesendete Objekte")
	mustRole(t, m, RoleDrafts, "Entwürfe")
	mustRole(t, m, RoleTrash, "Gelöschte Elemente")
	mustRole(t, m, RoleArchive, "Archive")
	mustRole(t, m, RoleJunk, "Junk")
}

func TestResolveRolesCourierLayout(t *testing.T) {
	dot := func(name string) folderEntry { return folderEntry{Name: name, Delim: '.'} }
	m := resolveRoles([]folderEntry{
		dot("INBOX"), dot("INBOX.Sent"), dot("INBOX.Drafts"), dot("INBOX.Trash"),
		dot("INBOX.Projects.Sent"), // deeper: must not win
	}, FolderOverrides{})
	mustRole(t, m, RoleSent, "INBOX.Sent")
	mustRole(t, m, RoleDrafts, "INBOX.Drafts")
	mustRole(t, m, RoleTrash, "INBOX.Trash")
}

func TestResolveRolesNameRankAndTies(t *testing.T) {
	m := resolveRoles([]folderEntry{entry("Sent Items"), entry("Sent"), entry("Gesendet")}, FolderOverrides{})
	mustRole(t, m, RoleSent, "Sent") // highest-priority name
	m = resolveRoles([]folderEntry{entry("B", imap.MailboxAttrTrash), entry("A", imap.MailboxAttrTrash)}, FolderOverrides{})
	mustRole(t, m, RoleTrash, "A") // deterministic tie-break
}

func TestResolveRolesSkipsNoSelect(t *testing.T) {
	m := resolveRoles([]folderEntry{
		entry("Trash", imap.MailboxAttrTrash, imap.MailboxAttrNoSelect),
		entry("Deleted Items"),
	}, FolderOverrides{})
	mustRole(t, m, RoleTrash, "Deleted Items")
}

func TestResolveRolesOverrides(t *testing.T) {
	entries := []folderEntry{
		entry("INBOX"),
		entry("Mine", imap.MailboxAttrDrafts), // pinned to Sent below
		entry("Drafts"),
		entry("Trash", imap.MailboxAttrTrash),
		entry("Parent", imap.MailboxAttrNoSelect),
	}
	m := resolveRoles(entries, FolderOverrides{Sent: "Mine", Trash: "Nope", Archive: "Parent"})
	mustRole(t, m, RoleSent, "Mine")
	// The override took "Mine", so Drafts falls back to the name match.
	mustRole(t, m, RoleDrafts, "Drafts")
	// A missing override is an error, not a silent fallback.
	if _, err := m.get(RoleTrash); !errors.Is(err, ErrFolderNotFound) {
		t.Fatalf("missing override: %v", err)
	}
	if _, err := m.get(RoleArchive); !errors.Is(err, ErrFolderNotFound) {
		t.Fatalf("noselect override: %v", err)
	}
}

func TestResolveRolesMissing(t *testing.T) {
	m := resolveRoles([]folderEntry{entry("INBOX")}, FolderOverrides{})
	mustRole(t, m, RoleInbox, "INBOX")
	for _, r := range []Role{RoleSent, RoleDrafts, RoleTrash, RoleArchive} {
		if _, err := m.get(r); !errors.Is(err, ErrFolderNotFound) {
			t.Errorf("%s: %v", r, err)
		}
	}
}

func TestResolveRolesOneRolePerFolder(t *testing.T) {
	m := resolveRoles([]folderEntry{entry("X", imap.MailboxAttrSent, imap.MailboxAttrDrafts)}, FolderOverrides{})
	mustRole(t, m, RoleDrafts, "X") // Drafts resolves first
	if _, err := m.get(RoleSent); err == nil {
		t.Fatal("one folder must not hold two roles")
	}
}
