package mail

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestMsgRefRoundTrip(t *testing.T) {
	for _, folder := range []string{"INBOX", "Gesendete Objekte", "Entwürfe", "a.b/c", strings.Repeat("x", maxFolderLen)} {
		ref := msgRef{Folder: folder, UIDValidity: 1700000000, UID: 42}
		got, err := parseRef(ref.String())
		if err != nil {
			t.Fatalf("%q: %v", folder, err)
		}
		if got != ref {
			t.Fatalf("got %+v, want %+v", got, ref)
		}
	}
}

func TestParseIDRejectsMalformed(t *testing.T) {
	valid := msgRef{Folder: "INBOX", UIDValidity: 7, UID: 9}.String()
	cases := map[string]string{
		"empty":           "",
		"unknown prefix":  "x1" + strings.TrimPrefix(valid, "m1"),
		"missing part":    "m1.SU5CT1g.7",
		"extra part":      valid + ".1",
		"bad base64":      "m1.!!!.7.9",
		"empty folder":    "m1..7.9",
		"zero uid":        "m1.SU5CT1g.7.0",
		"zero validity":   "m1.SU5CT1g.0.9",
		"leading zero":    "m1.SU5CT1g.07.9",
		"signed":          "m1.SU5CT1g.+7.9",
		"negative":        "m1.SU5CT1g.7.-9",
		"overflow":        "m1.SU5CT1g.7.4294967296",
		"crlf in folder":  "m1." + b64.EncodeToString([]byte("IN\r\nBOX")) + ".7.9",
		"nul in folder":   "m1." + b64.EncodeToString([]byte("IN\x00BOX")) + ".7.9",
		"invalid utf8":    "m1." + b64.EncodeToString([]byte{0xff, 0xfe}) + ".7.9",
		"too long":        "m1." + strings.Repeat("A", maxIDLen) + ".7.9",
		"draft short mac": "d1.SU5CT1g.7.9.AAAA",
		"draft no mac":    "d1.SU5CT1g.7.9",
	}
	for name, id := range cases {
		if _, err := parseRef(id); !errors.Is(err, ErrInvalidID) {
			t.Errorf("%s: err = %v, want ErrInvalidID", name, err)
		}
	}
}

func TestParseDraftRefRequiresDraftID(t *testing.T) {
	ref := msgRef{Folder: "Drafts", UIDValidity: 3, UID: 5}
	if _, _, err := parseDraftRef(ref.String()); !errors.Is(err, ErrDraftInvalid) {
		t.Fatalf("plain message id accepted as draft id: %v", err)
	}
	mac := draftMAC(bytes.Repeat([]byte{1}, 32), "user@example.org", ref, []byte("x"))
	got, gotMAC, err := parseDraftRef(formatDraftID(ref, mac))
	if err != nil || got != ref || !bytes.Equal(gotMAC, mac) {
		t.Fatalf("round trip failed: %v %+v", err, got)
	}
	// A draft ID still works as a message reference (read, move).
	if r, err := parseRef(formatDraftID(ref, mac)); err != nil || r != ref {
		t.Fatalf("draft id as message ref: %v", err)
	}
}

func TestDraftMACBindsEverything(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	ref := msgRef{Folder: "Drafts", UIDValidity: 3, UID: 5}
	content := []byte("Subject: hi\r\n\r\nbody\r\n")
	base := draftMAC(key, "user@example.org", ref, content)

	variants := map[string][]byte{
		"key":         draftMAC(bytes.Repeat([]byte{8}, 32), "user@example.org", ref, content),
		"account":     draftMAC(key, "other@example.org", ref, content),
		"folder":      draftMAC(key, "user@example.org", msgRef{"INBOX", 3, 5}, content),
		"uidvalidity": draftMAC(key, "user@example.org", msgRef{"Drafts", 4, 5}, content),
		"uid":         draftMAC(key, "user@example.org", msgRef{"Drafts", 3, 6}, content),
		"content":     draftMAC(key, "user@example.org", ref, []byte("Subject: hi\r\n\r\nbodY\r\n")),
	}
	for name, mac := range variants {
		if bytes.Equal(mac, base) {
			t.Errorf("MAC does not depend on %s", name)
		}
	}
	// Line-ending normalization only.
	if !bytes.Equal(base, draftMAC(key, "user@example.org", ref, []byte("Subject: hi\n\nbody\n"))) {
		t.Error("MAC should be stable across CRLF/LF storage")
	}
}
