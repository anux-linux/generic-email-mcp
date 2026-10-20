package mail

import (
	"errors"
	"testing"
	"time"
)

func stateEnv(t *testing.T) (*testEnv, *RecordStore) {
	t.Helper()
	env := newEnv(t, nil, true)
	env.client = env.newClient(func(c *Config) { c.StateFolder = DefaultStateFolder; c.LedgerFolder = DefaultLedgerFolder })
	return env, env.client.Records()
}

func TestRecordStoreUpdateAndFind(t *testing.T) {
	env, rs := stateEnv(t)
	c := ctx(t)
	// Empty store: decide sees nothing; the first append creates the folder.
	for i, fam := range []string{"famA", "famAB", "famA"} {
		err := rs.Update(c, "fam", fam, 2, func(recs []Record) (Record, error) {
			if fam == "famA" && i == 2 && (len(recs) != 1 || recs[0]["seq"] != "0") {
				t.Fatalf("famA history = %v", recs)
			}
			return Record{"fam": fam, "seq": string(rune('0' + i)), "kind": "issued"}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// "famA" is a substring of "famAB"; only exact matches count.
	var seen []Record
	if err := rs.Update(c, "fam", "famA", 5, func(recs []Record) (Record, error) { seen = recs; return nil, nil }); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || seen[0]["seq"] != "0" || seen[1]["seq"] != "2" {
		t.Fatalf("famA = %v", seen)
	}
	// newest limits to the most recent records, oldest first.
	_ = rs.Update(c, "fam", "famA", 1, func(recs []Record) (Record, error) { seen = recs; return nil, nil })
	if len(seen) != 1 || seen[0]["seq"] != "2" {
		t.Fatalf("newest = %v", seen)
	}
	found, err := rs.Find(c, "kind", "issued", time.Now().Add(-time.Hour))
	if err != nil || len(found) != 3 {
		t.Fatalf("find = %v %v", found, err)
	}
	// decide's error is returned after its record was appended.
	sentinel := errors.New("decided")
	if err := rs.Update(c, "fam", "famX", 1, func([]Record) (Record, error) { return Record{"fam": "famX"}, sentinel }); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	if n := len(env.imap.Messages(t, DefaultStateFolder)); n != 4 {
		t.Fatalf("stored %d records", n)
	}
}

func TestRecordStoreValidation(t *testing.T) {
	_, rs := stateEnv(t)
	c := ctx(t)
	for _, bad := range []Record{{"fam": "has space"}, {"Bad_Key": "x"}, {"fam": "line\r\nbreak"}} {
		if err := rs.Update(c, "fam", "ok", 1, func([]Record) (Record, error) { return bad, nil }); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%v: %v", bad, err)
		}
	}
	if _, err := rs.Find(c, "fam", "", time.Time{}); !errors.Is(err, ErrInvalidInput) {
		t.Error("empty value accepted")
	}
}

func TestStateFolderProtectedAndNotARole(t *testing.T) {
	env, rs := stateEnv(t)
	if err := rs.Update(ctx(t), "fam", "f1", 1, func([]Record) (Record, error) { return Record{"fam": "f1"}, nil }); err != nil {
		t.Fatal(err)
	}
	uid := env.imap.Messages(t, DefaultStateFolder)[0].UID
	id := msgRef{DefaultStateFolder, env.imap.UIDValidity(t, DefaultStateFolder), uid}.String()
	if _, err := env.client.Move(ctx(t), []string{id}, Destination{Role: RoleTrash}); !errors.Is(err, ErrProtected) {
		t.Fatalf("move out: %v", err)
	}
	inbox := msgRef{"INBOX", env.imap.UIDValidity(t, "INBOX"), env.imap.AddMessage(t, "INBOX", plainMail("a@example.net", "x", "y"), baseDate)}.String()
	if _, err := env.client.Move(ctx(t), []string{inbox}, Destination{Folder: DefaultStateFolder}); !errors.Is(err, ErrProtected) {
		t.Fatalf("move in: %v", err)
	}

	bad := env.newClient(func(c *Config) { c.StateFolder = "Sent" })
	err := bad.Records().Update(ctx(t), "fam", "f", 1, func([]Record) (Record, error) { return Record{"fam": "f"}, nil })
	if !errors.Is(err, ErrInvalidInput) || len(env.imap.Messages(t, "Sent")) != 0 {
		t.Fatalf("role folder as state folder: %v", err)
	}
	if env.newClient(func(c *Config) { c.StateFolder = "" }).Records() != nil {
		t.Fatal("memory mode returned a store")
	}
}

func TestStateFolderConfig(t *testing.T) {
	get := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	base := map[string]string{EnvUsername: "u@example.org", EnvPassword: "p"}
	if cfg, err := ConfigFromEnv(get(base)); err != nil || cfg.StateFolder != DefaultStateFolder {
		t.Fatalf("default: %q %v", cfg.StateFolder, err)
	}
	base[EnvState] = "memory"
	if cfg, _ := ConfigFromEnv(get(base)); cfg.StateFolder != "" {
		t.Fatal("memory mode kept folder")
	}
	base[EnvState] = "disk"
	if _, err := ConfigFromEnv(get(base)); err == nil {
		t.Fatal("bad mode accepted")
	}
	c := Config{Username: "u@example.org", Password: "p", DraftKey: testDraftKey, LedgerFolder: "X", StateFolder: "X"}
	if _, err := New(c, &fakePolicy{}); err == nil {
		t.Fatal("state folder == ledger folder accepted")
	}
}
