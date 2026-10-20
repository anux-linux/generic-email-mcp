package mail

import (
	"bytes"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
)

// recConn records bytes that reach the wire.
type recConn struct {
	net.Conn
	buf    bytes.Buffer
	closed bool
}

func (c *recConn) Write(p []byte) (int, error) { return c.buf.Write(p) }
func (c *recConn) Close() error                { c.closed = true; return nil }

func TestGuardAllowsSafeCommandsByteExact(t *testing.T) {
	stream := strings.Join([]string{
		"a1 LOGIN user pass",
		"a2 EXAMINE INBOX",
		`a3 UID FETCH 1:5 (UID FLAGS BODY.PEEK[1]<0.1024>)`,
		`a4 UID STORE 5 +FLAGS.SILENT (\Seen)`,
		"a5 UID MOVE 5 Trash",
		"a6 UNSELECT",
		"a7 LOGOUT",
	}, "\r\n") + "\r\n"
	rc := &recConn{}
	g := newGuardConn(rc)
	if _, err := g.Write([]byte(stream)); err != nil {
		t.Fatal(err)
	}
	if rc.buf.String() != stream {
		t.Fatalf("stream altered:\n%q\n%q", rc.buf.String(), stream)
	}
}

func TestGuardBlocksDestructiveCommands(t *testing.T) {
	for _, cmd := range []string{
		"a1 EXPUNGE",
		"a1 expunge",
		"a1 UID EXPUNGE 1:3",
		"a1 uid Expunge 4",
		"a1 CLOSE",
		"a1 DELETE Trash",
		`a1 STORE 1 +FLAGS.SILENT (\Deleted)`,
		`a1 UID STORE 1:* +FLAGS (\Seen \Deleted)`,
		`a1 UID STORE 1 FLAGS (\deleted)`,
	} {
		rc := &recConn{}
		g := newGuardConn(rc)
		// Prefix with a harmless command to check that only the bad line
		// is withheld.
		_, err := g.Write([]byte("a0 NOOP\r\n" + cmd + "\r\n"))
		if !errors.Is(err, ErrForbidden) {
			t.Errorf("%q: err = %v, want ErrForbidden", cmd, err)
			continue
		}
		if got := rc.buf.String(); got != "a0 NOOP\r\n" {
			t.Errorf("%q: wire got %q", cmd, got)
		}
		if !rc.closed {
			t.Errorf("%q: connection not closed", cmd)
		}
		if _, err := g.Write([]byte("a2 NOOP\r\n")); !errors.Is(err, ErrForbidden) {
			t.Errorf("%q: guard not sticky: %v", cmd, err)
		}
	}
}

func TestGuardBlocksSplitWrites(t *testing.T) {
	rc := &recConn{}
	g := newGuardConn(rc)
	var err error
	for _, b := range []byte("a1 NOOP\r\na2 UID EXPUNGE 7\r\n") {
		if _, err = g.Write([]byte{b}); err != nil {
			break
		}
	}
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("err = %v", err)
	}
	if rc.buf.String() != "a1 NOOP\r\n" {
		t.Fatalf("wire got %q", rc.buf.String())
	}
}

func TestGuardPassesLiteralContent(t *testing.T) {
	// Message content that looks like commands must not trigger the guard,
	// and the line after a literal continues the APPEND command.
	msg := "Subject: x\r\n\r\na1 EXPUNGE\r\nb2 UID STORE 1 +FLAGS (\\Deleted)\r\n"
	for _, marker := range []string{"{%d}", "{%d+}", "~{%d}"} {
		lit := strings.Replace(marker, "%d", strconv.Itoa(len(msg)), 1)
		stream := "a1 APPEND Drafts (\\Draft) " + lit + "\r\n" + msg + "\r\na2 NOOP\r\n"
		rc := &recConn{}
		g := newGuardConn(rc)
		for i := 0; i < len(stream); i += 7 { // odd chunking
			end := min(i+7, len(stream))
			if _, err := g.Write([]byte(stream[i:end])); err != nil {
				t.Fatalf("%s: %v", marker, err)
			}
		}
		if rc.buf.String() != stream {
			t.Fatalf("%s: stream altered", marker)
		}
	}
}

func TestGuardChecksCommandAfterLiteral(t *testing.T) {
	stream := "a1 LOGIN {4}\r\nuser {4}\r\npass\r\na2 EXPUNGE\r\n"
	rc := &recConn{}
	g := newGuardConn(rc)
	if _, err := g.Write([]byte(stream)); !errors.Is(err, ErrForbidden) {
		t.Fatalf("err = %v", err)
	}
	if rc.buf.String() != "a1 LOGIN {4}\r\nuser {4}\r\npass\r\n" {
		t.Fatalf("wire got %q", rc.buf.String())
	}
}

func TestGuardRecordsCommands(t *testing.T) {
	var got []string
	g := newGuardConn(&recConn{})
	g.onCommand = func(name string) { got = append(got, name) }
	if _, err := g.Write([]byte("a1 NOOP\r\na2 uid fetch 1 (UID)\r\n")); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "NOOP,UID FETCH" {
		t.Fatalf("got %v", got)
	}
}
