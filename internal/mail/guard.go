package mail

import (
	"bytes"
	"fmt"
	"net"
	"strconv"
	"sync"
)

// guardConn wraps the IMAP connection and refuses to transmit any command
// that can permanently remove mail: EXPUNGE, UID EXPUNGE, CLOSE (implicit
// expunge), DELETE (mailbox) and STORE/UID STORE setting \Deleted.
//
// This is defence in depth: no code in this package issues those commands,
// but imapclient.Move silently falls back to COPY + STORE \Deleted + EXPUNGE
// when the server lacks MOVE. The guard makes "no permanent deletion" a
// property of the transport rather than of every call site.
//
// It parses the client→server byte stream just enough to find command lines,
// passing literal payloads ({N} / {N+} / ~{N}) through unparsed so message
// content can never trigger it. A command line is forwarded only once it is
// complete and has been checked.
type guardConn struct {
	net.Conn

	mu      sync.Mutex
	line    []byte // current, not yet forwarded command-line fragment
	literal int64  // literal bytes still to pass through unparsed
	cont    bool   // current line continues a command after a literal
	err     error  // sticky: once blocked, the connection is dead

	// onCommand, if set, observes every command name (tests).
	onCommand func(name string)
}

const maxCommandLine = 64 << 10

func newGuardConn(c net.Conn) *guardConn { return &guardConn{Conn: c} }

func (g *guardConn) Write(p []byte) (int, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.err != nil {
		return 0, g.err
	}
	n := 0
	for len(p) > 0 {
		if g.literal > 0 {
			k := int(min(int64(len(p)), g.literal))
			w, err := g.Conn.Write(p[:k])
			n += w
			g.literal -= int64(w)
			if err != nil {
				return n, err
			}
			p = p[k:]
			continue
		}
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			if len(g.line)+len(p) > maxCommandLine {
				return n, g.fail(fmt.Errorf("%w: command line too long", ErrForbidden))
			}
			g.line = append(g.line, p...)
			return n + len(p), nil
		}
		g.line = append(g.line, p[:i+1]...)
		p = p[i+1:]
		if err := g.checkLine(); err != nil {
			return n, g.fail(err)
		}
		if _, err := g.Conn.Write(g.line); err != nil {
			return n, err
		}
		n += i + 1
		g.line = g.line[:0]
	}
	return n, nil
}

// blocked returns the violation that killed the connection, if any. The
// IMAP client only sees the resulting EOF, so callers check this.
func (g *guardConn) blocked() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.err
}

func (g *guardConn) fail(err error) error {
	g.err = err
	g.line = nil
	_ = g.Conn.Close()
	return err
}

// checkLine inspects the complete line in g.line and updates literal state.
func (g *guardConn) checkLine() error {
	line := bytes.TrimRight(g.line, "\r\n")
	if !g.cont {
		if err := g.checkCommand(line); err != nil {
			return err
		}
	}
	g.cont = false
	if n, ok := trailingLiteral(line); ok {
		g.literal = n
		g.cont = true
	}
	return nil
}

func (g *guardConn) checkCommand(line []byte) error {
	fields := bytes.Fields(line)
	if len(fields) < 2 {
		// Continuation responses (e.g. "DONE", SASL data) have no tag.
		return nil
	}
	name := string(bytes.ToUpper(fields[1]))
	args := fields[2:]
	if name == "UID" && len(args) > 0 {
		name = "UID " + string(bytes.ToUpper(args[0]))
		args = args[1:]
	}
	if g.onCommand != nil {
		g.onCommand(name)
	}
	switch name {
	case "EXPUNGE", "UID EXPUNGE", "CLOSE", "DELETE":
		return fmt.Errorf("%w: %s", ErrForbidden, name)
	case "STORE", "UID STORE":
		for _, a := range args {
			if bytes.Contains(bytes.ToLower(a), []byte(`\deleted`)) {
				return fmt.Errorf("%w: %s \\Deleted", ErrForbidden, name)
			}
		}
	}
	return nil
}

// trailingLiteral reports a literal announcement ({N}, {N+}, ~{N}) at the end
// of line.
func trailingLiteral(line []byte) (int64, bool) {
	if len(line) < 3 || line[len(line)-1] != '}' {
		return 0, false
	}
	open := bytes.LastIndexByte(line, '{')
	if open < 0 {
		return 0, false
	}
	num := bytes.TrimSuffix(line[open+1:len(line)-1], []byte("+"))
	n, err := strconv.ParseInt(string(num), 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}
