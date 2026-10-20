package testutil

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// SMTPMessage is one accepted SMTP transaction.
type SMTPMessage struct {
	From  string
	Rcpts []string
	Data  []byte
}

// SMTPServer is a minimal ESMTP submission server over implicit TLS that
// requires AUTH PLAIN and records accepted messages.
type SMTPServer struct {
	Addr     string
	Username string
	Password string

	mu         sync.Mutex
	messages   []SMTPMessage
	rejectRcpt map[string]bool
	dropData   bool
	authFails  int
	logins     int
}

// StartSMTP starts the server; it stops when the test ends.
func StartSMTP(t testing.TB, certs *TLS, username, password string) *SMTPServer {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", certs.Server)
	if err != nil {
		t.Fatal(err)
	}
	s := &SMTPServer{Addr: ln.Addr().String(), Username: username, Password: password, rejectRcpt: map[string]bool{}}
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Go(func() { s.serve(conn) })
		}
	})
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	return s
}

// RejectRecipient makes RCPT TO fail with 550 for addr.
func (s *SMTPServer) RejectRecipient(addr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rejectRcpt[strings.ToLower(addr)] = true
}

// DropAfterData makes the server read the message data and then close the
// connection without replying (delivery status unknown to the client).
func (s *SMTPServer) DropAfterData() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropData = true
}

// Messages returns the accepted messages.
func (s *SMTPServer) Messages() []SMTPMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]SMTPMessage(nil), s.messages...)
}

// Logins returns the number of successful AUTH attempts.
func (s *SMTPServer) Logins() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.logins
}

// AuthFailures returns the number of failed AUTH attempts.
func (s *SMTPServer) AuthFailures() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.authFails
}

func (s *SMTPServer) serve(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	reply := func(format string, args ...any) bool {
		fmt.Fprintf(w, format+"\r\n", args...)
		return w.Flush() == nil
	}
	if !reply("220 localhost ESMTP test") {
		return
	}
	var (
		authed bool
		cur    *SMTPMessage
	)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		verb, arg, _ := strings.Cut(line, " ")
		switch strings.ToUpper(verb) {
		case "EHLO", "HELO":
			fmt.Fprintf(w, "250-localhost\r\n250-AUTH PLAIN\r\n250-8BITMIME\r\n250 SIZE 10485760\r\n")
			if w.Flush() != nil {
				return
			}
		case "AUTH":
			mech, initial, _ := strings.Cut(arg, " ")
			if !strings.EqualFold(mech, "PLAIN") {
				reply("504 unsupported mechanism")
				continue
			}
			if initial == "" {
				if !reply("334 ") {
					return
				}
				if initial, err = r.ReadString('\n'); err != nil {
					return
				}
				initial = strings.TrimSpace(initial)
			}
			if s.checkPlain(initial) {
				authed = true
				reply("235 2.7.0 Authentication successful")
			} else {
				reply("535 5.7.8 Authentication credentials invalid")
			}
		case "MAIL":
			if !authed {
				reply("530 5.7.0 Authentication required")
				continue
			}
			cur = &SMTPMessage{From: addrArg(arg)}
			reply("250 2.1.0 Ok")
		case "RCPT":
			if cur == nil {
				reply("503 5.5.1 Need MAIL")
				continue
			}
			rcpt := addrArg(arg)
			s.mu.Lock()
			rejected := s.rejectRcpt[strings.ToLower(rcpt)]
			s.mu.Unlock()
			if rejected {
				reply("550 5.1.1 <%s>: Recipient address rejected", rcpt)
				continue
			}
			cur.Rcpts = append(cur.Rcpts, rcpt)
			reply("250 2.1.5 Ok")
		case "DATA":
			if cur == nil || len(cur.Rcpts) == 0 {
				reply("503 5.5.1 Need RCPT")
				continue
			}
			if !reply("354 End data with <CR><LF>.<CR><LF>") {
				return
			}
			data, err := readDotData(r)
			if err != nil {
				return
			}
			cur.Data = data
			s.mu.Lock()
			s.messages = append(s.messages, *cur)
			drop := s.dropData
			s.mu.Unlock()
			if drop {
				return
			}
			cur = nil
			reply("250 2.0.0 Ok: queued")
		case "RSET":
			cur = nil
			reply("250 2.0.0 Ok")
		case "NOOP":
			reply("250 2.0.0 Ok")
		case "QUIT":
			reply("221 2.0.0 Bye")
			return
		default:
			reply("502 5.5.2 Command not recognized")
		}
	}
}

func (s *SMTPServer) checkPlain(b64 string) bool {
	raw, err := base64.StdEncoding.DecodeString(b64)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		parts := bytes.Split(raw, []byte{0})
		if len(parts) == 3 && string(parts[1]) == s.Username && string(parts[2]) == s.Password {
			s.logins++
			return true
		}
	}
	s.authFails++
	return false
}

func addrArg(arg string) string {
	_, v, _ := strings.Cut(arg, ":")
	v = strings.TrimSpace(v)
	if i := strings.IndexByte(v, ' '); i >= 0 {
		v = v[:i] // drop ESMTP parameters
	}
	return strings.TrimSuffix(strings.TrimPrefix(v, "<"), ">")
}

// readDotData reads DATA until <CRLF>.<CRLF> and undoes dot-stuffing.
func readDotData(r *bufio.Reader) ([]byte, error) {
	var buf bytes.Buffer
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if line == ".\r\n" {
			return buf.Bytes(), nil
		}
		if !strings.HasSuffix(line, "\r\n") {
			return nil, errors.New("bare LF in DATA")
		}
		buf.WriteString(strings.TrimPrefix(line, "."))
	}
}
