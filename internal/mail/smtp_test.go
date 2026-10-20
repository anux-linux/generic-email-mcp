package mail

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/anux-linux/generic-email-mcp/internal/testutil"
)

func newTestSender(t *testing.T, certs *testutil.TLS, addr, user, pass string) *smtpSender {
	t.Helper()
	cfg := Config{SMTPAddr: addr, Username: user, Password: pass, TLSConfig: certs.Client}
	cfg.setDefaults()
	s, err := newSMTPSender(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSMTPSendSuccess(t *testing.T) {
	certs := testutil.NewTLS(t)
	srv := testutil.StartSMTP(t, certs, "user@example.org", "pw")
	s := newTestSender(t, certs, srv.Addr, "user@example.org", "pw")

	msg := []byte("Subject: hi\r\n\r\n.leading dot\r\nbody\r\n")
	if err := s.Send(ctx(t), "user@example.org", []string{"a@example.net", "b@example.net"}, msg); err != nil {
		t.Fatal(err)
	}
	got := srv.Messages()
	if len(got) != 1 {
		t.Fatalf("messages = %d", len(got))
	}
	if got[0].From != "user@example.org" || strings.Join(got[0].Rcpts, ",") != "a@example.net,b@example.net" {
		t.Fatalf("envelope = %+v", got[0])
	}
	if string(got[0].Data) != string(msg) {
		t.Fatalf("data = %q", got[0].Data)
	}
}

func TestSMTPBadPassword(t *testing.T) {
	certs := testutil.NewTLS(t)
	srv := testutil.StartSMTP(t, certs, "user@example.org", "pw")
	s := newTestSender(t, certs, srv.Addr, "user@example.org", "wrong")
	err := s.Send(ctx(t), "user@example.org", []string{"a@example.net"}, []byte("x\r\n"))
	mustErrIs(t, err, ErrAuth)
	if strings.Contains(err.Error(), "user@example.org") || strings.Contains(err.Error(), "wrong") {
		t.Fatalf("error leaks credentials: %v", err)
	}
	if len(srv.Messages()) != 0 {
		t.Fatal("message accepted")
	}
}

func TestSMTPRecipientRejectedSendsNothing(t *testing.T) {
	certs := testutil.NewTLS(t)
	srv := testutil.StartSMTP(t, certs, "u", "pw")
	srv.RejectRecipient("bad@example.net")
	s := newTestSender(t, certs, srv.Addr, "u", "pw")
	err := s.Send(ctx(t), "u@example.org", []string{"ok@example.net", "bad@example.net"}, []byte("x\r\n"))
	mustErrIs(t, err, ErrUpstream)
	if strings.Contains(err.Error(), "bad@example.net") {
		t.Fatalf("error echoes server text: %v", err)
	}
	if !strings.Contains(err.Error(), "550") {
		t.Fatalf("error lacks reply code: %v", err)
	}
	if len(srv.Messages()) != 0 {
		t.Fatal("partial delivery")
	}
}

func TestSMTPVerifiesCertificate(t *testing.T) {
	certs := testutil.NewTLS(t)
	srv := testutil.StartSMTP(t, certs, "u", "pw")
	other := testutil.NewTLS(t) // trusts a different CA
	s := newTestSender(t, other, srv.Addr, "u", "pw")
	err := s.Send(ctx(t), "u@example.org", []string{"a@example.net"}, []byte("x\r\n"))
	var verr *tls.CertificateVerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("err = %v, want certificate verification error", err)
	}
	if srv.Logins() != 0 {
		t.Fatal("credentials sent to unverified server")
	}
}

func TestSMTPHonorsContextDeadline(t *testing.T) {
	certs := testutil.NewTLS(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", certs.Server)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { // complete the handshake, then stall
				_ = c.(*tls.Conn).Handshake()
				time.Sleep(5 * time.Second)
				c.Close()
			}(c)
		}
	}()
	s := newTestSender(t, certs, ln.Addr().String(), "u", "pw")
	c, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = s.Send(c, "u@example.org", []string{"a@example.net"}, []byte("x\r\n"))
	if ErrorKind(err) != "timeout" {
		t.Fatalf("err = %v (kind %q), want timeout", err, ErrorKind(err))
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("deadline not enforced")
	}
}
