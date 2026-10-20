package mail

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"net/textproto"
	"time"
)

// Sender submits a fully formed message. Implementations must not log
// recipients or content.
type Sender interface {
	Send(ctx context.Context, from string, rcpts []string, msg []byte) error
}

// defaultSMTPTimeout bounds a submission when ctx has no deadline.
const defaultSMTPTimeout = 60 * time.Second

// smtpSender submits over implicit TLS (RFC 8314, port 465) with AUTH PLAIN.
// Certificate verification is always on.
type smtpSender struct {
	addr        string
	host        string
	helo        string
	username    string
	password    string
	tlsConfig   *tls.Config
	dialTimeout time.Duration
}

func newSMTPSender(cfg *Config) (*smtpSender, error) {
	host, _, err := net.SplitHostPort(cfg.SMTPAddr)
	if err != nil {
		return nil, err
	}
	return &smtpSender{
		addr:        cfg.SMTPAddr,
		host:        host,
		helo:        cfg.SMTPHelo,
		username:    cfg.Username,
		password:    cfg.Password,
		tlsConfig:   cfg.tlsConfig(host),
		dialTimeout: cfg.DialTimeout,
	}, nil
}

func (s *smtpSender) Send(ctx context.Context, from string, rcpts []string, msg []byte) error {
	if len(rcpts) == 0 {
		return fmt.Errorf("%w: no recipients", ErrInvalidInput)
	}
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: s.dialTimeout}, Config: s.tlsConfig.Clone()}
	conn, err := d.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return ctxErr(ctx, fmt.Errorf("smtp connect: %w", err))
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(defaultSMTPTimeout)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return err
	}

	c, err := smtp.NewClient(conn, s.host)
	if err != nil {
		_ = conn.Close()
		return ctxErr(ctx, smtpErr("greeting", err))
	}
	defer c.Close()

	if err := c.Hello(s.helo); err != nil {
		return ctxErr(ctx, smtpErr("ehlo", err))
	}
	if ok, _ := c.Extension("AUTH"); !ok {
		return fmt.Errorf("%w: smtp server offers no AUTH", ErrUpstream)
	}
	// PlainAuth refuses to send credentials unless the connection is TLS
	// and the server name matches s.host.
	if err := c.Auth(smtp.PlainAuth("", s.username, s.password, s.host)); err != nil {
		var tpErr *textproto.Error
		if errors.As(err, &tpErr) && tpErr.Code/100 == 5 {
			return ErrAuth
		}
		return ctxErr(ctx, smtpErr("auth", err))
	}
	if err := c.Mail(from); err != nil {
		return ctxErr(ctx, smtpErr("sender rejected", err))
	}
	for _, r := range rcpts {
		if err := c.Rcpt(r); err != nil {
			// Abort before DATA: nothing is delivered to anyone.
			return ctxErr(ctx, smtpErr("recipient rejected", err))
		}
	}
	w, err := c.Data()
	if err != nil {
		return ctxErr(ctx, smtpErr("data", err))
	}
	if _, err := w.Write(msg); err != nil {
		return ctxErr(ctx, smtpErr("data", err))
	}
	if err := w.Close(); err != nil {
		var tpErr *textproto.Error
		if !errors.As(err, &tpErr) {
			// The terminating "." may have reached the server; only a reply
			// code would tell. Never let this look like a clean failure.
			return ctxErr(ctx, fmt.Errorf("%w: %w", ErrDeliveryUnknown, err))
		}
		return ctxErr(ctx, smtpErr("message rejected", err))
	}
	// The message is accepted once DATA completes; a failed QUIT is moot.
	_ = c.Quit()
	return nil
}

// smtpErr keeps the SMTP reply code but drops the server text, which can
// echo addresses.
func smtpErr(stage string, err error) error {
	var tpErr *textproto.Error
	if errors.As(err, &tpErr) {
		return fmt.Errorf("%w: smtp %s (%d)", ErrUpstream, stage, tpErr.Code)
	}
	return fmt.Errorf("%w: smtp %s: %w", ErrUpstream, stage, err)
}
