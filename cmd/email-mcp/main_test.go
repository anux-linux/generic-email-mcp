package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/anux-linux/generic-email-mcp/internal/config"
	"github.com/anux-linux/generic-email-mcp/internal/logging"
	"github.com/anux-linux/generic-email-mcp/internal/server"
)

func TestHashPasswordCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run(t.Context(), []string{"hash-password"}, nil, strings.NewReader("a long enough password\n"), &out, &errOut)
	if code != 0 || !strings.HasPrefix(out.String(), "$argon2id$v=19$m=65536,t=3,p=1$") || strings.Contains(out.String(), "a long enough") {
		t.Fatalf("code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
	out.Reset()
	if code := run(t.Context(), []string{"hash-password"}, nil, strings.NewReader("short\n"), &out, &errOut); code != 1 || out.Len() != 0 {
		t.Fatalf("short password: %d", code)
	}
}

func TestUsageAndVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(t.Context(), []string{"bogus"}, nil, nil, &out, &errOut); code != 2 {
		t.Fatalf("code %d", code)
	}
	if code := run(t.Context(), []string{"version"}, nil, nil, &out, &errOut); code != 0 || out.Len() == 0 {
		t.Fatalf("version: %d", code)
	}
}

func TestConfigErrorExitsWithoutLeakingSecrets(t *testing.T) {
	env := map[string]string{"MAIL_PASSWORD": "hunter2-mail", "OAUTH_CLIENT_SECRET": "short-secret-value"}
	var out, errOut bytes.Buffer
	code := run(t.Context(), nil, func(k string) string { return env[k] }, nil, &out, &errOut)
	if code != 1 || !strings.Contains(errOut.String(), "configuration error") {
		t.Fatalf("code=%d %s", code, errOut.String())
	}
	if strings.Contains(errOut.String(), "hunter2") || strings.Contains(errOut.String(), "short-secret-value") {
		t.Fatal("secret in error output")
	}
}

func validEnv(base string) map[string]string {
	return map[string]string{
		"BASE_URL":                base,
		"OAUTH_CLIENT_ID":         "claude-client-0123456789",
		"OAUTH_CLIENT_SECRET":     "client-secret-0123456789abcdefghijklmnop",
		"TOKEN_SIGNING_KEY":       base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("K"), 32)),
		"AUTHORIZE_PASSWORD_HASH": "$argon2id$v=19$m=19456,t=1,p=1$MDEyMzQ1Njc4OWFiY2RlZg$Yo8w0JmYbYbqZ1pYcjWQ0z2PQK6oFzA9eM3Y2yVdD3Q",
		"MAIL_USERNAME":           "me@example.org",
		"MAIL_PASSWORD":           "x",
	}
}

func TestServeAndGracefulShutdown(t *testing.T) {
	for _, base := range []string{"", "http://127.0.0.1:8080"} { // setup and ready
		env := validEnv(base)
		cfg, err := config.Load(func(k string) string { return env[k] })
		if err != nil {
			t.Fatal(err)
		}
		var logs bytes.Buffer
		logger := logging.New(&logs, logging.Options{})
		h, err := buildHandler(cfg, logger)
		if err != nil {
			t.Fatal(err)
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan int, 1)
		go func() { done <- serve(ctx, ln, server.NewHTTPServer(ln.Addr().String(), h, logger), cfg, logger) }()

		resp, err := http.Get("http://" + ln.Addr().String() + "/healthz")
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("healthz: %v", err)
		}
		resp.Body.Close()
		cancel()
		select {
		case code := <-done:
			if code != 0 {
				t.Fatalf("exit code %d", code)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("no shutdown")
		}
	}
}
