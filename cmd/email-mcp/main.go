// Command email-mcp serves one mailbox to claude.ai over MCP (Streamable
// HTTP) with a built-in OAuth authorization server.
//
// Usage:
//
//	email-mcp                 serve (configuration from the environment)
//	email-mcp hash-password   read a password from stdin, print an argon2id hash
//	email-mcp version
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/anux-linux/generic-email-mcp/internal/config"
	"github.com/anux-linux/generic-email-mcp/internal/logging"
	"github.com/anux-linux/generic-email-mcp/internal/mail"
	"github.com/anux-linux/generic-email-mcp/internal/mcptools"
	"github.com/anux-linux/generic-email-mcp/internal/oauth"
	"github.com/anux-linux/generic-email-mcp/internal/policy"
	"github.com/anux-linux/generic-email-mcp/internal/server"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = ""

// shutdownGrace stays below Cloud Run's 10 s SIGTERM grace period.
const shutdownGrace = 8 * time.Second

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Getenv, os.Stdin, os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "hash-password":
			return hashPassword(stdin, stdout, stderr)
		case "version":
			fmt.Fprintln(stdout, buildVersion())
			return 0
		default:
			fmt.Fprintln(stderr, "usage: email-mcp [hash-password | version]")
			return 2
		}
	}

	cfg, err := config.Load(getenv)
	if err != nil {
		// Messages name settings only, never values.
		fmt.Fprintf(stderr, "configuration error:\n%v\n", err)
		return 1
	}
	logger := logging.New(stdout, logging.Options{Level: cfg.LogLevel})
	handler, err := buildHandler(cfg, logger)
	if err != nil {
		fmt.Fprintf(stderr, "startup error: %v\n", err)
		return 1
	}

	ln, err := net.Listen("tcp", ":"+cfg.Port)
	if err != nil {
		fmt.Fprintf(stderr, "listen: %v\n", err)
		return 1
	}
	return serve(ctx, ln, server.NewHTTPServer(ln.Addr().String(), handler, logger), cfg, logger)
}

func serve(ctx context.Context, ln net.Listener, srv *http.Server, cfg *config.Config, logger *slog.Logger) int {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()
	mode := "ready"
	if cfg.Setup() {
		mode = "setup"
	}
	logger.Info("listening", "component", "main", "addr", ln.Addr().String(), "status", mode, "version", buildVersion())

	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server stopped", "component", "main", "reason", "serve_error")
			return 1
		}
		return 0
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		logger.Warn("shutdown incomplete", "component", "main", "reason", "timeout")
		return 1
	}
	logger.Info("stopped", "component", "main")
	return 0
}

func buildHandler(cfg *config.Config, logger *slog.Logger) (http.Handler, error) {
	deps := server.Deps{BaseURL: cfg.BaseURL, Logger: logger, TrustedProxyHops: cfg.TrustedProxyHops}
	if cfg.Setup() {
		return server.Handler(deps), nil
	}
	pol, err := policy.NewMemory(cfg.Policy)
	if err != nil {
		return nil, err
	}
	mb, err := mail.New(cfg.Mail, pol)
	if err != nil {
		return nil, err
	}
	oc := cfg.OAuth
	oc.Logger = logger
	if deps.OAuth, err = oauth.New(oc); err != nil {
		return nil, err
	}
	deps.MCP = mcptools.NewServer(mb, mcptools.Options{Version: buildVersion(), Logger: logger, Policy: pol})
	return server.Handler(deps), nil
}

// hashPassword reads one line from stdin and prints its argon2id hash.
func hashPassword(stdin io.Reader, stdout, stderr io.Writer) int {
	line, err := bufio.NewReader(io.LimitReader(stdin, 1025)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		fmt.Fprintln(stderr, "read password:", err)
		return 1
	}
	pw := strings.TrimRight(line, "\r\n")
	if len(pw) > 1024 {
		fmt.Fprintln(stderr, "password too long (max 1024 bytes)")
		return 1
	}
	h, err := oauth.HashPassword(pw)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintln(stdout, h)
	return 0
}

func buildVersion() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" && len(s.Value) >= 12 {
				return s.Value[:12]
			}
		}
	}
	return "dev"
}
