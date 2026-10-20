package mail

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"strconv"
	"strings"
	"time"
)

// Defaults for Strato (see docs/VERIFY.md).
const (
	DefaultIMAPAddr      = "imap.strato.de:993"
	DefaultSMTPAddr      = "smtp.strato.de:465"
	DefaultSMTPHelo      = "[127.0.0.1]"
	DefaultMaxBodyBytes  = 64 << 10
	DefaultMaxFetchBytes = 1 << 20
	DefaultDialTimeout   = 10 * time.Second

	// MinDraftKeyLen is the minimum HMAC key length for draft IDs.
	MinDraftKeyLen = 32
)

// FolderOverrides pins role folders by exact name, bypassing discovery.
type FolderOverrides struct {
	Sent    string
	Drafts  string
	Trash   string
	Archive string
}

func (o FolderOverrides) get(r Role) string {
	switch r {
	case RoleSent:
		return o.Sent
	case RoleDrafts:
		return o.Drafts
	case RoleTrash:
		return o.Trash
	case RoleArchive:
		return o.Archive
	}
	return ""
}

// Config configures a Client. Both servers are reached over implicit TLS
// with certificate verification; there is deliberately no way to disable it.
type Config struct {
	IMAPAddr string // host:port, implicit TLS
	SMTPAddr string // host:port, implicit TLS
	SMTPHelo string // EHLO name

	Username string // IMAP/SMTP login (Strato: the full address)
	Password string

	FromAddress string // defaults to Username
	FromName    string

	Folders  FolderOverrides
	SaveSent bool // APPEND a copy of sent mail to the Sent folder

	MaxBodyBytes  int   // cap on returned body text
	MaxFetchBytes int64 // cap on raw bytes fetched per text part
	DialTimeout   time.Duration

	// DraftKey authenticates draft IDs (HMAC-SHA256). At least
	// MinDraftKeyLen bytes.
	DraftKey []byte

	// TLSConfig optionally supplies RootCAs (tests). Verification cannot be
	// disabled: InsecureSkipVerify is rejected by Validate.
	TLSConfig *tls.Config
}

// Env var names read by ConfigFromEnv.
const (
	EnvIMAPAddr      = "MAIL_IMAP_ADDR"
	EnvSMTPAddr      = "MAIL_SMTP_ADDR"
	EnvSMTPHelo      = "MAIL_SMTP_HELO"
	EnvUsername      = "MAIL_USERNAME"
	EnvPassword      = "MAIL_PASSWORD"
	EnvFromAddress   = "MAIL_FROM"
	EnvFromName      = "MAIL_FROM_NAME"
	EnvFolderSent    = "MAIL_FOLDER_SENT"
	EnvFolderDrafts  = "MAIL_FOLDER_DRAFTS"
	EnvFolderTrash   = "MAIL_FOLDER_TRASH"
	EnvFolderArchive = "MAIL_FOLDER_ARCHIVE"
	EnvSaveSent      = "MAIL_SAVE_SENT"
	EnvMaxBodyBytes  = "MAIL_MAX_BODY_BYTES"
)

// ConfigFromEnv builds a Config from environment variables. DraftKey and
// TLSConfig are not read from the environment; the caller sets DraftKey.
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	c := Config{
		IMAPAddr:    strings.TrimSpace(getenv(EnvIMAPAddr)),
		SMTPAddr:    strings.TrimSpace(getenv(EnvSMTPAddr)),
		SMTPHelo:    strings.TrimSpace(getenv(EnvSMTPHelo)),
		Username:    strings.TrimSpace(getenv(EnvUsername)),
		Password:    getenv(EnvPassword),
		FromAddress: strings.TrimSpace(getenv(EnvFromAddress)),
		FromName:    strings.TrimSpace(getenv(EnvFromName)),
		Folders: FolderOverrides{
			Sent:    getenv(EnvFolderSent),
			Drafts:  getenv(EnvFolderDrafts),
			Trash:   getenv(EnvFolderTrash),
			Archive: getenv(EnvFolderArchive),
		},
		SaveSent: true,
	}
	if v := strings.TrimSpace(getenv(EnvSaveSent)); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return Config{}, fmt.Errorf("%s: %w", EnvSaveSent, err)
		}
		c.SaveSent = b
	}
	if v := strings.TrimSpace(getenv(EnvMaxBodyBytes)); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1024 || n > 4<<20 {
			return Config{}, fmt.Errorf("%s must be an integer in [1024, 4194304]", EnvMaxBodyBytes)
		}
		c.MaxBodyBytes = n
	}
	c.setDefaults()
	return c, nil
}

func (c *Config) setDefaults() {
	if c.IMAPAddr == "" {
		c.IMAPAddr = DefaultIMAPAddr
	}
	if c.SMTPAddr == "" {
		c.SMTPAddr = DefaultSMTPAddr
	}
	if c.SMTPHelo == "" {
		c.SMTPHelo = DefaultSMTPHelo
	}
	if c.FromAddress == "" {
		c.FromAddress = c.Username
	}
	if c.MaxBodyBytes == 0 {
		c.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if c.MaxFetchBytes == 0 {
		c.MaxFetchBytes = DefaultMaxFetchBytes
	}
	if c.DialTimeout == 0 {
		c.DialTimeout = DefaultDialTimeout
	}
}

// Validate reports configuration errors. Messages name the setting, never
// its value.
func (c *Config) Validate() error {
	var errs []error
	for _, a := range []struct{ name, addr string }{{"IMAP address", c.IMAPAddr}, {"SMTP address", c.SMTPAddr}} {
		host, port, err := net.SplitHostPort(a.addr)
		if err != nil || host == "" || port == "" {
			errs = append(errs, fmt.Errorf("%s must be host:port", a.name))
		}
	}
	if c.Username == "" {
		errs = append(errs, errors.New("mail username is required"))
	}
	if c.Password == "" {
		errs = append(errs, errors.New("mail password is required"))
	}
	if a, err := mail.ParseAddress(c.FromAddress); err != nil || a.Name != "" || !isASCII(a.Address) {
		errs = append(errs, errors.New("from address must be a bare ASCII address"))
	}
	if strings.ContainsAny(c.FromName, "\r\n") {
		errs = append(errs, errors.New("from name must be a single line"))
	}
	if strings.ContainsAny(c.SMTPHelo, " \t\r\n") {
		errs = append(errs, errors.New("SMTP HELO name must not contain whitespace"))
	}
	if len(c.DraftKey) < MinDraftKeyLen {
		errs = append(errs, fmt.Errorf("draft key must be at least %d bytes", MinDraftKeyLen))
	}
	if c.MaxBodyBytes < 1024 || c.MaxFetchBytes < int64(c.MaxBodyBytes) {
		errs = append(errs, errors.New("body limits are invalid"))
	}
	if c.TLSConfig != nil && c.TLSConfig.InsecureSkipVerify {
		errs = append(errs, errors.New("TLS verification cannot be disabled"))
	}
	return errors.Join(errs...)
}

// tlsConfig returns the client TLS config for host: verification on,
// TLS 1.2 minimum.
func (c *Config) tlsConfig(host string, alpn ...string) *tls.Config {
	var t *tls.Config
	if c.TLSConfig != nil {
		t = c.TLSConfig.Clone()
	} else {
		t = &tls.Config{}
	}
	t.InsecureSkipVerify = false
	t.ServerName = host
	if t.MinVersion < tls.VersionTLS12 {
		t.MinVersion = tls.VersionTLS12
	}
	if len(alpn) > 0 && t.NextProtos == nil {
		t.NextProtos = alpn
	}
	return t
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func lowerASCII(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
