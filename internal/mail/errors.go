package mail

import (
	"context"
	"errors"
	"net"
	"os"
)

// Sentinel errors. Callers match them with errors.Is. Error strings never
// contain credentials, addresses, subjects or bodies.
var (
	ErrInvalidInput   = errors.New("invalid input")
	ErrInvalidID      = errors.New("invalid message id")
	ErrStaleID        = errors.New("message id is stale: the folder's UIDVALIDITY changed; search again")
	ErrNotFound       = errors.New("message not found")
	ErrFolderNotFound = errors.New("folder not found")
	ErrUnsupported    = errors.New("operation not supported by the mail server")
	ErrDraftInvalid   = errors.New("draft id is invalid, was not created by mail_create_draft, or the draft was modified since")
	ErrAlreadySent    = errors.New("draft was already sent or is being sent")
	ErrPolicy         = errors.New("send rejected by policy")
	// ErrDeliveryUnknown: the connection failed after the message data was
	// transmitted, so the server may have accepted it. Not safe to retry.
	ErrDeliveryUnknown = errors.New("delivery status unknown: the connection failed after the message was transmitted; check before retrying")
	ErrAuth            = errors.New("mail server authentication failed")
	ErrForbidden       = errors.New("forbidden IMAP command blocked")
	ErrUpstream        = errors.New("mail server error")
)

// ErrorKind returns a short, fixed classification of err that is safe to log.
func ErrorKind(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrDeliveryUnknown):
		return "delivery_unknown"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, ErrInvalidInput):
		return "invalid_input"
	case errors.Is(err, ErrInvalidID):
		return "invalid_id"
	case errors.Is(err, ErrStaleID):
		return "stale_id"
	case errors.Is(err, ErrNotFound):
		return "not_found"
	case errors.Is(err, ErrFolderNotFound):
		return "folder_not_found"
	case errors.Is(err, ErrUnsupported):
		return "unsupported"
	case errors.Is(err, ErrDraftInvalid):
		return "draft_invalid"
	case errors.Is(err, ErrAlreadySent):
		return "already_sent"
	case errors.Is(err, ErrPolicy):
		return "policy"
	case errors.Is(err, ErrAuth):
		return "auth"
	case errors.Is(err, ErrForbidden):
		return "forbidden"
	case errors.Is(err, ErrUpstream):
		return "upstream"
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return "timeout"
		}
		return "network"
	}
	return "internal"
}

// ctxErr prefers the context's error once it is done, because closing the
// connection on cancellation surfaces as an unrelated I/O error.
func ctxErr(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if cerr := ctx.Err(); cerr != nil && !errors.Is(err, cerr) {
		return errors.Join(cerr, err)
	}
	return err
}
