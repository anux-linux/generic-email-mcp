package oauth

import (
	"net/url"
	"sync"
	"testing"
)

// Concurrent use of one grant cannot be told apart from replay, so the
// single-use rules must hold under races (run with -race): exactly one
// request wins, and the losers revoke what the winner received.

const racers = 16

type raceResult struct {
	status int
	access string
}

func race(e *env, t *testing.T, form url.Values) []raceResult {
	out := make([]raceResult, racers)
	var wg sync.WaitGroup
	for i := range out {
		wg.Go(func() {
			w, body := e.token(t, form, true)
			out[i].status = w.Code
			out[i].access, _ = body["access_token"].(string)
		})
	}
	wg.Wait()
	return out
}

func checkOneWinnerRevoked(t *testing.T, e *env, res []raceResult) {
	t.Helper()
	wins := 0
	for _, r := range res {
		switch r.status {
		case 200:
			wins++
			if err := e.verify(r.access); err == nil {
				t.Error("winner's access token survived the concurrent reuse")
			}
		case 400:
		default:
			t.Errorf("status %d", r.status)
		}
	}
	if wins != 1 {
		t.Fatalf("%d requests won, want exactly 1", wins)
	}
}

func TestConcurrentCodeRedemption(t *testing.T) {
	e := newEnv(t, nil)
	checkOneWinnerRevoked(t, e, race(e, t, codeForm(e.code(t))))
}

func TestConcurrentRefresh(t *testing.T) {
	e := newEnv(t, nil)
	_, rt := e.tokens(t)
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}
	checkOneWinnerRevoked(t, e, race(e, t, form))
	// The family is dead for good, not only for the racers.
	w, body := e.token(t, form, true)
	wantTokenError(t, w, body, 400, "invalid_grant")
}

// Independent families do not interfere: parallel logins all succeed and
// each refresh rotates its own family.
func TestConcurrentIndependentFamilies(t *testing.T) {
	e := newEnv(t, nil)
	var wg sync.WaitGroup
	errs := make(chan string, racers)
	for range racers {
		wg.Go(func() {
			// e.code would call t.Fatal off the test goroutine.
			loc, err := url.Parse(e.authorize(t, authParams(), DefaultUsername, testPassword).Header().Get("Location"))
			if err != nil || loc.Query().Get("code") == "" {
				errs <- "authorize failed"
				return
			}
			w, body := e.token(t, codeForm(loc.Query().Get("code")), true)
			if w.Code != 200 {
				errs <- "code exchange failed"
				return
			}
			w, body = e.token(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {body["refresh_token"].(string)}}, true)
			if w.Code != 200 {
				errs <- "refresh failed"
				return
			}
			if e.verify(body["access_token"].(string)) != nil {
				errs <- "rotated access token rejected"
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
