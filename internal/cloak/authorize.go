package cloak

import (
	"log/slog"
	"sync"
	"time"

	"github.com/emersion/go-imap/v2"

	"github.com/brodyhoskins/mailcached/engine"

	"github.com/brodyhoskins/mailcloak-bridge/internal/version"
)

// The bridge serves only accounts whose provider reports a DMARC verdict
// it can read: without one, a forged sender is indistinguishable from a
// real one, and so are the keys that come with it.
//
// unsupportedAfter is how many messages mailcached examines without
// finding the provider's stamp, not even as a candidate, before an account
// is unsupported: from its first message if it never had a stamp, or from
// when the bridge saw it lose one. A provider's new name is a candidate by
// then, as it is on every message of a full window.
const unsupportedAfter = 20

// Unsupported reports whether st describes an account whose provider does
// not report a DMARC verdict the bridge can read. lostAt is st.Examined
// when the bridge first saw the account without the stamp it had.
func Unsupported(st engine.AuthState, lostAt int) bool {
	if len(st.Stamp) > 0 || len(st.Candidates) > 0 {
		// Stamped, or stamped but from too few senders to learn yet.
		return false
	}
	if st.LastStamped.IsZero() {
		return st.Examined >= unsupportedAfter
	}
	return st.Examined-lostAt >= unsupportedAfter
}

// Authorize refuses the login of an account whose provider is
// unsupported (Unsupported), with a message the mail client shows.
func Authorize(log *slog.Logger) func(a *engine.Account) error {
	var losses Losses
	return func(a *engine.Account) error {
		st := a.AuthState()
		if !Unsupported(st, losses.LostAt(a.User(), st)) {
			return nil
		}
		log.Error("login refused: the provider does not report DMARC verdicts the bridge can read",
			"user", a.User(), "examined", st.Examined, "last_stamped", st.LastStamped)
		return refusal{&imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeAuthorizationFailed,
			Text: version.Product + " cannot verify senders for this provider: it does not report DMARC results"}}
	}
}

// refusal is an IMAP error that is also engine.ErrLoginRejected, so JMAP
// and ActiveSync refuse the login too, rather than reporting the provider
// unavailable. IMAP clients see the explanation where mailcached passes it
// on.
type refusal struct{ err *imap.Error }

func (r refusal) Error() string { return r.err.Error() }

func (r refusal) Unwrap() error { return r.err }

func (refusal) Is(target error) bool { return target == engine.ErrLoginRejected }

// Losses records, by user, when the bridge first saw an account without
// the stamp it had.
type Losses struct{ m sync.Map }

type loss struct {
	examined    int       // st.Examined then
	lastStamped time.Time // st.LastStamped then: a later one is a new loss
}

// LostAt returns st.Examined when the bridge first saw user's account lose
// the stamp it last had (st.LastStamped), st.Examined if it has one.
func (l *Losses) LostAt(user string, st engine.AuthState) int {
	if len(st.Stamp) > 0 || st.LastStamped.IsZero() {
		l.m.Delete(user)
		return st.Examined
	}
	v, _ := l.m.Load(user)
	if was, ok := v.(loss); ok && was.lastStamped.Equal(st.LastStamped) {
		return was.examined
	}
	l.m.Store(user, loss{st.Examined, st.LastStamped})
	return st.Examined
}
