package cloak_test

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"

	"github.com/brodyhoskins/mailcached/engine"
	"github.com/brodyhoskins/mailcloak/discover"

	"github.com/brodyhoskins/mailcloak-bridge/internal/cloak"

	"github.com/brodyhoskins/mailcloak-bridge/internal/testkeys"
	"github.com/brodyhoskins/mailcloak-bridge/internal/testworld"
)

// TestAutocryptNeedsPass checks that an Autocrypt key is learned only
// from mail that passed sender authentication: a forged From must not
// replace a correspondent's key.
func TestAutocryptNeedsPass(t *testing.T) {
	w := testworld.New(t, true)
	store := &discover.Store{Dir: t.TempDir()}
	w.Cloak.Harvest = &discover.Harvester{Store: store, Autocrypt: true, Log: testworld.Log}
	const carol = "carol@ac.example"
	key := testkeys.PublicBytes(t, testkeys.NewPGP(t, carol))
	msg := []byte("Autocrypt: " + discover.FormatAutocrypt(carol, "mutual", key) + "\r\n" +
		"From: " + carol + "\r\nTo: " + testworld.Alice + "\r\nSubject: Hi\r\nDate: Mon, 12 Oct 2026 10:00:00 +0000\r\n" +
		"Content-Type: text/plain\r\n\r\nHello.\r\n")
	learned := func() bool {
		var v map[string]any
		ok, err := store.Get("autocrypt", carol, &v)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}

	for _, ctx := range []context.Context{
		context.Background(), // no check ran
		engine.WithAuthResult(context.Background(), engine.AuthResult{Status: engine.AuthNoPolicy, From: carol}),
		// Several From fields: the pass names no sender.
		engine.WithAuthResult(context.Background(), engine.AuthResult{Status: engine.AuthPass}),
		// A pass for another sender.
		engine.WithAuthResult(context.Background(), engine.AuthResult{Status: engine.AuthPass, From: "dave@ac.example"}),
		// Moved back by the user: vouched for, but not its keys.
		engine.WithAuthResult(context.Background(), engine.AuthResult{Status: engine.AuthPass, From: carol, Rescued: true}),
		// Deleted for its SPF failure after this.
		engine.WithAuthResult(context.Background(), engine.AuthResult{Status: engine.AuthPass, From: carol, SPF: "fail"}),
		engine.WithAuthResult(context.Background(), engine.AuthResult{Status: engine.AuthPass, From: carol, SPF: "softfail"}),
	} {
		w.Cloak.DecryptMessage(ctx, msg)
		if learned() {
			t.Fatalf("learned a key without a pass (%v)", ctx)
		}
	}
	w.Cloak.DecryptMessage(engine.WithAuthResult(context.Background(), engine.AuthResult{Status: engine.AuthPass, From: carol}), msg)
	if !learned() {
		t.Fatal("did not learn the key from mail that passed")
	}
}

// TestCryptoStrict checks that crypto mail is moved away on a weaker
// verdict than other mail, waits in Junk while the stamp is learned, goes
// to Junk without a verdict after, and that other mail is left to
// mailcached.
func TestCryptoStrict(t *testing.T) {
	w := testworld.New(t, true)
	const carol = "carol@x.example"
	tr := w.Cloak.Transform(true)
	plainMsg := []byte("From: carol@x.example\r\nTo: " + testworld.Alice + "\r\nSubject: Hi\r\n\r\nHello.\r\n")
	withAC := append([]byte("Autocrypt: addr=carol@x.example; keydata=AAAA\r\n"), plainMsg...)
	// After an empty Autocrypt field.
	secondAC := append([]byte("Autocrypt: \r\n"), withAC...)
	// Opaque S/MIME signed-data: the signature wraps the content.
	opaque := []byte("From: carol@x.example\r\nTo: " + testworld.Alice + "\r\nSubject: Hi\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: application/pkcs7-mime; smime-type=signed-data; name=smime.p7m\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\nAAAA\r\n")
	for _, c := range []struct {
		name string
		raw  []byte
		r    *engine.AuthResult
		want engine.ReadStatus // or ReadFinal for shown
	}{
		{"crypto, no record, no DKIM", withAC, &engine.AuthResult{New: true, Status: engine.AuthNoPolicy}, engine.ReadJunk},
		{"crypto, no record, aligned DKIM", withAC, &engine.AuthResult{New: true, From: carol, Status: engine.AuthNoPolicy, DKIMAligned: true}, engine.ReadFinal},
		{"crypto, no record, aligned SPF", withAC, &engine.AuthResult{New: true, From: carol, Status: engine.AuthNoPolicy, SPFAligned: true}, engine.ReadFinal},
		{"crypto, fail", withAC, &engine.AuthResult{New: true, Status: engine.AuthFail, DKIMAligned: true}, engine.ReadJunk},
		{"crypto, pass", withAC, &engine.AuthResult{New: true, From: carol, Status: engine.AuthPass}, engine.ReadFinal},
		// Several From fields: the pass names no sender.
		{"crypto, pass, no single From", withAC, &engine.AuthResult{New: true, Status: engine.AuthPass}, engine.ReadJunk},
		// Unwrapped, it shows another From than the one checked.
		{"crypto, pass, another From inside", append([]byte("From: mallory@evil.example\r\n"), withAC...),
			&engine.AuthResult{New: true, From: carol, Status: engine.AuthPass}, engine.ReadJunk},
		{"crypto, no verdict", withAC, &engine.AuthResult{New: true, Status: engine.AuthUnknown, Learning: true}, engine.ReadDefer},
		{"crypto, no stamp on it", withAC, &engine.AuthResult{New: true, Status: engine.AuthUnknown}, engine.ReadDefer},
		{"crypto, DMARC lookup failed", withAC, &engine.AuthResult{New: true, Status: engine.AuthUnknown,
			Reason: "the sender's DMARC record could not be read: i/o timeout"}, engine.ReadHold},
		{"crypto, moved back", withAC, &engine.AuthResult{New: true, Status: engine.AuthPass, Rescued: true}, engine.ReadFinal},
		{"crypto, not checked", withAC, nil, engine.ReadFinal},
		{"second Autocrypt field, no record", secondAC, &engine.AuthResult{New: true, Status: engine.AuthNoPolicy}, engine.ReadJunk},
		{"opaque S/MIME, no record", opaque, &engine.AuthResult{New: true, Status: engine.AuthNoPolicy}, engine.ReadJunk},
		{"plain, no record", plainMsg, &engine.AuthResult{New: true, Status: engine.AuthNoPolicy}, engine.ReadFinal},
		{"plain, fail", plainMsg, &engine.AuthResult{New: true, Status: engine.AuthFail}, engine.ReadFinal},
		{"plain, no verdict", plainMsg, &engine.AuthResult{New: true, Status: engine.AuthUnknown}, engine.ReadRetry},
		// Not new: the verdict is only for the label.
		{"crypto, fail, not new", withAC, &engine.AuthResult{Status: engine.AuthFail}, engine.ReadFinal},
		// Read again once the stamp is known.
		{"plain, not new, learning", plainMsg, &engine.AuthResult{Status: engine.AuthUnknown, Learning: true}, engine.ReadRetry},
		// The provider's new stamp, before it is learned.
		{"plain, not new, no verdict", plainMsg, &engine.AuthResult{Status: engine.AuthUnknown}, engine.ReadRetry},
	} {
		ctx := context.Background()
		if c.r != nil {
			ctx = engine.WithAuthResult(ctx, *c.r)
		}
		if _, st := tr.Read(ctx, c.raw); st != c.want {
			t.Errorf("%s: status %v, want %v", c.name, st, c.want)
		}
	}
}

func TestUnsupported(t *testing.T) {
	stamped := time.Now().Add(-30 * 24 * time.Hour)
	for _, c := range []struct {
		name   string
		st     engine.AuthState
		lostAt int
		want   bool
	}{
		{"stamped", engine.AuthState{Stamp: []string{"mx.example"}, Examined: 100}, 0, false},
		{"learning", engine.AuthState{Examined: 5}, 0, false},
		{"never stamped", engine.AuthState{Examined: 20}, 0, true},
		{"stamped, too few senders", engine.AuthState{Candidates: []string{"mx.example"}, Examined: 20}, 0, false},
		// An idle account whose provider renamed its stamp long after its
		// last stamped message.
		{"stamp just lost", engine.AuthState{Examined: 500, LastStamped: stamped}, 497, false},
		{"stamp gone for good", engine.AuthState{Examined: 500, LastStamped: stamped}, 480, true},
	} {
		if got := cloak.Unsupported(c.st, c.lostAt); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}

// TestLosses checks that a stamp lost, back, and lost again between two
// logins counts from the second loss.
func TestLosses(t *testing.T) {
	var l cloak.Losses
	first := time.Now().Add(-time.Hour)
	if got := l.LostAt("u", engine.AuthState{Examined: 103, LastStamped: first}); got != 103 {
		t.Fatalf("first loss at %d", got)
	}
	if got := l.LostAt("u", engine.AuthState{Examined: 110, LastStamped: first}); got != 103 {
		t.Fatalf("same loss at %d", got)
	}
	// Back through 123, lost again by 126, with no login in between.
	if got := l.LostAt("u", engine.AuthState{Examined: 126, LastStamped: first.Add(time.Minute)}); got != 126 {
		t.Fatalf("second loss at %d", got)
	}
}

// TestAuthenticationLabel checks the X-Mailcloak-Authentication field: the
// verdict and why, and that a sender's own copy of it does not survive.
func TestAuthenticationLabel(t *testing.T) {
	w := testworld.New(t, true)
	const carol = "carol@x.example"
	msg := []byte("X-Mailcloak-Authentication: pass\r\nFrom: carol@x.example\r\nTo: " + testworld.Alice +
		"\r\nSubject: Hi\r\n\r\nHello.\r\n")
	for _, c := range []struct {
		r    *engine.AuthResult
		want string
	}{
		{&engine.AuthResult{Status: engine.AuthFail, DMARC: "fail", DKIM: "pass", DKIMDomains: []string{"evil.example"}, SPF: "fail"},
			"failed; dmarc=fail, dkim=pass (evil.example), spf=fail"},
		{&engine.AuthResult{Status: engine.AuthNoPolicy, From: carol, DMARC: "none", DKIMAligned: true, DKIM: "pass",
			DKIMDomains: []string{"next-tms.com"}, SPF: "pass", SPFDomain: "next-tms.com"},
			"verified; dmarc=none, dkim=pass (next-tms.com), spf=pass (next-tms.com)"},
		{&engine.AuthResult{Status: engine.AuthNoPolicy, From: carol, DMARC: "none", DKIM: "none", SPF: "pass", SPFDomain: "random.example"},
			"unverified; dmarc=none, dkim=none, spf=pass (random.example)"},
		{&engine.AuthResult{Status: engine.AuthPass, From: carol, DMARC: "pass"}, "verified; dmarc=pass"},
		// Several From fields: the pass names no sender.
		{&engine.AuthResult{Status: engine.AuthPass, DMARC: "pass"}, "unknown; dmarc=pass"},
		{&engine.AuthResult{Status: engine.AuthPass, From: carol, DMARC: "pass", SPF: "softfail", SPFDomain: ""}, "failed; dmarc=pass, spf=softfail"},
		{&engine.AuthResult{Status: engine.AuthPass, Rescued: true}, "vouched; moved back by you"},
		{&engine.AuthResult{Status: engine.AuthUnknown, Reason: "no verdict from the provider"}, "unknown; no verdict from the provider"},
		{nil, ""},
	} {
		ctx := context.Background()
		if c.r != nil {
			ctx = engine.WithAuthResult(ctx, *c.r)
		}
		d := w.Cloak.DecryptMessage(ctx, msg)
		got := bytes.Count(d.Data, []byte("X-Mailcloak-Authentication:"))
		line := "X-Mailcloak-Authentication: " + c.want + "\r\n"
		if c.want == "" && got != 0 || c.want != "" && (got != 1 || !bytes.Contains(d.Data, []byte(line))) {
			t.Errorf("want %q:\n%s", c.want, d.Data)
		}
	}
}

// TestAuthenticationLabelFrom checks that a pass for one From field is
// not shown as verified on a message that has another: unwrapping a
// signed message can bring the signed part's own in.
func TestAuthenticationLabelFrom(t *testing.T) {
	w := testworld.New(t, true)
	msg := []byte("From: carol@x.example\r\nFrom: mallory@evil.example\r\nTo: " + testworld.Alice +
		"\r\nSubject: Hi\r\n\r\nHello.\r\n")
	ctx := engine.WithAuthResult(context.Background(), engine.AuthResult{Status: engine.AuthPass, From: "carol@x.example", DMARC: "pass"})
	d := w.Cloak.DecryptMessage(ctx, msg)
	if !bytes.Contains(d.Data, []byte("X-Mailcloak-Authentication: unknown; dmarc=pass\r\n")) {
		t.Errorf("label:\n%s", d.Data)
	}
}

// TestOwnFieldsOrder checks that the bridge's own fields come last, in
// alphabetical order.
func TestOwnFieldsOrder(t *testing.T) {
	w := testworld.New(t, true)
	msg := []byte("From: carol@x.example\r\nTo: " + testworld.Alice + "\r\nSubject: Hi\r\n\r\nHello.\r\n")
	ctx := engine.WithAuthResult(context.Background(), engine.AuthResult{Status: engine.AuthPass, DMARC: "pass"})
	d := w.Cloak.DecryptMessage(ctx, msg)
	hdr, _, _ := bytes.Cut(d.Data, []byte("\r\n\r\n"))
	var names []string
	for _, line := range bytes.Split(hdr, []byte("\r\n")) {
		if name, _, ok := bytes.Cut(line, []byte(":")); ok && bytes.HasPrefix(name, []byte("X-Mailcloak-")) {
			names = append(names, string(name))
		}
	}
	if !slices.IsSorted(names) || len(names) != 2 {
		t.Errorf("fields: %v", names)
	}
}

type stamper struct{ stamp atomic.Pointer[string] }

func (s *stamper) AuthState() engine.AuthState {
	if p := s.stamp.Load(); p != nil {
		return engine.AuthState{Stamp: []string{*p}}
	}
	return engine.AuthState{}
}

func (s *stamper) set(name string) { s.stamp.Store(&name) }

// TestLiveStampLearned checks that Watch rechecks once when a tracked
// account learns its provider's stamp, or a new one, so mail read before
// then gets its verdict.
func TestLiveStampLearned(t *testing.T) {
	w := testworld.New(t, true)
	live, err := cloak.NewLive(w.Config, true, testworld.Log)
	if err != nil {
		t.Fatal(err)
	}
	a := &stamper{}
	live.Track(a)
	rechecks := make(chan struct{}, 10)
	go live.Watch(t.Context(), 5*time.Millisecond, func() { rechecks <- struct{}{} })
	quiet := func(what string) {
		select {
		case <-rechecks:
			t.Fatal("recheck " + what)
		case <-time.After(50 * time.Millisecond):
		}
	}
	recheck := func(what string) {
		select {
		case <-rechecks:
		case <-time.After(time.Second):
			t.Fatal("no recheck " + what)
		}
	}
	quiet("while learning")
	a.set("mx.example")
	recheck("once the stamp was learned")
	quiet("again with the stamp known")
	// The provider's name changed, and the new one was learned between
	// two looks.
	a.set("mx2.example")
	recheck("once a new stamp was learned")
	// The stamp was lost and learned again between two looks, with mail
	// read in between, while another account still learns its own.
	live.Track(&stamper{})
	tr := live.Transform(true)
	ctx := engine.WithAuthResult(context.Background(), engine.AuthResult{Status: engine.AuthUnknown, Learning: true})
	read := func() { tr.Read(ctx, []byte("From: carol@x.example\r\nSubject: Hi\r\n\r\nHello.\r\n")) }
	read()
	recheck("after mail was read while the stamp was learned again")
	quiet("again with nothing read")
	// The other account's mail, read while it learns: no more than one
	// recheck every learningRecheck.
	read()
	quiet("again soon after")
}

// TestAuthorizeRefusal checks that a refused login is a refusal in every
// protocol, and keeps its explanation for IMAP clients.
func TestAuthorizeRefusal(t *testing.T) {
	err := cloak.Refusal("no verdicts")
	var ie *imap.Error
	if !errors.Is(err, engine.ErrLoginRejected) || !errors.As(err, &ie) || ie.Text != "no verdicts" {
		t.Fatalf("%#v", err)
	}
}

// TestLiveLookupFailed checks that mail read while the sender's DMARC
// record could not be looked up is rechecked later.
func TestLiveLookupFailed(t *testing.T) {
	w := testworld.New(t, true)
	live, err := cloak.NewLive(w.Config, true, testworld.Log)
	if err != nil {
		t.Fatal(err)
	}
	a := &stamper{}
	a.set("mx.example")
	live.Track(a)
	rechecks := make(chan struct{}, 10)
	go live.Watch(t.Context(), 5*time.Millisecond, func() { rechecks <- struct{}{} })
	<-rechecks // the stamp, new to Watch
	ctx := engine.WithAuthResult(context.Background(), engine.AuthResult{Status: engine.AuthUnknown,
		Reason: "the sender's DMARC record could not be read: i/o timeout"})
	live.Transform(true).Read(ctx, []byte("From: carol@x.example\r\nSubject: Hi\r\n\r\nHello.\r\n"))
	select {
	case <-rechecks:
	case <-time.After(time.Second):
		t.Fatal("no recheck after a failed lookup")
	}
}
