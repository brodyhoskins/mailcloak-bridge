package cloak_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
	"github.com/emersion/go-smtp"

	"github.com/brodyhoskins/mailcached/config"
	"github.com/brodyhoskins/mailcached/engine"
	"github.com/brodyhoskins/mailcached/imapproxy"
	"github.com/brodyhoskins/mailcached/smtpproxy"
	"github.com/brodyhoskins/mailcloak/mimeutil"
	"github.com/brodyhoskins/mailcloak/pgp"

	"github.com/brodyhoskins/mailcloak-bridge/internal/cloak"
	"github.com/brodyhoskins/mailcloak-bridge/internal/testkeys"
	"github.com/brodyhoskins/mailcloak-bridge/internal/testworld"
)

const password = "correct horse"

func plain(from, subject, body string) []byte {
	return []byte("From: " + from + "\r\nTo: " + testworld.Alice + "\r\nSubject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + body + "\r\n")
}

// fromBob is a message bob encrypted to alice and signed.
func fromBob(t *testing.T, w *testworld.World, subject, body string) []byte {
	t.Helper()
	m, err := mimeutil.Parse(plain(testworld.Bob, subject, body))
	if err != nil {
		t.Fatal(err)
	}
	out, err := w.BobPGP.Encrypt(m, []*openpgp.Entity{w.BobPGP.LocalKey(testworld.Alice)}, testworld.Bob)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestChanges checks that every message goes through Read, plain mail
// too, so each one gets X-Mailcloak-Encryption.
func TestChanges(t *testing.T) {
	tr := testworld.New(t, true).Cloak.Transform(true)
	if !tr.Changes(textproto.MIMEHeader{}) {
		t.Error("Changes is false for plain mail")
	}
}

// TestIMAP runs the Transform in mailcached's engine, through its IMAP
// proxy: mail from bob is
// decrypted for alice, a spoofed X-Mailcloak field is removed, and what
// alice stores is encrypted to her before it reaches the provider.
func TestIMAP(t *testing.T) {
	w := testworld.New(t, true)
	e := newEnv(t, w.Cloak.Transform(true), nil)
	provider := login(t, e.provider)
	secret := appendMsg(t, provider, "INBOX", fromBob(t, w, "Quarterly numbers", "The secret number is 42."))
	spoofed := appendMsg(t, provider, "INBOX", append([]byte("X-Mailcloak-Signature: pgp; status=valid\r\nX-Mailcloak-Encryption: pgp\r\nAutocrypt: addr=bob@pgp.example; keydata=AA\r\n"), plain(testworld.Bob, "Fake", "Trust me.")...))

	c := login(t, e.proxy)
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	full := &imap.FetchItemBodySection{Peek: true}
	got := fetch(t, c, secret, full)
	for _, want := range []string{"X-Mailcloak-Encryption: pgp", "X-Mailcloak-Signature: pgp; status=valid; signer=" + testworld.Bob + "\r\n", "The secret number is 42."} {
		if !bytes.Contains(got, []byte(want)) {
			t.Errorf("decrypted message lacks %q:\n%s", want, got)
		}
	}
	if got := fetch(t, c, spoofed, full); bytes.Contains(got, []byte("status=valid")) || bytes.Contains(got, []byte("Encryption: pgp")) {
		t.Errorf("a spoofed X-Mailcloak field reached the client:\n%s", got)
	} else if !bytes.Contains(got, []byte("X-Mailcloak-Encryption: none\r\n")) {
		t.Errorf("plain message lacks X-Mailcloak-Encryption: none:\n%s", got)
	}
	if got := fetch(t, c, spoofed, full); bytes.Contains(got, []byte("Autocrypt:")) {
		t.Errorf("an Autocrypt field reached the client:\n%s", got)
	}

	sent := appendMsg(t, c, "Sent", plain(testworld.Alice, "To bob", "Draft of the secret plan."))
	if _, err := provider.Select("Sent", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	stored := fetch(t, provider, sent, full)
	if m, err := mimeutil.Parse(stored); err != nil || !pgp.IsEncrypted(m) || bytes.Contains(stored, []byte("secret plan")) {
		t.Fatalf("provider stored:\n%s", stored)
	}
	if _, err := c.Select("Sent", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	if got := fetch(t, c, sent, full); !bytes.Contains(got, []byte("Draft of the secret plan.")) {
		t.Fatalf("alice read back:\n%s", got)
	}
}

// TestHoldUntilKey checks the bridge's part of the first-sync rule:
// mail from before the account's first sync that does not decrypt is
// served as the provider has it, and later mail stays hidden until the
// key arrives, then shows up as new mail, decrypted.
func TestHoldUntilKey(t *testing.T) {
	w := testworld.New(t, true)
	aliceKey := filepath.Join(w.KeyDir, testworld.Alice+".gpg")
	saved, err := os.ReadFile(aliceKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(aliceKey); err != nil {
		t.Fatal(err)
	}
	live, err := cloak.NewLive(w.Config, true, testworld.Log)
	if err != nil {
		t.Fatal(err)
	}
	st, err := engine.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	e := newEnv(t, live.Transform(true), st)

	provider := login(t, e.provider)
	appendAt(t, provider, "INBOX", fromBob(t, w, "Old", "From last year."), time.Now().Add(-time.Hour))
	c := login(t, e.proxy)
	a := e.eng.Account(testworld.Alice)
	eventually(t, "the first sync", func() bool { return a.Running() && a.Sweeps() > 0 })
	if a.Since().IsZero() {
		t.Fatal("no cutoff after the first sync")
	}
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	full := &imap.FetchItemBodySection{Peek: true}
	if got := fetchSeq(t, c, 1, full); !bytes.Contains(got, []byte("-----BEGIN PGP MESSAGE-----")) {
		t.Fatalf("old mail that does not decrypt is not served as it is:\n%s", got)
	}

	appendAt(t, provider, "INBOX", fromBob(t, w, "New", "The secret number is 42."), time.Now().Add(time.Minute))
	eventually(t, "the new message to be held", func() bool { return a.Held() == 1 })
	if err := c.Noop().Wait(); err != nil {
		t.Fatal(err)
	}
	if n := c.Mailbox().NumMessages; n != 1 {
		t.Fatalf("INBOX shows %d messages while one is held, want 1", n)
	}

	if err := os.WriteFile(aliceKey, saved, 0o600); err != nil {
		t.Fatal(err)
	}
	if !live.Reload() {
		t.Fatal("Reload missed the key")
	}
	e.eng.Recheck()
	eventually(t, "the held message", func() bool {
		return c.Noop().Wait() == nil && a.Held() == 0 && c.Mailbox().NumMessages == 2
	})
	got := fetchSeq(t, c, 2, full)
	for _, want := range []string{"X-Mailcloak-Encryption: pgp", "The secret number is 42."} {
		if !bytes.Contains(got, []byte(want)) {
			t.Errorf("released message lacks %q:\n%s", want, got)
		}
	}
}

// TestFilter runs the Filter as mailcached's SMTP proxy does: bob gets
// mail he can read, and alice can read the provider's Sent copy only with
// encrypt_to_self.
func TestFilter(t *testing.T) {
	for _, self := range []bool{true, false} {
		w := testworld.New(t, self)
		var got []*smtpproxy.Envelope
		sink := smtpproxy.HandlerFunc(func(_ context.Context, env *smtpproxy.Envelope) error {
			got = append(got, env)
			return nil
		})
		env := &smtpproxy.Envelope{From: testworld.Alice, To: []string{testworld.Bob}, Data: plain(testworld.Alice, "Quarterly numbers", "The secret number is 42.")}
		if err := w.Cloak.Filter()(sink).Handle(t.Context(), env); err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].To[0] != testworld.Bob || bytes.Contains(got[0].Data, []byte("secret number")) {
			t.Fatalf("submitted %+v", got)
		}
		m, err := mimeutil.Parse(got[0].Data)
		if err != nil || !pgp.IsEncrypted(m) {
			t.Fatalf("not PGP/MIME: %v\n%s", err, got[0].Data)
		}
		res, err := w.BobPGP.Decrypt(m)
		if err != nil || !bytes.Contains(res.Message, []byte("secret number is 42")) || res.Signature != pgp.SigValid {
			t.Fatalf("bob: %v, signature %s", err, res.Signature)
		}
		if d := w.Cloak.DecryptMessage(t.Context(), got[0].Data); (d.Verdict != cloak.Hold) != self {
			t.Errorf("encrypt_to_self %v: alice's verdict %v", self, d.Verdict)
		}
	}
}

// TestFilterRefusesEncrypted checks that a message the client encrypted
// itself is refused, permanently, and never reaches the provider.
func TestFilterRefusesEncrypted(t *testing.T) {
	w := testworld.New(t, true)
	sink := smtpproxy.HandlerFunc(func(context.Context, *smtpproxy.Envelope) error {
		t.Error("a message the client encrypted reached the provider")
		return nil
	})
	env := &smtpproxy.Envelope{From: testworld.Bob, To: []string{testworld.Alice}, Data: fromBob(t, w, "Hi", "Hello.")}
	err := w.Cloak.Filter()(sink).Handle(t.Context(), env)
	var se *smtp.SMTPError
	if !errors.As(err, &se) || se.Code/100 != 5 || !strings.Contains(se.Message, "mailcloak-bridge encrypts mail itself") {
		t.Fatalf("got %v, want a permanent SMTP error", err)
	}
}

// env is a provider (go-imap's in-memory server, with alice's INBOX and
// Sent) and mailcached's IMAP proxy in front of it, with tr.
type env struct {
	provider, proxy string
	eng             *engine.Engine
}

// newEnv starts the provider and the proxy. st, if not nil, is the
// engine's database, which the account's first sync and held messages
// need.
func newEnv(t *testing.T, tr engine.Transform, st *engine.Store) *env {
	t.Helper()
	mem := imapmemserver.New()
	u := imapmemserver.NewUser(testworld.Alice, password)
	for _, name := range []string{"INBOX", "Sent"} {
		if err := u.Create(name, nil); err != nil {
			t.Fatal(err)
		}
	}
	mem.AddUser(u)
	up := imapserver.New(&imapserver.Options{
		NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return mem.NewSession(), nil, nil
		},
		Caps:         imap.CapSet{imap.CapIMAP4rev1: {}},
		InsecureAuth: true,
	})
	ul := listen(t)
	go up.Serve(ul)
	t.Cleanup(func() { up.Close() })

	eng := &engine.Engine{
		Store: st,
		Route: func(string) (engine.Upstream, bool) {
			return engine.Upstream{Addr: ul.Addr().String(), TLS: config.TLSNone, Timeout: 5 * time.Second}, true
		},
		Timeout:   5 * time.Second,
		Transform: tr,
		Cache:     &engine.Cache{MaxBytes: 1 << 20},
		Log:       testworld.Log,
	}
	p := &imapproxy.Server{Engine: eng, MaxMessageBytes: 1 << 20, Log: testworld.Log}
	pl := listen(t)
	go p.Serve(pl)
	t.Cleanup(func() { p.Close(); eng.Close() })
	return &env{provider: ul.Addr().String(), proxy: pl.Addr().String(), eng: eng}
}

func listen(t *testing.T) net.Listener {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func login(t *testing.T, addr string) *imapclient.Client {
	t.Helper()
	c, err := imapclient.DialInsecure(addr, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if err := c.Login(testworld.Alice, password).Wait(); err != nil {
		t.Fatal(err)
	}
	return c
}

func appendMsg(t *testing.T, c *imapclient.Client, mailbox string, data []byte) imap.UID {
	t.Helper()
	cmd := c.Append(mailbox, int64(len(data)), nil)
	if _, err := cmd.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Close(); err != nil {
		t.Fatal(err)
	}
	res, err := cmd.Wait()
	if err != nil {
		t.Fatal(err)
	}
	return res.UID
}

func appendAt(t *testing.T, c *imapclient.Client, mailbox string, data []byte, at time.Time) {
	t.Helper()
	cmd := c.Append(mailbox, int64(len(data)), &imap.AppendOptions{Time: at})
	if _, err := cmd.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
}

func eventually(t *testing.T, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for " + what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func fetchSeq(t *testing.T, c *imapclient.Client, seq uint32, section *imap.FetchItemBodySection) []byte {
	t.Helper()
	msgs, err := c.Fetch(imap.SeqSetNum(seq), &imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{section}}).Collect()
	if err != nil || len(msgs) != 1 {
		t.Fatalf("fetch %d: %v, %d messages", seq, err, len(msgs))
	}
	return msgs[0].FindBodySection(section)
}

func fetch(t *testing.T, c *imapclient.Client, uid imap.UID, section *imap.FetchItemBodySection) []byte {
	t.Helper()
	msgs, err := c.Fetch(imap.UIDSetNum(uid), &imap.FetchOptions{UID: true, BodySection: []*imap.FetchItemBodySection{section}}).Collect()
	if err != nil || len(msgs) != 1 {
		t.Fatalf("fetch %d: %v, %d messages", uid, err, len(msgs))
	}
	return msgs[0].FindBodySection(section)
}

// TestLiveReload checks that a key added to the key directory counts
// without a restart: bob's signature is unknown before, and valid after.
func TestLiveReload(t *testing.T) {
	w := testworld.New(t, true)
	bobKey := filepath.Join(w.KeyDir, testworld.Bob+".gpg")
	saved, err := os.ReadFile(bobKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(bobKey); err != nil {
		t.Fatal(err)
	}
	live, err := cloak.NewLive(w.Config, true, testworld.Log)
	if err != nil {
		t.Fatal(err)
	}
	msg := fromBob(t, w, "Hi", "Hello.")
	tr := live.Transform(true)
	if out, _ := tr.Read(t.Context(), msg); !bytes.Contains(out, []byte("status=unknown-key")) {
		t.Fatalf("before: %s", out)
	}
	if live.Reload() {
		t.Fatal("Reload with no change built the keys again")
	}
	if err := os.WriteFile(bobKey, saved, 0o600); err != nil {
		t.Fatal(err)
	}
	if !live.Reload() {
		t.Fatal("Reload missed the new key")
	}
	if out, _ := tr.Read(t.Context(), msg); !bytes.Contains(out, []byte("status=valid")) {
		t.Fatalf("after: %s", out)
	}
}

// pgpSigned is a PGP/MIME signed message (RFC 3156) from bob, signed by
// key.
func pgpSigned(t *testing.T, key *openpgp.Entity, body string) []byte {
	t.Helper()
	entity := "Content-Type: text/plain; charset=utf-8\r\n\r\n" + body + "\r\n"
	var sig bytes.Buffer
	if err := openpgp.ArmoredDetachSign(&sig, key, strings.NewReader(entity), nil); err != nil {
		t.Fatal(err)
	}
	return []byte("From: " + testworld.Bob + "\r\nTo: " + testworld.Alice + "\r\nSubject: Signed\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: multipart/signed; micalg=pgp-sha256; protocol=\"application/pgp-signature\"; boundary=\"b\"\r\n\r\n" +
		"--b\r\n" + entity + "\r\n--b\r\nContent-Type: application/pgp-signature; name=\"signature.asc\"\r\n\r\n" +
		sig.String() + "\r\n--b--\r\n")
}

// TestPGPSignedOnly checks that a PGP signature on mail that is not
// encrypted is checked and removed, whatever the result.
func TestPGPSignedOnly(t *testing.T) {
	w := testworld.New(t, true)
	stranger := testkeys.NewPGP(t, "eve@elsewhere.example")
	for _, tc := range []struct {
		name    string
		msg     []byte
		status  string
		verdict cloak.Verdict
	}{
		{"valid", pgpSigned(t, w.BobKey, "Hello."), "status=valid; signer=" + testworld.Bob, cloak.Done},
		{"tampered", bytes.Replace(pgpSigned(t, w.BobKey, "Hello."), []byte("Hello."), []byte("Bye."), 1), "status=invalid", cloak.Recheck},
		{"unknown key", pgpSigned(t, stranger, "Hello."), "status=unknown-key", cloak.Recheck},
	} {
		d := w.Cloak.DecryptMessage(t.Context(), tc.msg)
		if d.Verdict != tc.verdict || bytes.Contains(d.Data, []byte("pgp-signature")) || bytes.Contains(d.Data, []byte("BEGIN PGP SIGNATURE")) ||
			!bytes.Contains(d.Data, []byte("X-Mailcloak-Signature: pgp; "+tc.status)) {
			t.Errorf("%s: verdict %v:\n%s", tc.name, d.Verdict, d.Data)
		}
	}
}
