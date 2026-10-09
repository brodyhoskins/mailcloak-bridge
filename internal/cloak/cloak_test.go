package cloak

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brodyhoskins/mailcloak/config"
	"github.com/brodyhoskins/mailcloak/hp"
	"github.com/brodyhoskins/mailcloak/mimeutil"
	"github.com/brodyhoskins/mailcloak/smime"

	"github.com/brodyhoskins/mailcloak-bridge/internal/testkeys"
)

const (
	alice = "alice@corp.example"
	carol = "carol@smime.example"
)

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

// setup returns the bridge's Cloak (alice's keys, carol's certificate)
// and carol's own engine, to send from.
func setup(t *testing.T) (*Cloak, *smime.Engine) {
	ours, theirs := t.TempDir(), t.TempDir()
	testkeys.SMIME(t, ours, alice, true)
	testkeys.SMIME(t, theirs, carol, true)
	crt, err := os.ReadFile(filepath.Join(theirs, carol+".crt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ours, carol+".crt"), crt, 0o600); err != nil {
		t.Fatal(err)
	}
	crt, err = os.ReadFile(filepath.Join(ours, alice+".crt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(theirs, alice+".crt"), crt, 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(t.TempDir(), "mailcloak.yaml")
	cfg := fmt.Sprintf("keys:\n  smime:\n    dir: %s\ndiscovery:\n  wkd: false\n  openpgpkey: false\n  smimea: false\n  smime_harvest: false\n", ours)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	mc, err := config.Load(cfgPath, "encrypt", config.Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	ck, err := New(mc, true, discard)
	if err != nil {
		t.Fatal(err)
	}
	sender, err := smime.Load(theirs, discard)
	if err != nil {
		t.Fatal(err)
	}
	return ck, sender
}

func message(t *testing.T) *mimeutil.Message {
	raw := "From: " + carol + "\r\nTo: " + alice + "\r\nSubject: hi\r\nMessage-ID: <1@smime.example>\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n\r\nThe secret plan.\r\n"
	m, err := mimeutil.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// TestUnwrapSignature checks that every signature is removed and recorded
// in a header, so clients never see one, and that a decrypted message with
// a signature the bridge cannot trust is held.
func TestUnwrapSignature(t *testing.T) {
	ck, sender := setup(t)
	enc, err := sender.Encrypt(message(t), []*x509.Certificate{ck.SMIME.LocalCert(alice)}, carol)
	if err != nil {
		t.Fatal(err)
	}

	// Carol's certificate is self-signed: it does not chain to the roots.
	d := ck.DecryptMessage(context.Background(), enc)
	if d.Verdict != Hold || bytes.Contains(d.Data, []byte("smime.p7s")) || !bytes.Contains(d.Data, []byte("X-Mailcloak-Signature: smime; status=untrusted; signer="+carol)) {
		t.Fatalf("untrusted signature: verdict %v:\n%s", d.Verdict, d.Data)
	}

	ck.Roots = x509.NewCertPool()
	ck.Roots.AddCert(ck.SMIME.LocalCert(carol))
	d = ck.DecryptMessage(context.Background(), enc)
	if d.Verdict != Done {
		t.Errorf("trusted signature: verdict %v", d.Verdict)
	}
	m, err := mimeutil.Parse(d.Data)
	if err != nil {
		t.Fatal(err)
	}
	if mt, _ := m.Header.MediaType(); mt != "text/plain" || !strings.Contains(string(m.Body), "The secret plan.") {
		t.Errorf("unwrapped message = %s:\n%s", mt, d.Data)
	}
	if got, want := m.Header.Get("X-Mailcloak-Signature"), "smime; status=valid; signer="+carol; got != want {
		t.Errorf("X-Mailcloak-Signature = %q, want %q", got, want)
	}
	if m.Header.Get("Subject") != "hi" || m.Header.Get("X-Mailcloak-Encryption") != "smime" || m.Header.Get("X-Mailcloak-Decrypted") != "" {
		t.Errorf("headers lost:\n%s", d.Data)
	}
	// The bridge's own fields come last.
	if n := len(m.Header); n < 3 || !strings.HasPrefix(m.Header[n-1].Name, "X-Mailcloak-") || !strings.HasPrefix(m.Header[n-2].Name, "X-Mailcloak-") {
		t.Errorf("X-Mailcloak fields are not last:\n%s", m.Header.Bytes())
	}

	// A changed signed-only message loses its signature too. It is shown,
	// with the status recorded, and checked again later.
	signed, err := sender.Sign(message(t), carol)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(signed, []byte("secret plan"), []byte("public plan"), 1)
	if d := ck.DecryptMessage(context.Background(), tampered); d.Verdict != Recheck || bytes.Contains(d.Data, []byte("smime.p7s")) ||
		!bytes.Contains(d.Data, []byte("status=invalid")) {
		t.Errorf("bad signature: verdict %v:\n%s", d.Verdict, d.Data)
	}
	// An untouched signed-only message is unwrapped too.
	if d := ck.DecryptMessage(context.Background(), signed); d.Verdict != Done || bytes.Contains(d.Data, []byte("smime.p7s")) {
		t.Errorf("valid signature on a signed-only message: verdict %v:\n%s", d.Verdict, d.Data)
	}
}

// TestHeaderProtection checks that the Subject inside signed and
// encrypted S/MIME mail (RFC 9788) replaces the one outside, which a server
// on the way tagged, and that a signed part cannot add the bridge's fields.
func TestHeaderProtection(t *testing.T) {
	ck, sender := setup(t)
	ck.Roots = x509.NewCertPool()
	ck.Roots.AddCert(ck.SMIME.LocalCert(carol))
	m := message(t)
	m.Header = append(m.Header[:len(m.Header):len(m.Header)], mimeutil.Field{Name: "X-Mailcloak-Encryption", Raw: "X-Mailcloak-Encryption: none\r\n"})
	outer, entity := hp.Protect(m)
	enc, err := sender.EncryptEntity(outer, entity, []*x509.Certificate{ck.SMIME.LocalCert(alice)}, carol)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(enc, []byte("Subject: hi")) {
		t.Fatalf("Subject not hidden:\n%s", enc)
	}
	enc = bytes.Replace(enc, []byte("Subject: [...]"), []byte("Subject: ***UNCHECKED*** [...]"), 1)

	d := ck.DecryptMessage(context.Background(), enc)
	if d.Verdict != Done {
		t.Errorf("verdict %v", d.Verdict)
	}
	got, err := mimeutil.Parse(d.Data)
	if err != nil {
		t.Fatal(err)
	}
	if s := got.Header.Get("Subject"); s != "hi" || bytes.Count(d.Data, []byte("Subject:")) != 1 {
		t.Errorf("Subject = %q:\n%s", s, d.Data)
	}
	if bytes.Count(d.Data, []byte("X-Mailcloak-Encryption:")) != 1 || got.Header.Get("X-Mailcloak-Encryption") != "smime" {
		t.Errorf("X-Mailcloak-Encryption:\n%s", d.Data)
	}
	if bytes.Contains(d.Data, []byte("HP-Outer")) || !strings.HasPrefix(string(got.Body), "The secret plan.") {
		t.Errorf("payload not unwrapped:\n%s", d.Data)
	}
}

// TestEmailRoots checks that the embedded roots parse and hold an
// email-only root that system stores on Linux leave out.
func TestEmailRoots(t *testing.T) {
	found := false
	n := 0
	for rest := emailRoots; ; {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		n++
		found = found || c.Subject.CommonName == "Sectigo Public Email Protection Root R46"
	}
	if n < 50 || !found {
		t.Errorf("%d roots, Sectigo email root found: %v", n, found)
	}
}
