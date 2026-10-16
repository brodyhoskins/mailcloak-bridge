package cloak

import (
	"context"
	"net/textproto"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/emersion/go-smtp"

	"github.com/brodyhoskins/mailcached/engine"
	"github.com/brodyhoskins/mailcached/smtpproxy"
	"github.com/brodyhoskins/mailcloak/mimeutil"
	"github.com/brodyhoskins/mailcloak/pgp"
	"github.com/brodyhoskins/mailcloak/pipeline"
	"github.com/brodyhoskins/mailcloak/smime"

	"github.com/brodyhoskins/mailcloak-bridge/internal/version"
)

// Transform returns mailcached's message hook: it decrypts mail on its way to
// clients and, with encryptAppends, encrypts what a client stores (Sent,
// Drafts) to the sender, so the provider never keeps it in the clear.
func (c *Cloak) Transform(encryptAppends bool) engine.Transform {
	return &transform{get: func() *Cloak { return c }, encryptAppends: encryptAppends}
}

type transform struct {
	get            func() *Cloak // the Cloak to use now
	encryptAppends bool
	learning       *atomic.Bool // set on a read while a stamp is learned; nil for none
}

// Fields is empty: Changes needs no fields.
func (*transform) Fields() []string { return nil }

// Changes is true for every message: the bridge labels each one with
// X-Mailcloak-Encryption, plain mail too, so none is served as the
// provider has it.
func (*transform) Changes(textproto.MIMEHeader) bool { return true }

// Read decrypts raw and removes its signatures. The engine shows a held
// message only if it came before the account's first sync; a message after
// it stays hidden until it decrypts with no bad signature.
//
// New crypto mail (isCrypto) is held to more than mailcached in strict
// mode holds other mail to. Without a verdict, it waits in Junk
// (ReadDefer): mailcached brings it back once it learns a stamp, the
// provider's new one too. When DNS failed, it is held until a verdict.
// With a failing verdict (strictFail), or when unwrapping it shows another
// From than the one checked, it goes to Junk. A message the user moved
// back is shown, but its keys are not learned (harvest).
func (t *transform) Read(ctx context.Context, raw []byte) ([]byte, engine.ReadStatus) {
	r, ok := engine.AuthResultFrom(ctx)
	if ok && (r.Learning || lookupFailed(r)) && t.learning != nil {
		// Read again later: Live.Watch rechecks.
		t.learning.Store(true)
	}
	strict := ok && r.New && !r.Rescued && isCrypto(raw)
	if strict {
		switch {
		case lookupFailed(r):
			// Held, and read again every sweep until DNS answers.
			t.get().Log.Info("imap: crypto mail held until the sender's DMARC record can be read", "from", r.From,
				"reason", r.Reason)
			return raw, engine.ReadHold
		case r.Status == engine.AuthUnknown:
			t.get().Log.Info("imap: crypto mail without a verdict waits in Junk", "from", r.From, "reason", r.Reason)
			return raw, engine.ReadDefer
		case strictFail(r):
			t.get().Log.Info("imap: crypto mail failed sender authentication", "from", r.From, "status", r.Status,
				"reason", r.Reason)
			return raw, engine.ReadJunk
		}
	}
	d := t.get().DecryptMessage(ctx, raw)
	if strict && d.Verdict != Hold && onlyFrom(d.Data) != r.From {
		t.get().Log.Info("imap: crypto mail shows another sender than the one checked", "from", r.From)
		return raw, engine.ReadJunk
	}
	switch d.Verdict {
	case Done:
		return d.Data, engine.ReadFinal
	case Recheck:
		return d.Data, engine.ReadRetry
	}
	return d.Data, engine.ReadHold
}

// dmarcLookupFailed starts mailcached's reason for a verdict it could not
// work out because the DNS lookup of the sender's DMARC record failed. It
// is not cached, so a later read may succeed; other unknown verdicts come
// from the message, and stay.
const dmarcLookupFailed = "the sender's DMARC record could not be read"

func lookupFailed(r engine.AuthResult) bool {
	return r.Status == engine.AuthUnknown && strings.HasPrefix(r.Reason, dmarcLookupFailed)
}

// strictFail reports whether a sender check's result is a failure for
// crypto mail. It is stricter than mailcached's for other mail: when the
// From domain publishes no DMARC record, the provider must still have
// found a DKIM signature or an SPF pass for it, as DMARC would ask, or the
// From field is anyone's word, and so are the keys and the encryption that
// come with it. A verdict that names no single sender (several From
// fields) vouches for none.
func strictFail(r engine.AuthResult) bool {
	return r.Status == engine.AuthFail || r.From == "" ||
		r.Status == engine.AuthNoPolicy && !r.DKIMAligned && !r.SPFAligned
}

// isCrypto reports whether raw is crypto mail: encrypted, signed, or with
// an Autocrypt field, whose key the bridge would learn.
func isCrypto(raw []byte) bool {
	m, err := mimeutil.Parse(raw)
	if err != nil {
		return false
	}
	switch mt, _ := m.Header.MediaType(); mt {
	case "multipart/signed", "application/pkcs7-mime", "application/x-pkcs7-mime":
		// Signed, or S/MIME of any kind, opaque signed-data too.
		return true
	}
	return pgp.IsEncrypted(m) || slices.ContainsFunc(m.Header, func(f mimeutil.Field) bool {
		return strings.EqualFold(f.Name, "Autocrypt")
	})
}

func (t *transform) Write(_ context.Context, raw []byte) ([]byte, error) {
	if !t.encryptAppends {
		return raw, nil
	}
	c := t.get()
	out, method, ok, err := c.EncryptToSender(raw)
	switch {
	case err != nil:
		return nil, err
	case ok:
		c.Log.Info("imap: append: encrypted to sender", "method", method)
		return out, nil
	}
	c.Log.Info("imap: append: stored as is (already encrypted, or no key for the sender)")
	return raw, nil
}

// Filter returns mailcached's SMTP hook: mailcloak's encrypt hook, run on
// each message before submission. A message the client encrypted itself
// is refused: the bridge does the encryption, and a client's own could
// use keys the bridge does not have, so it could not read the Sent copy
// or the replies.
func (c *Cloak) Filter() smtpproxy.Filter { return filter(func() *Cloak { return c }) }

// filter is the SMTP hook on the Cloak that get returns for each message.
func filter(get func() *Cloak) smtpproxy.Filter {
	return func(next smtpproxy.Handler) smtpproxy.Handler {
		sink := pipeline.HandlerFunc(func(ctx context.Context, env *pipeline.Envelope) error {
			return next.Handle(ctx, &smtpproxy.Envelope{From: env.From, To: env.To, Data: env.Data})
		})
		return smtpproxy.HandlerFunc(func(ctx context.Context, env *smtpproxy.Envelope) error {
			if m, err := mimeutil.Parse(env.Data); err == nil && (pgp.IsEncrypted(m) || smime.IsEncrypted(m)) {
				get().Log.Warn("smtp: refused a message the client encrypted", "from", env.From)
				return errClientEncrypted
			}
			return get().Encrypt.Middleware(sink).Handle(ctx, &pipeline.Envelope{From: env.From, To: env.To, Data: env.Data})
		})
	}
}

// errClientEncrypted refuses a message the client encrypted. It is
// permanent, so the client shows it instead of trying again.
var errClientEncrypted = &smtp.SMTPError{
	Code: 554, EnhancedCode: smtp.EnhancedCode{5, 7, 1},
	Message: "Turn off encryption in your mail app: " + version.Product + " encrypts mail itself",
}
