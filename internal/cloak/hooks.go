package cloak

import (
	"context"
	"net/textproto"

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
func (t *transform) Read(ctx context.Context, raw []byte) ([]byte, engine.ReadStatus) {
	d := t.get().DecryptMessage(ctx, raw)
	switch d.Verdict {
	case Done:
		return d.Data, engine.ReadFinal
	case Recheck:
		return d.Data, engine.ReadRetry
	}
	return d.Data, engine.ReadHold
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
