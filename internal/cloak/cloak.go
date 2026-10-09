// Package cloak builds mailcloak's encrypt and decrypt hooks from mailcloak's
// config, the same way mailcloak-encrypt and mailcloak-decrypt do,
// and runs them on single messages.
package cloak

import (
	"bytes"
	"context"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/brodyhoskins/mailcloak/config"
	"github.com/brodyhoskins/mailcloak/discover"
	"github.com/brodyhoskins/mailcloak/dnssec"
	"github.com/brodyhoskins/mailcloak/fetch"
	"github.com/brodyhoskins/mailcloak/hooks"
	"github.com/brodyhoskins/mailcloak/mimeutil"
	"github.com/brodyhoskins/mailcloak/pgp"
	"github.com/brodyhoskins/mailcloak/pipeline"
	"github.com/brodyhoskins/mailcloak/smime"

	"github.com/brodyhoskins/mailcloak-bridge/internal/version"
)

// Cloak holds the engines and hooks for one mailcloak config.
type Cloak struct {
	PGP     *pgp.Engine   // nil if keys.pgp.dir is not set
	SMIME   *smime.Engine // nil if keys.smime.dir is not set
	Prefer  []string      // encrypt.prefer
	Encrypt *hooks.Encrypt
	Decrypt *hooks.Decrypt
	// Roots are the CAs a verified S/MIME signature must chain to before
	// the bridge removes it.
	Roots *x509.CertPool
	Log   *slog.Logger

	pgpPublic openpgp.EntityList // the PGP key directory, to verify signatures
}

// New builds the hooks. encryptToSelf sets hooks.Encrypt.EncryptToSelf.
func New(cfg *config.Config, encryptToSelf bool, log *slog.Logger) (*Cloak, error) {
	p, s, err := loadEngines(cfg.Keys, log)
	if err != nil {
		return nil, err
	}
	c := &Cloak{PGP: p, SMIME: s, Prefer: cfg.Encrypt.Prefer, Log: log}
	if c.pgpPublic, err = loadPGPPublic(cfg.Keys.PGP.Dir); err != nil {
		return nil, err
	}

	e := cfg.Encrypt
	var strict []discover.Source
	for _, src := range e.StrictSources {
		strict = append(strict, discover.Source(src))
	}
	keys, err := resolver(cfg, p, s, log)
	if err != nil {
		return nil, err
	}
	c.Encrypt = &hooks.Encrypt{
		PGP:                p,
		SMIME:              s,
		Keys:               keys,
		Prefer:             e.Prefer,
		Mode:               hooks.Mode(e.Mode),
		LocalDomains:       e.LocalDomains,
		StrictSources:      strict,
		AdvertiseAutocrypt: *e.Autocrypt.Advertise,
		PreferEncrypt:      e.Autocrypt.PreferEncrypt,
		EncryptToSelf:      encryptToSelf,
		ProtectHeaders:     *e.HeaderProtection,
		Log:                log,
	}

	c.Decrypt = &hooks.Decrypt{PGP: p, SMIME: s, Log: log}
	d := cfg.Discovery
	if c.Roots, err = smimeRoots(d.SMIMECAFile); err != nil {
		return nil, err
	}
	if d.Autocrypt || *d.SMIMEHarvest {
		c.Decrypt.Harvest = &discover.Harvester{
			Store:     store(cfg),
			Autocrypt: d.Autocrypt,
			SMIME:     *d.SMIMEHarvest,
			Log:       log,
		}
		if *d.SMIMEHarvest {
			if c.Decrypt.Harvest.SMIMERoots, err = smimeRoots(d.SMIMECAFile); err != nil {
				return nil, err
			}
		}
	}
	return c, nil
}

// Verdict says what a decrypt result is good for.
type Verdict int

const (
	// Done: decrypted, or nothing to decrypt, with a valid signature or
	// none. It stays the same, so it can be cached for good.
	Done Verdict = iota
	// Recheck: fit to show, but a later run may give more: a signature
	// from a PGP key the bridge does not have yet, or a signature on
	// unencrypted mail that does not verify (yet).
	Recheck
	// Hold: not fit to show. The message is still encrypted (no key, or
	// the key failed), or it decrypted but its signature is invalid or
	// its S/MIME certificate is not trusted. A later run, after a key or
	// a CA is added, may succeed.
	Hold
)

// Decrypted is the result of running the decrypt hook on one message.
type Decrypted struct {
	Data    []byte
	Verdict Verdict
}

// DecryptMessage runs the decrypt hook on raw, as mailcloak-decrypt would.
func (c *Cloak) DecryptMessage(ctx context.Context, raw []byte) Decrypted {
	var out []byte
	sink := pipeline.HandlerFunc(func(_ context.Context, env *pipeline.Envelope) error {
		out = env.Data
		return nil
	})
	// The decrypt hook never fails: undecryptable mail passes through.
	if err := c.Decrypt.Middleware(sink).Handle(ctx, &pipeline.Envelope{Data: raw}); err != nil || out == nil {
		return Decrypted{Data: raw, Verdict: Hold}
	}
	if stillEncrypted(out) {
		return Decrypted{Data: out, Verdict: Hold}
	}
	m, err := mimeutil.Parse(out)
	if err != nil {
		// The decrypt hook could not parse it either and passed it
		// through: it is served as the provider has it.
		return Decrypted{Data: out, Verdict: Done}
	}
	method := m.Header.Get(hooks.HeaderDecrypted)
	decrypted := method != ""
	// The decrypt hook records the PGP signature it removed with the
	// encryption. A signature inside (S/MIME in S/MIME, or plain signed
	// mail) is removed here. Clients see neither.
	data, inner := c.unwrap(out)
	v := Done
	for _, st := range []string{string(pgpStatus(m.Header.Get(hooks.HeaderSignature))), inner} {
		switch st {
		case "", sigValid, string(pgp.SigNone):
		case sigUnknownKey:
			v = max(v, Recheck)
		default: // invalid or untrusted
			if decrypted {
				v = Hold
			} else {
				v = max(v, Recheck)
			}
		}
	}
	if !decrypted {
		method = encryptionNone
	}
	return Decrypted{Data: c.ownFields(data, method), Verdict: v}
}

// pgpStatus reads the status from an X-Mailcloak-Signature value the
// decrypt hook wrote, such as "pgp; status=valid; signer=…".
func pgpStatus(v string) pgp.SignatureStatus {
	method, rest, _ := strings.Cut(v, ";")
	if strings.TrimSpace(method) != "pgp" {
		return ""
	}
	for _, p := range strings.Split(rest, ";") {
		if k, val, ok := strings.Cut(strings.TrimSpace(p), "="); ok && k == "status" {
			return pgp.SignatureStatus(val)
		}
	}
	return ""
}

// HeaderEncryption says how a message reached the provider: "pgp" or
// "smime" when the bridge decrypted it, encryptionNone when it was not
// encrypted. It takes the place of the decrypt hook's X-Mailcloak-Decrypted,
// which plain mail does not get.
const (
	HeaderEncryption = "X-Mailcloak-Encryption"
	encryptionNone   = "none"
)

// ownFields makes the header clients see. It replaces
// X-Mailcloak-Decrypted with X-Mailcloak-Encryption: method, names a PGP
// signer by address, and removes Autocrypt fields: the decrypt hook has
// learned their keys, and a client that learned them too would encrypt
// its replies, which the bridge refuses. It moves the X-Mailcloak-*
// fields, which the decrypt hook puts first, to the end of the header.
// The bridge is the last to handle the message, so its fields come after
// those of the servers before it, and clients that show the header from
// the top show the sender's fields first.
func (c *Cloak) ownFields(raw []byte, method string) []byte {
	m, err := mimeutil.Parse(raw)
	if err != nil {
		return raw
	}
	own := func(name string) bool { return strings.HasPrefix(strings.ToLower(name), "x-mailcloak-") }
	drop := func(name string) bool {
		return own(name) || strings.EqualFold(name, "Autocrypt") || strings.EqualFold(name, "Autocrypt-Gossip")
	}
	var mine mimeutil.Header
	mine.Add(HeaderEncryption, method)
	for _, f := range m.Header {
		switch {
		case strings.EqualFold(f.Name, hooks.HeaderSignature):
			mine.Add(hooks.HeaderSignature, c.signerByAddress(f.Value()))
		case own(f.Name) && !strings.EqualFold(f.Name, hooks.HeaderDecrypted):
			mine = append(mine, f)
		}
	}
	m.Header = append(m.Header.Without(drop), mine...)
	return m.Bytes()
}

// signerByAddress rewrites the signer in an X-Mailcloak-Signature value
// from the decrypt hook, which names a PGP signer by key fingerprint, to
// the key's address, as the bridge names signers of unencrypted mail. A
// key not in the PGP key directory keeps its fingerprint.
func (c *Cloak) signerByAddress(v string) string {
	ps := strings.Split(v, ";")
	if strings.TrimSpace(ps[0]) != hooks.MethodPGP {
		return v
	}
	for i, p := range ps {
		if k, fpr, ok := strings.Cut(strings.TrimSpace(p), "="); ok && k == "signer" {
			if addr := pgpAddress(c.pgpKey(fpr)); addr != "" {
				ps[i] = " signer=" + addr
			}
		}
	}
	return strings.Join(ps, ";")
}

// pgpKey returns the key in the PGP key directory whose primary key or
// subkey has the fingerprint fpr (hex), or nil.
func (c *Cloak) pgpKey(fpr string) *openpgp.Entity {
	b, err := hex.DecodeString(fpr)
	if err != nil {
		return nil
	}
	for _, e := range c.pgpPublic {
		if bytes.Equal(e.PrimaryKey.Fingerprint, b) {
			return e
		}
		for _, sk := range e.Subkeys {
			if bytes.Equal(sk.PublicKey.Fingerprint, b) {
				return e
			}
		}
	}
	return nil
}

func stillEncrypted(raw []byte) bool {
	m, err := mimeutil.Parse(raw)
	if err != nil {
		return false
	}
	return pgp.IsEncrypted(m) || smime.IsEncrypted(m)
}

// EncryptToSender encrypts raw to its sender's own key, for a copy the
// client stores on the server (Sent, Drafts). The key comes from the local
// key directories, in encrypt.prefer order. ok is false, with raw returned
// unchanged, when the message is already encrypted or the sender has no key.
func (c *Cloak) EncryptToSender(raw []byte) (out []byte, method string, ok bool, err error) {
	m, err := mimeutil.Parse(raw)
	if err != nil {
		return raw, "", false, fmt.Errorf("message could not be parsed: %w", err)
	}
	if pgp.IsEncrypted(m) || smime.IsEncrypted(m) {
		return raw, "", false, nil
	}
	sender := m.Header.FromAddress()
	if sender == "" {
		return raw, "", false, nil
	}
	for _, p := range c.Prefer {
		switch p {
		case hooks.MethodPGP:
			if c.PGP == nil {
				continue
			}
			if k := c.PGP.LocalKey(sender); k != nil {
				out, err := c.PGP.Encrypt(m, []*openpgp.Entity{k}, "")
				return out, p, err == nil, err
			}
		case hooks.MethodSMIME:
			if c.SMIME == nil {
				continue
			}
			if cert := c.SMIME.LocalCert(sender); cert != nil {
				out, err := c.SMIME.Encrypt(m, []*x509.Certificate{cert}, "")
				return out, p, err == nil, err
			}
		}
	}
	return raw, "", false, nil
}

func store(cfg *config.Config) *discover.Store {
	if cfg.StateDir == "" {
		return nil
	}
	return &discover.Store{Dir: filepath.Join(cfg.StateDir, "keys")}
}

func resolver(cfg *config.Config, p *pgp.Engine, s *smime.Engine, log *slog.Logger) (*discover.Resolver, error) {
	d := cfg.Discovery
	r := &discover.Resolver{
		PGP:           p,
		SMIME:         s,
		Store:         store(cfg),
		WKD:           *d.WKD,
		OPENPGPKEY:    *d.OPENPGPKEY,
		SMIMEA:        *d.SMIMEA,
		Keyserver:     d.Keyserver,
		Autocrypt:     d.Autocrypt,
		RequireMutual: *d.AutocryptRequireMutual,
		SMIMEHarvest:  *d.SMIMEHarvest,
		Timeout:       d.Timeout,
		CacheTTL:      d.CacheTTL,
		NegativeTTL:   d.NegativeTTL,
		Log:           log,
	}
	if cfg.NetworkDiscovery() {
		// Every name the bridge resolves goes through the validating
		// resolver, including the hostnames of HTTPS key servers.
		nets, err := cfg.DNS.Networks()
		if err != nil {
			return nil, err
		}
		r.DNS = &dnssec.Resolver{Addr: cfg.DNS.Resolver, ResolvConf: config.ResolvConf, Trusted: nets, Timeout: d.Timeout}
		if _, err := r.DNS.Current(); err != nil {
			log.Warn("key discovery unavailable with the current resolver", "err", err)
		}
		r.HTTP = &fetch.Client{
			HTTP:      &http.Client{Transport: fetch.NewTransport(r.DNS.DialContext), Timeout: d.Timeout},
			MaxBody:   512 << 10,
			UserAgent: version.Token(),
		}
	}
	if *d.SMIMEA {
		var err error
		if r.SMIMERoots, err = smimeRoots(d.SMIMECAFile); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// emailRoots are the roots Mozilla trusts for email (CCADB, "make roots").
// System trust stores on Linux hold the roots trusted for websites only,
// and S/MIME certificates often chain to roots that are not among them.
//
//go:embed emailroots.pem
var emailRoots []byte

// smimeRoots is the system trust store, Mozilla's email roots, and any
// extra CA file.
func smimeRoots(caFile string) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	pool.AppendCertsFromPEM(emailRoots)
	if caFile != "" {
		b, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		if !pool.AppendCertsFromPEM(b) {
			return nil, fmt.Errorf("smime_ca_file %s: no certificates", caFile)
		}
	}
	return pool, nil
}

// loadEngines loads the PGP and S/MIME engines named in keys. Either may be
// nil if its directory is not configured.
func loadEngines(keys config.Keys, log *slog.Logger) (*pgp.Engine, *smime.Engine, error) {
	var p *pgp.Engine
	if dir := keys.PGP.Dir; dir != "" {
		var pass []byte
		if f := keys.PGP.PassphraseFile; f != "" {
			b, err := os.ReadFile(f)
			if err != nil {
				return nil, nil, err
			}
			pass = bytes.TrimRight(b, "\r\n")
		}
		var err error
		if p, err = pgp.Load(dir, pass, log); err != nil {
			return nil, nil, err
		}
	}
	var s *smime.Engine
	if dir := keys.SMIME.Dir; dir != "" {
		var err error
		if s, err = smime.Load(dir, log); err != nil {
			return nil, nil, err
		}
	}
	return p, s, nil
}
