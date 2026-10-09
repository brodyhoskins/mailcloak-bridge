package cloak

import (
	"bytes"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	pgperrors "github.com/ProtonMail/go-crypto/openpgp/errors"

	"github.com/brodyhoskins/mailcloak/hooks"
	"github.com/brodyhoskins/mailcloak/hp"
	"github.com/brodyhoskins/mailcloak/mimeutil"
	"github.com/brodyhoskins/mailcloak/pgp"
	"github.com/brodyhoskins/mailcloak/smime"
)

// Signature statuses the bridge records in X-Mailcloak-Signature. PGP
// signatures removed by decryption get mailcloak's own (pgp.SigValid and
// the others), which use the same words.
const (
	sigValid      = "valid"
	sigInvalid    = "invalid"     // the signature does not match the message
	sigUntrusted  = "untrusted"   // S/MIME: the certificate does not chain to a trusted CA
	sigUnknownKey = "unknown-key" // PGP: the bridge does not have the signer's key
)

// unwrap removes a multipart/signed layer, PGP or S/MIME, whether or not
// the signature verifies, and records the result in X-Mailcloak-Signature.
// Clients never see a signature: the bridge checks it for them. status is
// "" when raw has no signature, and sigInvalid when one is there but
// cannot be taken apart; raw is then returned unchanged.
func (c *Cloak) unwrap(raw []byte) (out []byte, status string) {
	m, err := mimeutil.Parse(raw)
	if err != nil {
		return raw, ""
	}
	mt, params := m.Header.MediaType()
	if mt != "multipart/signed" {
		return raw, ""
	}
	var method, who string
	switch proto := strings.ToLower(params["protocol"]); proto {
	case "application/pkcs7-signature", "application/x-pkcs7-signature":
		method = hooks.MethodSMIME
		// The signature first, then the chain, so an untrusted signer is
		// still named.
		var signer *x509.Certificate
		var chain []*x509.Certificate
		if signer, chain, err = smime.VerifySigned(m, nil); err == nil {
			err = c.chains(signer, chain)
		}
		status = smimeStatus(err)
		if signer != nil {
			who = signer.Subject.CommonName
			if len(signer.EmailAddresses) > 0 {
				who = signer.EmailAddresses[0]
			}
		}
	case "application/pgp-signature":
		method = hooks.MethodPGP
		status, who = c.verifyPGP(m, params["boundary"])
	default:
		return raw, ""
	}
	if status != sigValid {
		c.Log.Info("decrypt: signature removed, not valid", "method", method, "status", status, "err", err)
	}
	signed, ok := signedEntity(m, params["boundary"])
	if !ok {
		return raw, sigInvalid
	}
	value := method + "; status=" + status
	if who != "" {
		value += "; signer=" + who
	}
	var h mimeutil.Header
	h.Add(hooks.HeaderSignature, value)
	outer, _ := m.SplitEntity()
	// The signed entity can carry header fields (Header Protection). They
	// take the place of those outside, but cannot speak for the bridge.
	sm, err := mimeutil.Parse(signed)
	if err != nil {
		return raw, sigInvalid
	}
	sm.Header = sm.Header.Without(func(n string) bool { return strings.HasPrefix(strings.ToLower(n), "x-mailcloak-") })
	out, err = hp.Unprotect(append(h, outer...), sm.Bytes())
	if err != nil {
		return raw, sigInvalid
	}
	return out, status
}

// chains checks that signer chains to Roots and may sign email, as
// smime.VerifySigned does when given roots.
func (c *Cloak) chains(signer *x509.Certificate, chain []*x509.Certificate) error {
	inter := x509.NewCertPool()
	for _, cert := range chain {
		inter.AddCert(cert)
	}
	_, err := signer.Verify(x509.VerifyOptions{
		Roots: c.Roots, Intermediates: inter,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
	})
	return err
}

// smimeStatus turns a verification error into a status.
func smimeStatus(err error) string {
	var unknown x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	switch {
	case err == nil:
		return sigValid
	case errors.As(err, &unknown), errors.As(err, &invalid):
		return sigUntrusted
	}
	return sigInvalid
}

// parts splits a multipart/signed body into the signed entity and the
// signature part.
func parts(m *mimeutil.Message, boundary string) (signed, sig []byte, ok bool) {
	p := bytes.Split(m.Body, []byte("--"+boundary))
	// p: preamble, signed entity, signature part, epilogue ("--").
	if boundary == "" || len(p) < 3 {
		return nil, nil, false
	}
	// The CRLF before each delimiter belongs to the delimiter.
	trim := func(b []byte) []byte {
		return bytes.TrimSuffix(bytes.TrimPrefix(b, []byte("\r\n")), []byte("\r\n"))
	}
	return trim(p[1]), trim(p[2]), true
}

func signedEntity(m *mimeutil.Message, boundary string) ([]byte, bool) {
	signed, _, ok := parts(m, boundary)
	return signed, ok
}

// verifyPGP checks a PGP/MIME signature (RFC 3156) against the public
// keys in the PGP key directory.
func (c *Cloak) verifyPGP(m *mimeutil.Message, boundary string) (status, who string) {
	signed, sigPart, ok := parts(m, boundary)
	if !ok {
		return sigInvalid, ""
	}
	sm, err := mimeutil.Parse(sigPart)
	if err != nil {
		return sigInvalid, ""
	}
	signer, err := openpgp.CheckArmoredDetachedSignature(c.pgpPublic, bytes.NewReader(signed), bytes.NewReader(sm.Body), nil)
	switch {
	case errors.Is(err, pgperrors.ErrUnknownIssuer):
		return sigUnknownKey, ""
	case err != nil:
		return sigInvalid, ""
	}
	return sigValid, pgpAddress(signer)
}

// pgpAddress returns the email address of key's primary identity, else
// of any identity, or "" for a nil key or one without an address.
func pgpAddress(key *openpgp.Entity) string {
	if key == nil {
		return ""
	}
	if id := key.PrimaryIdentity(); id != nil && id.UserId != nil && id.UserId.Email != "" {
		return id.UserId.Email
	}
	for _, id := range key.Identities {
		if id.UserId != nil && id.UserId.Email != "" {
			return id.UserId.Email
		}
	}
	return ""
}

// loadPGPPublic reads the public keys in the PGP key directory, as
// pgp.Load does, to verify signatures on mail that is not encrypted.
func loadPGPPublic(dir string) (openpgp.EntityList, error) {
	if dir == "" {
		return nil, nil
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var all openpgp.EntityList
	for _, f := range files {
		switch strings.ToLower(filepath.Ext(f.Name())) {
		case ".asc", ".gpg", ".pgp":
		default:
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, f.Name()))
		if err != nil {
			return nil, err
		}
		ents, err := pgp.ParseKeys(b)
		if err != nil {
			return nil, err
		}
		all = append(all, ents...)
	}
	return all, nil
}
