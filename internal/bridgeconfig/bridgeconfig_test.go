package bridgeconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func load(t *testing.T, yaml string) (*Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "mailcloak.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(p)
}

// base is a mailcloak.yaml without network lookups, so the test needs no
// resolver. Tests append to its bridge: section.
const base = `
keys: {pgp: {dir: /k}}
discovery: {wkd: false, openpgpkey: false, smimea: false}
encrypt: {mode: strict}
bridge:
  tls: {cert_file: /c.pem, key_file: /k.pem}
  imap: {listen: ":993"}
  smtp: {listen: ":465"}
`

func TestDefaults(t *testing.T) {
	c, err := load(t, base)
	if err != nil {
		t.Fatal(err)
	}
	if !*c.EncryptToSelf {
		t.Error("encrypt_to_self defaults to false")
	}
	if c.CacheMaxAge == 0 || !*c.Backfill {
		t.Error("mailcached's defaults were not applied")
	}
}

func TestBridgeSettings(t *testing.T) {
	t.Setenv("MC", "/etc/x")
	c, err := load(t, base+"  encrypt_to_self: false\n  cache_dir: ${MC}/cache\n")
	if err != nil {
		t.Fatal(err)
	}
	if *c.EncryptToSelf {
		t.Error("encrypt_to_self: false was ignored")
	}
	if c.CacheDir != "/etc/x/cache" {
		t.Errorf("cache_dir = %q", c.CacheDir)
	}
	if m := c.Mailcloak; m.Keys.PGP.Dir != "/k" || m.Encrypt.Mode != "strict" {
		t.Errorf("mailcloak: keys.pgp.dir %q, encrypt.mode %q", m.Keys.PGP.Dir, m.Encrypt.Mode)
	}
}

func TestRejects(t *testing.T) {
	for _, tc := range []struct{ yaml, want string }{
		{base + "  bogus: {}\n", "field bogus not found"},
		{base + "bogus: {}\n", "field bogus not found"},
		{base + "  cache_dir: ${MAILCLOAK_BRIDGE_TEST_UNSET}\n", "MAILCLOAK_BRIDGE_TEST_UNSET"},
		{"keys: {pgp: {dir: /k}}\ndiscovery: {wkd: false, openpgpkey: false, smimea: false}\nbridge:\n  imap: {listen: \":993\"}\n", "tls.cert_file"},
		{"bridge:\n  tls: {cert_file: /c.pem, key_file: /k.pem}\n", "no keys configured"},
	} {
		_, err := load(t, tc.yaml)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: err = %v, want %q", tc.yaml, err, tc.want)
		}
	}
}

// TestExample keeps examples/mailcloak.yaml loadable.
func TestExample(t *testing.T) {
	c, err := Load("../../examples/mailcloak.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if u, _, ok := c.Route("smtp", "alice@example.org"); !ok || u.UpstreamTLS != "starttls" {
		t.Errorf("alice@example.org smtp = %+v, %v", u, ok)
	}
}
