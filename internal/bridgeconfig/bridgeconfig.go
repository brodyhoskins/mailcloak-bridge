// Package bridgeconfig loads the bridge's settings from mailcloak.yaml, the
// file the filters use too. The shared settings (keys, discovery) and
// encrypt: are mailcloak's; bridge: holds mailcached's settings (listeners,
// upstream servers, cache, TLS certificate) and the bridge's own.
package bridgeconfig

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"

	"github.com/brodyhoskins/mailcached/config"
	mcconfig "github.com/brodyhoskins/mailcloak/config"
)

// Files is where the bridge looks for mailcloak.yaml: the -config flag,
// $MAILCLOAK_CONFIG, systemd's $CONFIGURATION_DIRECTORY, the XDG config
// directory (not as root), then mailcloak's DefaultPath, like the filters.
func Files() config.Files {
	return config.Files{Env: "MAILCLOAK_CONFIG", Name: "mailcloak.yaml", XDG: "mailcloak/mailcloak.yaml", Default: mcconfig.DefaultPath}
}

type Config struct {
	config.Config `yaml:",inline"`
	// EncryptToSelf also encrypts outgoing mail to the sender's own key, so
	// the copy a provider saves to Sent stays readable, and encrypts what a
	// client stores (Sent, Drafts) to the sender. Default true.
	EncryptToSelf *bool `yaml:"encrypt_to_self"`
	// Mailcloak is the rest of mailcloak.yaml, with mailcloak's defaults.
	Mailcloak *mcconfig.Config `yaml:"-"`
}

// Load reads path (empty for none) and applies defaults.
func Load(path string) (*Config, error) {
	mc, err := mcconfig.Load(path, "encrypt", mcconfig.Overrides{})
	if err != nil {
		return nil, err
	}
	var c Config
	if err := decode(&mc.Bridge, &c); err != nil {
		return nil, err
	}
	if err := c.Finish(); err != nil {
		return nil, err
	}
	if c.EncryptToSelf == nil {
		t := true
		c.EncryptToSelf = &t
	}
	c.Mailcloak = mc
	return &c, nil
}

// decode decodes the bridge: section into c, rejecting unknown fields like
// the rest of the file. An empty section leaves c unchanged.
func decode(n *yaml.Node, c *Config) error {
	if n.IsZero() {
		return nil
	}
	b, err := yaml.Marshal(n)
	if err != nil {
		return fmt.Errorf("config: bridge: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("config: bridge: %w", err)
	}
	return nil
}
