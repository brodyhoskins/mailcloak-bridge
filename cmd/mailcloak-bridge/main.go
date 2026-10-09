// Command mailcloak-bridge is a local IMAP and SMTP server for mail clients
// that sits in front of any mail provider. It is mailcached with mailcloak
// on top: it decrypts incoming mail and encrypts outgoing mail with
// mailcloak's keys and rules.
//
//	mailcloak-bridge -config /etc/mailcloak/mailcloak.yaml
package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/brodyhoskins/mailcached/config"
	"github.com/brodyhoskins/mailcached/daemon"
	"github.com/brodyhoskins/mailcached/engine"

	"github.com/brodyhoskins/mailcloak-bridge/internal/bridgeconfig"
	"github.com/brodyhoskins/mailcloak-bridge/internal/cloak"
	"github.com/brodyhoskins/mailcloak-bridge/internal/version"
)

// keyCheckInterval is how often the key files are checked for changes.
const keyCheckInterval = 30 * time.Second

func main() {
	var bc *bridgeconfig.Config
	os.Exit(daemon.Main(daemon.Program{
		Name:    version.Product,
		Version: version.String(),
		Files:   bridgeconfig.Files(),
		Load: func(path string) (*config.Config, error) {
			var err error
			if bc, err = bridgeconfig.Load(path); err != nil {
				return nil, err
			}
			return &bc.Config, nil
		},
		Hooks: func(log *slog.Logger) (daemon.Hooks, error) {
			toSelf := *bc.EncryptToSelf
			log.Info("mailcloak settings", "encrypt_mode", bc.Mailcloak.Encrypt.Mode, "encrypt_to_self", toSelf)
			live, err := cloak.NewLive(bc.Mailcloak, toSelf, log)
			if err != nil {
				return daemon.Hooks{}, err
			}
			return daemon.Hooks{
				Transform: live.Transform(toSelf),
				Filter:    live.Filter(),
				// The keys are loaded again when their files change, and
				// held messages are then tried again with them.
				Started: func(eng *engine.Engine) {
					go live.Watch(context.Background(), keyCheckInterval, eng.Recheck)
				},
			}, nil
		},
	}, os.Args[1:], os.Stdout, os.Stderr))
}
