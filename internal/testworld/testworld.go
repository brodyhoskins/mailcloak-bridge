// Package testworld builds a mailcloak setup for tests: alice is the
// bridge's user with private keys, bob is an outside PGP correspondent.
package testworld

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/brodyhoskins/mailcloak/config"
	"github.com/brodyhoskins/mailcloak/pgp"

	"github.com/brodyhoskins/mailcloak-bridge/internal/cloak"
	"github.com/brodyhoskins/mailcloak-bridge/internal/testkeys"
)

const (
	Alice = "alice@corp.example"
	Bob   = "bob@pgp.example"
)

var Log = slog.New(slog.NewTextHandler(io.Discard, nil))

type World struct {
	Cloak *cloak.Cloak
	// Config is the mailcloak.yaml the Cloak was built from. KeyDir is its
	// PGP key directory, with alice's private key and bob's public key.
	Config *config.Config
	KeyDir string
	// BobPGP holds bob's private key, to read what the bridge sends him.
	BobPGP *pgp.Engine
	// BobKey is bob's key pair, to sign as bob.
	BobKey *openpgp.Entity
}

// New builds the world. encryptToSelf is passed to cloak.New.
func New(t testing.TB, encryptToSelf bool) *World {
	t.Helper()
	ours, theirs := t.TempDir(), t.TempDir()
	alice, bob := testkeys.NewPGP(t, Alice), testkeys.NewPGP(t, Bob)
	writeKey(t, ours, alice, true)
	writeKey(t, ours, bob, false)
	writeKey(t, theirs, bob, true)
	writeKey(t, theirs, alice, false)
	cfgPath := filepath.Join(t.TempDir(), "mailcloak.yaml")
	cfg := fmt.Sprintf("keys:\n  pgp:\n    dir: %s\ndiscovery:\n  wkd: false\n  openpgpkey: false\n  smimea: false\n", ours)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	mc, err := config.Load(cfgPath, "encrypt", config.Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	ck, err := cloak.New(mc, encryptToSelf, Log)
	if err != nil {
		t.Fatal(err)
	}
	bobEngine, err := pgp.Load(theirs, nil, Log)
	if err != nil {
		t.Fatal(err)
	}
	return &World{Cloak: ck, Config: mc, KeyDir: ours, BobPGP: bobEngine, BobKey: bob}
}

// writeKey writes ent into dir, with its secret key if private.
func writeKey(t testing.TB, dir string, ent *openpgp.Entity, private bool) {
	t.Helper()
	var b bytes.Buffer
	var err error
	if private {
		err = ent.SerializePrivate(&b, nil)
	} else {
		err = ent.Serialize(&b)
	}
	if err != nil {
		t.Fatal(err)
	}
	name := ent.PrimaryIdentity().UserId.Email + ".gpg"
	if err := os.WriteFile(filepath.Join(dir, name), b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}
