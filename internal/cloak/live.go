package cloak

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/brodyhoskins/mailcached/engine"
	"github.com/brodyhoskins/mailcached/smtpproxy"
	"github.com/brodyhoskins/mailcloak/config"
)

// Live is a Cloak that is built again when its key files change: the PGP
// and S/MIME key directories, the PGP passphrase file and the S/MIME CA
// file. mailcloak loads keys once, so without it a new key would count
// only after a restart.
type Live struct {
	cur   atomic.Pointer[Cloak]
	build func() (*Cloak, error)
	paths []string
	stamp string
	log   *slog.Logger
}

// NewLive builds the Cloak as New does, and remembers how to build it again.
func NewLive(cfg *config.Config, encryptToSelf bool, log *slog.Logger) (*Live, error) {
	l := &Live{
		build: func() (*Cloak, error) { return New(cfg, encryptToSelf, log) },
		paths: []string{cfg.Keys.PGP.Dir, cfg.Keys.PGP.PassphraseFile, cfg.Keys.SMIME.Dir, cfg.Discovery.SMIMECAFile},
		log:   log,
	}
	l.stamp = l.state()
	c, err := l.build()
	if err != nil {
		return nil, err
	}
	l.cur.Store(c)
	return l, nil
}

// Cloak returns the current Cloak.
func (l *Live) Cloak() *Cloak { return l.cur.Load() }

// Transform is Cloak.Transform on the current Cloak, whichever it is when
// a message passes.
func (l *Live) Transform(encryptAppends bool) engine.Transform {
	return &transform{get: l.Cloak, encryptAppends: encryptAppends}
}

// Filter is Cloak.Filter on the current Cloak.
func (l *Live) Filter() smtpproxy.Filter { return filter(l.Cloak) }

// Watch checks the key files every interval until ctx ends. After it built
// the Cloak again, it calls changed. A build that fails keeps the old
// Cloak, and is tried again at the next change.
func (l *Live) Watch(ctx context.Context, interval time.Duration, changed func()) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if !l.Reload() {
			continue
		}
		if changed != nil {
			changed()
		}
	}
}

// Reload builds the Cloak again if the key files changed since the last
// build. It reports whether it did.
func (l *Live) Reload() bool {
	s := l.state()
	if s == l.stamp {
		return false
	}
	l.stamp = s
	c, err := l.build()
	if err != nil {
		l.log.Error("keys changed, but could not be loaded; keeping the previous keys", "err", err)
		return false
	}
	l.cur.Store(c)
	l.log.Info("keys changed and were loaded again")
	return true
}

// state describes the key files: names, sizes and modification times.
func (l *Live) state() string {
	var b strings.Builder
	for _, p := range l.paths {
		if p == "" {
			continue
		}
		fi, err := os.Stat(p)
		if err != nil {
			fmt.Fprintf(&b, "%s: %v\n", p, err)
			continue
		}
		fmt.Fprintf(&b, "%s %d %d\n", p, fi.Size(), fi.ModTime().UnixNano())
		if !fi.IsDir() {
			continue
		}
		entries, _ := os.ReadDir(p)
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, e := range entries {
			if info, err := e.Info(); err == nil {
				fmt.Fprintf(&b, "%s %d %d\n", filepath.Join(p, e.Name()), info.Size(), info.ModTime().UnixNano())
			}
		}
	}
	return b.String()
}
