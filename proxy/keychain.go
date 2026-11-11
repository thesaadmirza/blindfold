package main

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	valueCacheTTL = time.Minute
	missCacheTTL  = 5 * time.Second
)

// keychainLookup reads secrets the way lib.sh stores them, under the account
// PREFIX:SCOPE:NAME, where SCOPE is a project path or "global". Service and
// prefix come from the guard so the two can't drift apart. With a project
// scope, the project's own value wins over a global one, as in lib.sh.
func keychainLookup(keychain, service, accountPrefix string) func(scope, name string) (string, error) {
	read := cachedKeychainRead(keychain, service)
	return func(scope, name string) (string, error) {
		if scope != "" {
			if v, err := read(accountPrefix + ":" + scope + ":" + name); err == nil {
				return v, nil
			}
		}
		return read(accountPrefix + ":global:" + name)
	}
}

// cachedKeychainRead returns one account's value. Values are cached for a
// minute so a burst of requests doesn't run `security` each time, and a
// rotated secret is picked up soon after.
func cachedKeychainRead(keychain, service string) func(account string) (string, error) {
	type entry struct {
		mu    sync.Mutex
		value string
		err   error
		at    time.Time
	}
	var mu sync.Mutex
	entries := map[string]*entry{}

	return func(account string) (string, error) {
		mu.Lock()
		e, ok := entries[account]
		if !ok {
			e = &entry{}
			entries[account] = e
		}
		mu.Unlock()

		// One lock per secret, so a slow keychain read for one never holds
		// up requests that need another
		e.mu.Lock()
		defer e.mu.Unlock()
		ttl := valueCacheTTL
		if e.err != nil {
			ttl = missCacheTTL
		}
		if !e.at.IsZero() && time.Since(e.at) < ttl {
			return e.value, e.err
		}

		args := []string{"find-generic-password", "-a", account, "-s", service, "-w"}
		if keychain != "" {
			args = append(args, keychain)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "security", args...).Output()
		e.value, e.err, e.at = strings.TrimSuffix(string(out), "\n"), nil, time.Now()
		if err != nil {
			e.value, e.err = "", errors.New("not found in the keychain")
		}
		return e.value, e.err
	}
}
