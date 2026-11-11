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
	keychainService = "claude-secrets"
	accountPrefix   = "claude-secret:global:"
	valueCacheTTL   = time.Minute
)

// keychainLookup reads global secrets the way lib.sh stores them. Values are
// kept in memory for a minute so a burst of requests doesn't run `security`
// each time, and a rotated secret is picked up soon after.
func keychainLookup(keychain string) func(string) (string, error) {
	type cached struct {
		value string
		at    time.Time
	}
	var mu sync.Mutex
	cache := map[string]cached{}

	return func(name string) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		if c, ok := cache[name]; ok && time.Since(c.at) < valueCacheTTL {
			return c.value, nil
		}

		args := []string{"find-generic-password", "-a", accountPrefix + name, "-s", keychainService, "-w"}
		if keychain != "" {
			args = append(args, keychain)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "security", args...).Output()
		if err != nil {
			return "", errors.New("not found in the keychain")
		}
		value := strings.TrimSuffix(string(out), "\n")
		cache[name] = cached{value, time.Now()}
		return value, nil
	}
}
