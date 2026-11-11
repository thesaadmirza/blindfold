package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	fakeRoots   = "-----BEGIN CERTIFICATE-----\nZmFrZSByb290\n-----END CERTIFICATE-----\n"
	validPolicy = "[secrets.T]\nhosts = [\"gitlab.com\"]\nheader = \"X\"\n"
	brokenRule  = "[secrets.T]\nhosts = [\"*.gitlab.com\"]\nheader = \"X\"\n"
)

func newWatcher(t *testing.T, policy string) *policyWatcher {
	t.Helper()
	dir := t.TempDir()
	w := &policyWatcher{
		proxy:  NewProxy(func(Entry) {}, nil),
		path:   filepath.Join(dir, "policy.toml"),
		state:  filepath.Join(dir, "run", "policy.state"),
		bundle: filepath.Join(dir, "run", "ca-bundle.pem"),
		roots:  filepath.Join(dir, "roots.pem"),
	}
	if err := os.WriteFile(w.roots, []byte(fakeRoots), 0o600); err != nil {
		t.Fatal(err)
	}
	if policy != "" {
		if err := os.WriteFile(w.path, []byte(policy), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.reload(); err != nil {
		t.Fatal(err)
	}
	return w
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestBundleHoldsTheRootsAndTheCA(t *testing.T) {
	w := newWatcher(t, validPolicy)

	b := readFile(t, w.bundle)
	ca := w.proxy.state.Load().ca
	if !strings.HasPrefix(b, fakeRoots) || !bytes.HasSuffix([]byte(b), ca.PEM()) {
		t.Fatalf("bundle =\n%s", b)
	}
	if info, _ := os.Stat(w.bundle); info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v", info.Mode().Perm())
	}
	if s := readFile(t, w.state); s != "ok\nT\n" {
		t.Fatalf("state = %q", s)
	}
}

func TestNoPolicyMeansNoCA(t *testing.T) {
	w := newWatcher(t, "")

	if ca := w.proxy.state.Load().ca; ca != nil || readFile(t, w.bundle) != fakeRoots {
		t.Fatalf("ca = %v, bundle = %q", ca, readFile(t, w.bundle))
	}
	if s := readFile(t, w.state); s != "ok\n" {
		t.Fatalf("state = %q", s)
	}
}

func TestBrokenPolicyTurnsInjectionOffAndSaysWhy(t *testing.T) {
	w := newWatcher(t, validPolicy)
	os.WriteFile(w.path, []byte(brokenRule), 0o600)

	if err := w.reload(); err != nil {
		t.Fatal(err)
	}

	if st := w.proxy.state.Load(); st.ca != nil || len(st.policy.Secrets) != 0 {
		t.Fatalf("old rules still active: %+v", st.policy.Secrets)
	}
	if s := readFile(t, w.state); !strings.HasPrefix(s, "error\n") || !strings.Contains(s, "wildcards") {
		t.Fatalf("state = %q", s)
	}
}
