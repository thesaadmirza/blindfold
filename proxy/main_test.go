package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

const fakeRoots = "-----BEGIN CERTIFICATE-----\nZmFrZSByb290\n-----END CERTIFICATE-----\n"

func newWatcher(t *testing.T, policy string) (*policyWatcher, string) {
	t.Helper()
	dir := t.TempDir()
	w := &policyWatcher{
		proxy:  NewProxy(func(Entry) {}, nil),
		path:   filepath.Join(dir, "policy.toml"),
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
	return w, dir
}

func readBundle(t *testing.T, w *policyWatcher) []byte {
	t.Helper()
	b, err := os.ReadFile(w.bundle)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBundleHoldsTheRootsAndTheCA(t *testing.T) {
	w, _ := newWatcher(t, `[secrets.T]`+"\n"+`hosts = ["gitlab.com"]`+"\n"+`header = "X"`)

	if err := w.reload(); err != nil {
		t.Fatal(err)
	}

	b := readBundle(t, w)
	if !bytes.HasPrefix(b, []byte(fakeRoots)) || !bytes.HasSuffix(b, w.ca.PEM()) {
		t.Fatalf("bundle =\n%s", b)
	}
	if info, _ := os.Stat(w.bundle); info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v", info.Mode().Perm())
	}
}

func TestNoPolicyMeansNoCA(t *testing.T) {
	w, _ := newWatcher(t, "")

	if err := w.reload(); err != nil {
		t.Fatal(err)
	}

	if w.ca != nil || string(readBundle(t, w)) != fakeRoots {
		t.Fatalf("ca = %v, bundle = %q", w.ca, readBundle(t, w))
	}
}

func TestBrokenPolicyTurnsInjectionOff(t *testing.T) {
	w, _ := newWatcher(t, `[secrets.T]`+"\n"+`hosts = ["gitlab.com"]`+"\n"+`header = "X"`)
	if err := w.reload(); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(w.path, []byte(`[secrets.T]`+"\n"+`hosts = ["*.gitlab.com"]`+"\n"+`header = "X"`), 0o600)

	if err := w.reload(); err == nil {
		t.Fatal("broken policy loaded without an error")
	}

	if st := w.proxy.state.Load(); st.ca != nil || len(st.policy.Secrets) != 0 {
		t.Fatalf("old rules still active: %+v", st.policy.Secrets)
	}
}
