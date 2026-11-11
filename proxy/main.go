// Command blindfold-proxy is the local proxy that sandboxed commands send
// their network traffic through. It tunnels traffic and logs where it goes,
// and for hosts a policy names it puts each secret's real value in place of
// its placeholder. See docs/design/destination-binding.md.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:0", "loopback address to listen on")
	portFile := flag.String("port-file", "", "write the chosen port to this file (mode 600)")
	logPath := flag.String("log", "", "append one JSON line per connection to this file")
	policyPath := flag.String("policy", "", "policy file saying where each secret may go")
	bundlePath := flag.String("ca-bundle", "", "write the system roots plus the local CA to this file")
	systemRoots := flag.String("system-roots", "/etc/ssl/cert.pem", "PEM file with the roots clients normally trust")
	keychain := flag.String("keychain", "", "keychain to read secrets from (default: the login keychain)")
	printSecrets := flag.Bool("print-secrets", false, "check the policy, print the secret names it covers and exit")
	flag.Parse()

	if *printSecrets {
		pol, err := LoadPolicy(*policyPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		for _, name := range pol.Names() {
			fmt.Println(name)
		}
		return
	}

	ln, err := listenLoopback(*listen)
	if err != nil {
		log.Fatal(err)
	}
	record, err := openEgressLog(*logPath)
	if err != nil {
		log.Fatal(err)
	}
	proxy := NewProxy(record, keychainLookup(*keychain))
	w := &policyWatcher{proxy: proxy, path: *policyPath, bundle: *bundlePath, roots: *systemRoots}
	// The bundle has to exist before the port file says the proxy is up
	if err := w.reload(); err != nil {
		log.Fatal(err)
	}
	go w.watch(time.Second)
	if *portFile != "" {
		port := ln.Addr().(*net.TCPAddr).Port
		if err := writePortFile(*portFile, port); err != nil {
			log.Fatal(err)
		}
	}

	srv := &http.Server{
		Handler:           proxy,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	log.Fatal(srv.Serve(ln))
}

// policyWatcher reloads the policy when its file changes and rewrites the CA
// bundle when that changes the CA
type policyWatcher struct {
	proxy  *Proxy
	path   string
	bundle string
	roots  string
	seen   string // size and mtime of the file at the last load
	ca     *authority
}

func (w *policyWatcher) stamp() string {
	info, err := os.Stat(w.path)
	if err != nil {
		return "missing"
	}
	return fmt.Sprint(info.Size(), info.ModTime().UnixNano())
}

func (w *policyWatcher) watch(every time.Duration) {
	for range time.Tick(every) {
		if w.stamp() != w.seen {
			if err := w.reload(); err != nil {
				log.Print(err)
			}
		}
	}
}

// reload applies the policy file. A policy that doesn't load turns injection
// off until it's fixed, rather than keeping rules the user meant to change.
func (w *policyWatcher) reload() error {
	w.seen = w.stamp()
	pol, loadErr := LoadPolicy(w.path)
	if loadErr != nil {
		pol = &Policy{}
	}
	ca, err := w.proxy.SetPolicy(pol)
	if err != nil {
		return err
	}
	if w.bundle != "" && (ca != w.ca || ca == nil) {
		if err := writeBundle(w.bundle, w.roots, ca); err != nil {
			return err
		}
	}
	w.ca = ca
	return loadErr
}

// writeBundle writes the usual roots plus the local CA, for SSL_CERT_FILE and
// friends inside the sandbox. The CA is never added to the system trust store.
func writeBundle(path, roots string, ca *authority) error {
	pem, err := os.ReadFile(roots)
	if err != nil {
		return fmt.Errorf("reading system roots: %w", err)
	}
	if ca != nil {
		pem = append(bytes.TrimRight(pem, "\n"), '\n')
		pem = append(pem, ca.PEM()...)
	}
	return writeFileAtomic(path, pem)
}

// listenLoopback refuses any address that isn't loopback, so the proxy is
// never reachable from the network.
func listenLoopback(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	if ip := ln.Addr().(*net.TCPAddr).IP; !ip.IsLoopback() {
		ln.Close()
		return nil, fmt.Errorf("refusing to listen on %s: not a loopback address", ln.Addr())
	}
	return ln, nil
}

func writePortFile(path string, port int) error {
	return writeFileAtomic(path, []byte(strconv.Itoa(port)+"\n"))
}

// writeFileAtomic writes through a temp file and a rename, so a reader never
// sees a half-written file. The file ends up with mode 0600.
func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	// os.CreateTemp already creates the file with mode 0600
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// openEgressLog returns a recorder that appends JSON lines to path. An empty
// path records nothing.
func openEgressLog(path string) (func(Entry), error) {
	if path == "" {
		return func(Entry) {}, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	var mu sync.Mutex
	enc := json.NewEncoder(f)
	return func(e Entry) {
		mu.Lock()
		defer mu.Unlock()
		if err := enc.Encode(e); err != nil {
			log.Printf("egress log: %v", err)
		}
	}, nil
}
