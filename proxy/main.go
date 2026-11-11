// Command blindfold-proxy is the local proxy that sandboxed commands send
// their network traffic through. It tunnels traffic and logs where it goes,
// and for hosts a policy names it puts each secret's real value in place of
// its placeholder. See docs/design/destination-binding.md.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:0", "loopback address to listen on")
	portFile := flag.String("port-file", "", "write the chosen port to this file (mode 600)")
	logPath := flag.String("log", "", "append one JSON line per connection to this file")
	auditPath := flag.String("audit", "", "append one JSON line per secret used or refused to this file")
	policyPath := flag.String("policy", "", "policy file saying where each secret may go")
	stateFile := flag.String("state", "", "write the loaded policy's secret names, or its error, to this file")
	private := flag.String("private", "", "folder with project tokens and approved project policies")
	check := flag.String("check", "", "check this policy file, print the secret names it covers and exit")
	dialog := flag.String("dialog", "", "show a dialog with these comma-separated buttons, the first being the safe one, reading the message from stdin; print the button clicked, or nothing")
	dialogWait := flag.Duration("dialog-timeout", dialogTimeout, "how long -dialog waits for an answer")
	bundlePath := flag.String("ca-bundle", "", "write the system roots plus the local CA to this file")
	systemRoots := flag.String("system-roots", "/etc/ssl/cert.pem", "PEM file with the roots clients normally trust")
	keychain := flag.String("keychain", "", "keychain to read secrets from (default: the login keychain)")
	service := flag.String("service", "claude-secrets", "keychain service secrets are stored under")
	accountPrefix := flag.String("account-prefix", "claude-secret", "keychain accounts are PREFIX:SCOPE:NAME")
	flag.Parse()

	if *dialog != "" {
		msg, _ := io.ReadAll(os.Stdin)
		fmt.Println(showDialog(context.Background(), string(msg), strings.Split(*dialog, ","), *dialogWait))
		return
	}

	if *check != "" {
		// Not LoadPolicy: a missing file is an error here, not an empty policy
		data, err := os.ReadFile(*check)
		var pol *Policy
		if err == nil {
			pol, err = ParsePolicy(data)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(strings.Join(pol.Names(), "\n"))
		return
	}

	ln, err := listenLoopback(*listen)
	if err != nil {
		log.Fatal(err)
	}
	record, err := openJSONL[Entry](*logPath)
	if err != nil {
		log.Fatal(err)
	}
	audit, err := openJSONL[AuditEntry](*auditPath)
	if err != nil {
		log.Fatal(err)
	}
	proxy := NewProxy(record, keychainLookup(*keychain, *service, *accountPrefix))
	proxy.audit = audit
	w := &policyWatcher{proxy: proxy, path: *policyPath, private: *private, state: *stateFile, bundle: *bundlePath, roots: *systemRoots}
	// The state and bundle have to exist before the port file says the proxy is up
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

// policyWatcher reloads the policies when their files change, and stops the
// proxy when its own binary is rebuilt so the guard starts the new one
type policyWatcher struct {
	proxy   *Proxy
	path    string
	private string
	state   string
	bundle  string
	roots   string
	seen    string // stamp of every policy file at the last load
}

func (w *policyWatcher) stamp() string { return stamp(w.path) + "#" + projectsStamp(w.private) }

// stamp changes whenever a file is written, replaced or removed
func stamp(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return "missing"
	}
	return fmt.Sprint(info.Size(), info.ModTime().UnixNano())
}

// watch polls for changes, and reloads at once on SIGHUP, which the approval
// script sends so a project approved a moment ago is live by the agent's retry
func (w *policyWatcher) watch(every time.Duration) {
	self, _ := os.Executable()
	built := stamp(self)
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	tick := time.NewTicker(every)
	for {
		select {
		case <-tick.C:
			if self != "" && stamp(self) != built {
				os.Exit(0)
			}
			if w.stamp() == w.seen {
				continue
			}
		case <-hup:
		}
		if err := w.reload(); err != nil {
			log.Print(err)
		}
	}
}

// reload applies the policy file and writes what it loaded to the state file,
// which the guard reads, so the guard and the proxy never disagree about the
// policy. A policy that doesn't load turns injection off until it's fixed,
// rather than keeping rules the user meant to change. The error returned is
// only for files the proxy couldn't write.
func (w *policyWatcher) reload() error {
	w.seen = w.stamp()
	pol, loadErr := LoadPolicy(w.path)
	if loadErr != nil {
		log.Print(loadErr)
		pol = &Policy{}
	}
	projects := loadProjects(w.private)
	ca, err := w.proxy.SetPolicies(pol, projects)
	if err != nil {
		return err
	}
	if w.bundle != "" {
		if err := writeBundle(w.bundle, w.roots, ca); err != nil {
			return err
		}
	}
	if w.state == "" {
		return nil
	}
	state := "ok\n"
	if loadErr != nil {
		state = "error\n" + loadErr.Error() + "\n"
	}
	for _, name := range pol.Names() {
		state += name + "\n"
	}
	// "@id NAME..." for each approved project in effect. The guard takes a
	// project's placeholders from here, so it never exports one the proxy
	// hasn't loaded.
	var lines []string
	for _, p := range projects {
		lines = append(lines, "@"+strings.Join(append([]string{p.ID}, p.Policy.Names()...), " "))
	}
	slices.Sort(lines)
	for _, l := range lines {
		state += l + "\n"
	}
	return writeFileAtomic(w.state, []byte(state))
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

// openJSONL returns a recorder that appends one JSON line per value to path.
// An empty path records nothing.
func openJSONL[T any](path string) (func(T), error) {
	if path == "" {
		return func(T) {}, nil
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
	return func(v T) {
		mu.Lock()
		defer mu.Unlock()
		if err := enc.Encode(v); err != nil {
			log.Printf("%s: %v", path, err)
		}
	}, nil
}
