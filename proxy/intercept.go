package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"net/http/httputil"
	"slices"
	"strings"
	"time"
)

// intercept terminates TLS for a policy host with a certificate from the local
// CA, then checks and forwards each request on the connection. It is the only
// place a real value is ever put into traffic.
func (p *Proxy) intercept(w http.ResponseWriter, r *http.Request, host string, rules map[string]*Rule, scope string, ca *authority) {
	cert, err := ca.leaf(host)
	if err != nil {
		http.Error(w, "cannot intercept", http.StatusInternalServerError)
		p.log(Entry{Kind: "connect", Host: r.Host, Status: http.StatusInternalServerError, Error: err.Error()}, time.Now())
		return
	}
	client, buffered, err := http.NewResponseController(w).Hijack()
	if err != nil {
		http.Error(w, "cannot tunnel", http.StatusInternalServerError)
		return
	}
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		client.Close()
		return
	}

	tlsConn := tls.Server(&bufferedConn{Conn: client, r: buffered.Reader}, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		// HTTP/1.1 only for now: every client speaks it, and it keeps one
		// request per check simple to reason about
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
	})
	forwarder := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "https"
			pr.Out.URL.Host = host
			pr.Out.Host = host
		},
		Transport: p.transport,
		ErrorLog:  log.New(io.Discard, "", 0),
	}
	srv := &http.Server{
		Handler:           p.checkAndInject(host, rules, scope, forwarder),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	// Serve returns once the listener is drained, but the connection keeps
	// being served on its own goroutine until it closes
	srv.Serve(&oneConnListener{conn: tlsConn})
}

func (p *Proxy) checkAndInject(host string, rules map[string]*Rule, scope string, forwarder http.Handler) http.Handler {
	lookup := func(name string) (string, error) { return p.lookup(scope, name) }
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e := Entry{Kind: "https", Host: host, Method: r.Method}
		start := time.Now()
		defer func() { p.log(e, start) }()

		// The request has to be for the host the tunnel was opened to, or a
		// client could open gitlab.com and then ask for something else
		if target := requestHost(r); target != host {
			e.Status, e.Error = http.StatusMisdirectedRequest, fmt.Sprintf("request for %s inside a tunnel to %s", target, host)
			http.Error(w, "Blindfold: request host does not match the tunnel", e.Status)
			return
		}
		used, err := inject(r, rules, lookup)
		e.Secrets = used
		if err != nil {
			e.Status, e.Error = http.StatusBadGateway, err.Error()
			http.Error(w, "Blindfold: "+err.Error(), e.Status)
			return
		}
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		forwarder.ServeHTTP(rec, r)
		e.Status = rec.status
	})
}

// requestHost is the host a request inside a tunnel asks for, taken from an
// absolute URL if the client sent one, otherwise from the Host header
func requestHost(r *http.Request) string {
	h := r.Host
	if r.URL.Host != "" {
		h = r.URL.Host
	}
	h = strings.ToLower(h)
	if name, port, err := net.SplitHostPort(h); err == nil && port == "443" {
		return name
	}
	return h
}

// inject swaps each secret's placeholder for its value, but only in the one
// slot its rule names. A placeholder anywhere else, such as the body, another
// header or another parameter, is sent as the literal placeholder. Returns the
// names it filled in.
func inject(r *http.Request, rules map[string]*Rule, lookup func(string) (string, error)) ([]string, error) {
	var used []string
	for _, name := range slices.Sorted(maps.Keys(rules)) {
		rule, ph := rules[name], placeholder(name)
		hasPlaceholder := func(v string) bool { return strings.Contains(v, ph) }

		// The slot's current values, and how to put filled ones back
		var vals []string
		var store func([]string)
		switch {
		case rule.Header != "":
			vals = r.Header.Values(rule.Header)
			store = func(v []string) { r.Header[rule.Header] = v }
		case rule.BasicAuth != nil:
			user, pass, ok := r.BasicAuth()
			if !ok {
				continue
			}
			if want := rule.BasicAuth.Username; want != "" && user != want && hasPlaceholder(pass) {
				return used, fmt.Errorf("%s may only be used with username %q", name, want)
			}
			vals = []string{pass}
			store = func(v []string) { r.SetBasicAuth(user, v[0]) }
		case rule.Query != "":
			q := r.URL.Query()
			vals = q[rule.Query]
			store = func(v []string) { q[rule.Query] = v; r.URL.RawQuery = q.Encode() }
		}
		if !slices.ContainsFunc(vals, hasPlaceholder) {
			continue
		}

		value, err := lookup(name)
		if err != nil {
			return used, fmt.Errorf("could not read %s: %w", name, err)
		}
		if value == "" {
			return used, fmt.Errorf("%s has no stored value", name)
		}
		filled := make([]string, len(vals))
		for i, v := range vals {
			filled[i] = strings.ReplaceAll(v, ph, value)
		}
		store(filled)
		used = append(used, name)
	}
	return used, nil
}

// bufferedConn reads through the bufio.Reader the hijack returned, which may
// already hold the start of the TLS handshake
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// oneConnListener hands one connection to an http.Server. Serve calls Accept
// from a single goroutine, so no locking is needed.
type oneConnListener struct{ conn net.Conn }

func (l *oneConnListener) Accept() (net.Conn, error) {
	if c := l.conn; c != nil {
		l.conn = nil
		return c, nil
	}
	return nil, net.ErrClosed
}

func (l *oneConnListener) Close() error   { return nil }
func (l *oneConnListener) Addr() net.Addr { return &net.TCPAddr{} }
