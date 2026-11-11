package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"sort"
	"strings"
	"sync"
	"time"
)

// intercept terminates TLS for a policy host with a certificate from the local
// CA, then checks and forwards each request on the connection. It is the only
// place a real value is ever put into traffic.
func (p *Proxy) intercept(w http.ResponseWriter, r *http.Request, host string, st *policyState) {
	cert, err := st.ca.leaf(host)
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
		Handler:           p.checkAndInject(host, st.policy.RulesFor(host), forwarder),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	srv.Serve(newOneConnListener(tlsConn))
}

func (p *Proxy) checkAndInject(host string, rules map[string]*Rule, forwarder http.Handler) http.Handler {
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
		used, err := inject(r, rules, p.lookup)
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
	names := make([]string, 0, len(rules))
	for n := range rules {
		names = append(names, n)
	}
	sort.Strings(names)

	var used []string
	for _, name := range names {
		rule, ph := rules[name], placeholder(name)
		var value string
		fill := func(s string) (string, error) {
			if value == "" {
				v, err := lookup(name)
				if err != nil {
					return "", fmt.Errorf("could not read %s: %w", name, err)
				}
				if v == "" {
					return "", fmt.Errorf("%s has no stored value", name)
				}
				value = v
			}
			return strings.ReplaceAll(s, ph, value), nil
		}

		switch {
		case rule.Header != "":
			vals := r.Header.Values(rule.Header)
			if !anyContains(vals, ph) {
				continue
			}
			filled := make([]string, len(vals))
			for i, v := range vals {
				var err error
				if filled[i], err = fill(v); err != nil {
					return used, err
				}
			}
			r.Header[rule.Header] = filled

		case rule.BasicAuth != nil:
			user, pass, ok := r.BasicAuth()
			if !ok || !strings.Contains(pass, ph) {
				continue
			}
			if want := rule.BasicAuth.Username; want != "" && user != want {
				return used, fmt.Errorf("%s may only be used with username %q", name, want)
			}
			pass, err := fill(pass)
			if err != nil {
				return used, err
			}
			r.SetBasicAuth(user, pass)

		case rule.Query != "":
			q := r.URL.Query()
			vals := q[rule.Query]
			if !anyContains(vals, ph) {
				continue
			}
			for i, v := range vals {
				var err error
				if vals[i], err = fill(v); err != nil {
					return used, err
				}
			}
			r.URL.RawQuery = q.Encode()
		}
		used = append(used, name)
	}
	return used, nil
}

func anyContains(vals []string, s string) bool {
	for _, v := range vals {
		if strings.Contains(v, s) {
			return true
		}
	}
	return false
}

// bufferedConn reads through the bufio.Reader the hijack returned, which may
// already hold the start of the TLS handshake
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// oneConnListener hands one connection to an http.Server, then blocks Accept
// until that connection closes so Serve returns when the tunnel is done.
type oneConnListener struct {
	conn net.Conn
	once sync.Once
	done chan struct{}
}

func newOneConnListener(c net.Conn) *oneConnListener {
	return &oneConnListener{conn: c, done: make(chan struct{})}
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = &notifyOnClose{Conn: l.conn, done: l.done} })
	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *oneConnListener) Close() error   { return nil }
func (l *oneConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

type notifyOnClose struct {
	net.Conn
	done chan struct{}
	once sync.Once
}

func (c *notifyOnClose) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.done) })
	return err
}
