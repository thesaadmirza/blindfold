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
func (p *Proxy) intercept(w http.ResponseWriter, r *http.Request, host string, rules map[string]*Rule, scopes map[string]string, ca *authority) {
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
	srv := &http.Server{
		Handler:           p.checkAndInject(host, rules, scopes),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	// Serve returns once the listener is drained, but the connection keeps
	// being served on its own goroutine until it closes
	srv.Serve(&oneConnListener{conn: tlsConn})
}

func (p *Proxy) checkAndInject(host string, rules map[string]*Rule, scopes map[string]string) http.Handler {
	lookup := func(name string) (string, error) { return p.lookup(scopes[name], name) }
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e := Entry{Kind: "https", Host: host, Method: r.Method}
		start := time.Now()
		defer func() { p.log(e, start) }()
		audit := func(decision, name string, status int, detail string) {
			p.auditLog(AuditEntry{Decision: decision, Secret: name, Project: scopes[name], Method: r.Method,
				Host: host, Path: r.URL.Path, Status: status, Detail: detail})
		}

		// The request has to be for the host the tunnel was opened to, or a
		// client could open gitlab.com and then ask for something else
		if target := requestHost(r); target != host {
			e.Status, e.Error = http.StatusMisdirectedRequest, fmt.Sprintf("request for %s inside a tunnel to %s", target, host)
			audit(auditWrongHost, "", e.Status, "asked for "+target)
			http.Error(w, "Blindfold: request host does not match the tunnel", e.Status)
			return
		}
		// A gated secret waits here, before its value is read, until a person
		// allows it
		var approvals map[string]string
		allow := func(name string) *refusal {
			if !rules[name].NeedsApproval(r.Method) {
				return nil
			}
			ans := p.approver.approve(r.Context(), approvalRequest{name, scopes[name], r.Method, host, r.URL.Path})
			if !ans.allowed() {
				return &refusal{name, auditApproval, http.StatusForbidden,
					fmt.Sprintf("using %s for this request was not approved (%s)", name, ans), ans.String()}
			}
			if approvals == nil {
				approvals = map[string]string{}
			}
			approvals[name] = ans.String()
			return nil
		}
		used, ref := inject(r, rules, allow, lookup)
		e.Secrets = used
		if ref != nil {
			e.Status, e.Error = ref.status, ref.msg
			audit(ref.decision, ref.secret, e.Status, ref.detail)
			http.Error(w, "Blindfold: "+ref.msg, e.Status)
			return
		}
		// Placeholders left over were somewhere their rule doesn't name
		for _, name := range placeholdersIn(r, slices.Collect(maps.Keys(rules))) {
			audit(auditOutsideSlot, name, 0, "")
		}

		// Every secret this host may receive is scrubbed from what comes back,
		// filled in on this request or not: an API can store a token and
		// return it on a later call
		pairs := scrubPairsFor(rules, lookup)
		found := map[string]int{}
		var unreadable string
		forwarder := &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.Out.URL.Scheme = "https"
				pr.Out.URL.Host = host
				pr.Out.Host = host
				// Responses have to come back readable to be scrubbed. With the
				// client's header gone, the transport asks for gzip itself and
				// decodes it before ModifyResponse sees the body.
				pr.Out.Header.Del("Accept-Encoding")
			},
			ModifyResponse: func(resp *http.Response) error {
				unreadable = scrubResponse(resp, pairs, found)
				if unreadable != "" {
					return fmt.Errorf("the response is %s-encoded, which Blindfold can't check for secrets", unreadable)
				}
				return nil
			},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				http.Error(w, "Blindfold: "+err.Error(), http.StatusBadGateway)
			},
			Transport: p.transport,
			ErrorLog:  log.New(io.Discard, "", 0),
		}
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		// ServeHTTP returns after the body is copied, so found is complete
		forwarder.ServeHTTP(rec, r)
		e.Status = rec.status

		for _, name := range used {
			audit(auditFilled, name, e.Status, approvals[name])
		}
		if unreadable != "" {
			audit(auditEncoding, "", e.Status, unreadable)
		}
		for _, name := range slices.Sorted(maps.Keys(found)) {
			audit(auditEchoed, name, e.Status, fmt.Sprintf("%d copies", found[name]))
		}
	})
}

// scrubPairsFor returns the values worth scrubbing for a host's secrets.
// Values come from the same cache as injection, so this rarely runs `security`.
func scrubPairsFor(rules map[string]*Rule, lookup func(string) (string, error)) []scrubPair {
	var pairs []scrubPair
	for name := range rules {
		if v, err := lookup(name); err == nil && len(v) >= minScrubLength {
			pairs = append(pairs, newScrubPair(name, v))
		}
	}
	sortScrubPairs(pairs)
	return pairs
}

// scrubResponse swaps any copy of a secret's value in the response for its
// placeholder, in headers now and in the body as it streams, counting copies
// into found. Returns the encoding when the body is in one it can't read.
func scrubResponse(resp *http.Response, pairs []scrubPair, found map[string]int) (unreadable string) {
	if len(pairs) == 0 {
		return ""
	}
	if ce := resp.Header.Get("Content-Encoding"); ce != "" && !strings.EqualFold(ce, "identity") {
		return ce
	}
	for _, vals := range resp.Header {
		for i := range vals {
			vals[i] = scrubString(vals[i], pairs, found)
		}
	}
	resp.Body = newScrubber(resp.Body, pairs, found)
	// The length changes when a value and its placeholder differ in size
	resp.Header.Del("Content-Length")
	resp.ContentLength = -1
	return ""
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
// names it filled in. allow is asked about each secret once it's known to be
// needed and before its value is read, so a refused request never touches the
// keychain or holds the value.
func inject(r *http.Request, rules map[string]*Rule, allow func(string) *refusal, lookup func(string) (string, error)) ([]string, *refusal) {
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
				return used, &refusal{name, auditWrongUser, http.StatusBadGateway, fmt.Sprintf("%s may only be used with username %q", name, want), ""}
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
		if ref := allow(name); ref != nil {
			return used, ref
		}

		value, err := lookup(name)
		if err == nil && value == "" {
			err = fmt.Errorf("it's empty")
		}
		if err != nil {
			return used, &refusal{name, auditMissing, http.StatusBadGateway, fmt.Sprintf("could not read %s: %v", name, err), ""}
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

// refusal is why a request was turned away, for the response and the audit log
type refusal struct {
	secret, decision string
	status           int
	msg, detail      string
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
