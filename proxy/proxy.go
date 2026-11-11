package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

const dialTimeout = 10 * time.Second

// Entry is one line of the egress log: where a sandboxed command connected.
// Paths and query strings are left out, since they can carry data.
type Entry struct {
	Time     string `json:"ts"`
	Kind     string `json:"kind"` // "connect" or "http"
	Host     string `json:"host"`
	Method   string `json:"method,omitempty"`
	Status   int    `json:"status,omitempty"`
	Sent     int64  `json:"sent,omitempty"`
	Received int64  `json:"received,omitempty"`
	Millis   int64  `json:"ms"`
	Error    string `json:"error,omitempty"`
	// Secrets lists the secrets whose values were put into the request
	Secrets []string `json:"secrets,omitempty"`
}

// Proxy tunnels CONNECT requests and forwards plain HTTP ones. Tunnels to
// hosts a policy names on port 443 are intercepted instead, so the secret
// meant for that host can be put into the request. Everything else passes
// through untouched.
type Proxy struct {
	record    func(Entry)
	audit     func(AuditEntry)
	lookup    func(scope, name string) (string, error)
	dial      func(ctx context.Context, network, addr string) (net.Conn, error)
	transport *http.Transport
	forwarder *httputil.ReverseProxy
	state     atomic.Pointer[policyState]
}

// policyState is swapped whole when a policy changes, so a request never sees
// policies from one version and a CA from another
type policyState struct {
	policy   *Policy             // the global policy
	projects map[string]*Project // approved projects, by token
	ca       *authority          // nil when no policy names a host
}

// rulesFor returns the rules for host that apply to a request carrying token,
// and the scope to look each secret up in: none for the global policy's
// secrets, the project's path for its own. A project only adds rules for names
// the global policy doesn't have; it can't change a global secret's rule.
func (st *policyState) rulesFor(token, host string) (map[string]*Rule, map[string]string) {
	rules, scopes := st.policy.RulesFor(host), map[string]string{}
	proj := st.projects[token]
	if proj == nil {
		return rules, scopes
	}
	for name, r := range proj.Policy.RulesFor(host) {
		if _, global := st.policy.Secrets[name]; !global {
			rules[name], scopes[name] = r, proj.Path
		}
	}
	return rules, scopes
}

// names returns every secret any loaded policy names
func (st *policyState) names() []string {
	names := st.policy.Names()
	for _, proj := range st.projects {
		names = append(names, proj.Policy.Names()...)
	}
	slices.Sort(names)
	return slices.Compact(names)
}

// NewProxy returns a proxy with an empty policy. lookup returns the stored
// value of a secret, preferring the project scope when one is given.
func NewProxy(record func(Entry), lookup func(scope, name string) (string, error)) *Proxy {
	dialer := &net.Dialer{Timeout: dialTimeout}
	p := &Proxy{record: record, audit: func(AuditEntry) {}, lookup: lookup, dial: dialer.DialContext}
	p.transport = &http.Transport{
		// Proxy is nil, so traffic never loops back through a proxy
		DialContext:         func(ctx context.Context, n, a string) (net.Conn, error) { return p.dial(ctx, n, a) },
		TLSHandshakeTimeout: dialTimeout,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   true,
	}
	p.forwarder = &httputil.ReverseProxy{
		// The outgoing request is already a copy of the absolute-URL one we got
		Rewrite:   func(*httputil.ProxyRequest) {},
		Transport: p.transport,
	}
	p.state.Store(&policyState{policy: &Policy{}})
	return p
}

// SetPolicies switches to a global policy and a set of approved projects. The
// CA covers every host any of them names, and is made again only when that
// set changes. Returns the CA now in use, or nil when no policy names a host.
func (p *Proxy) SetPolicies(pol *Policy, projects map[string]*Project) (*authority, error) {
	old := p.state.Load()
	next := &policyState{policy: pol, projects: projects, ca: old.ca}
	all := pol.Hosts()
	for _, proj := range projects {
		all = append(all, proj.Policy.Hosts()...)
	}
	slices.Sort(all)
	if hosts := slices.Compact(all); len(hosts) == 0 {
		next.ca = nil
	} else if old.ca == nil || !slices.Equal(old.ca.hosts, hosts) {
		ca, err := newAuthority(hosts)
		if err != nil {
			return nil, err
		}
		next.ca = ca
	}
	p.state.Store(next)
	return next.ca, nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodConnect:
		p.tunnel(w, r)
	case r.URL.IsAbs() && r.URL.Scheme == "http":
		p.forward(w, r)
	default:
		http.Error(w, "blindfold-proxy only handles proxy requests", http.StatusBadRequest)
	}
}

func (p *Proxy) tunnel(w http.ResponseWriter, r *http.Request) {
	if host, port, err := net.SplitHostPort(r.Host); err == nil && port == "443" {
		host = strings.ToLower(host)
		// SetPolicies makes a CA whenever any rule names a host
		st := p.state.Load()
		if rules, scopes := st.rulesFor(proxyToken(r), host); len(rules) > 0 {
			p.intercept(w, r, host, rules, scopes, st.ca)
			return
		}
	}

	e := Entry{Kind: "connect", Host: r.Host}
	start := time.Now()
	defer func() { p.log(e, start) }()

	upstream, err := p.dial(r.Context(), "tcp", r.Host)
	if err != nil {
		e.Status, e.Error = http.StatusBadGateway, err.Error()
		http.Error(w, "upstream unreachable", http.StatusBadGateway)
		return
	}
	client, buffered, err := http.NewResponseController(w).Hijack()
	if err != nil {
		upstream.Close()
		e.Status, e.Error = http.StatusInternalServerError, err.Error()
		http.Error(w, "cannot tunnel", http.StatusInternalServerError)
		return
	}
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		client.Close()
		upstream.Close()
		e.Error = err.Error()
		return
	}
	e.Status = http.StatusOK
	e.Sent, e.Received = splice(client, buffered.Reader, upstream)
}

// splice copies both ways until either side is done, then closes both. Waiting
// for the other side as well would keep the tunnel open until a server's own
// keep-alive timeout, long after the client has gone. The client is read
// through its bufio.Reader, which may already hold bytes sent right after CONNECT.
func splice(client net.Conn, clientReader *bufio.Reader, upstream net.Conn) (sent, received int64) {
	done := make(chan struct{}, 2)
	go func() {
		received, _ = io.Copy(client, upstream)
		done <- struct{}{}
	}()
	go func() {
		sent, _ = io.Copy(upstream, clientReader)
		done <- struct{}{}
	}()
	<-done
	client.Close()
	upstream.Close()
	<-done
	return sent, received
}

func (p *Proxy) forward(w http.ResponseWriter, r *http.Request) {
	e := Entry{Kind: "http", Host: r.URL.Host, Method: r.Method}
	// Plain HTTP is never filled in, but a placeholder sent this way is worth
	// a line in the audit log
	if st := p.state.Load(); st != nil {
		for _, name := range placeholdersIn(r, st.names()) {
			p.auditLog(AuditEntry{Decision: auditPlainHTTP, Secret: name, Method: r.Method, Host: r.URL.Hostname(), Path: r.URL.Path})
		}
	}
	start := time.Now()
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	p.forwarder.ServeHTTP(rec, r)
	e.Status = rec.status
	p.log(e, start)
}

func (p *Proxy) log(e Entry, start time.Time) {
	e.Time = start.UTC().Format(time.RFC3339)
	e.Millis = time.Since(start).Milliseconds()
	p.record(e)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Unwrap lets http.ResponseController reach the real writer to flush streams
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }
