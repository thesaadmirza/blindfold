package main

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// startProxy runs the proxy on a loopback port and returns its URL plus a
// channel that receives every recorded entry.
func startProxy(t *testing.T) (*url.URL, <-chan Entry) {
	t.Helper()
	entries := make(chan Entry, 16)
	srv := httptest.NewServer(NewProxy(func(e Entry) { entries <- e }, nil))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return u, entries
}

func nextEntry(t *testing.T, entries <-chan Entry) Entry {
	t.Helper()
	select {
	case e := <-entries:
		return e
	case <-time.After(5 * time.Second):
		t.Fatal("proxy recorded nothing")
		return Entry{}
	}
}

func clientVia(proxyURL *url.URL, upstream *httptest.Server) *http.Client {
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	if upstream.TLS != nil {
		tr.TLSClientConfig = upstream.Client().Transport.(*http.Transport).TLSClientConfig
	}
	return &http.Client{Transport: tr, Timeout: 5 * time.Second}
}

func TestTunnelsHTTPSWithoutTouchingTLS(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello over tls")
	}))
	defer upstream.Close()
	proxyURL, entries := startProxy(t)

	client := clientVia(proxyURL, upstream)
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	client.CloseIdleConnections()

	if string(body) != "hello over tls" {
		t.Fatalf("body = %q", body)
	}
	e := nextEntry(t, entries)
	if e.Kind != "connect" || e.Host != upstream.Listener.Addr().String() || e.Status != 200 {
		t.Fatalf("entry = %+v", e)
	}
	if e.Sent == 0 || e.Received == 0 {
		t.Fatalf("byte counts missing: %+v", e)
	}
}

func TestTunnelEndsWhenTheClientHangsUp(t *testing.T) {
	// An upstream that accepts and then never writes or closes, like a server
	// sitting on a keep-alive connection
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		for {
			c, err := upstream.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			io.Copy(io.Discard, c)
		}
	}()
	proxyURL, entries := startProxy(t)

	conn, err := net.Dial("tcp", proxyURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	addr := upstream.Addr().String()
	io.WriteString(conn, "CONNECT "+addr+" HTTP/1.1\r\nHost: "+addr+"\r\n\r\n")
	if _, err := http.ReadResponse(bufio.NewReader(conn), nil); err != nil {
		t.Fatal(err)
	}
	io.WriteString(conn, "hello")
	conn.Close()

	if e := nextEntry(t, entries); e.Kind != "connect" || e.Sent != 5 {
		t.Fatalf("entry = %+v", e)
	}
}

func TestForwardsPlainHTTP(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		io.WriteString(w, "plain")
	}))
	defer upstream.Close()
	proxyURL, entries := startProxy(t)

	resp, err := clientVia(proxyURL, upstream).Get(upstream.URL + "/path?token=abc")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusTeapot || string(body) != "plain" {
		t.Fatalf("got %d %q", resp.StatusCode, body)
	}
	e := nextEntry(t, entries)
	if e.Kind != "http" || e.Method != "GET" || e.Status != http.StatusTeapot {
		t.Fatalf("entry = %+v", e)
	}
	line, _ := json.Marshal(e)
	if strings.Contains(string(line), "token") || strings.Contains(string(line), "/path") {
		t.Fatalf("path or query leaked into the log: %s", line)
	}
}

func TestRefusesRequestsThatAreNotProxyRequests(t *testing.T) {
	proxyURL, _ := startProxy(t)

	resp, err := http.Get(proxyURL.String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestUnreachableUpstreamIsBadGateway(t *testing.T) {
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := closed.Addr().String()
	closed.Close()
	proxyURL, entries := startProxy(t)

	conn, err := net.Dial("tcp", proxyURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	io.WriteString(conn, "CONNECT "+addr+" HTTP/1.1\r\nHost: "+addr+"\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if e := nextEntry(t, entries); e.Status != http.StatusBadGateway || e.Error == "" {
		t.Fatalf("entry = %+v", e)
	}
}

func TestPortFileIsPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run", "proxy.port")

	if err := writePortFile(path, 4321); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v", info.Mode().Perm())
	}
	if b, _ := os.ReadFile(path); string(b) != "4321\n" {
		t.Fatalf("content = %q", b)
	}
}

func TestListensOnLoopbackOnly(t *testing.T) {
	if ln, err := listenLoopback("0.0.0.0:0"); err == nil {
		ln.Close()
		t.Fatal("listened on a non-loopback address")
	}
	ln, err := listenLoopback("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
}
