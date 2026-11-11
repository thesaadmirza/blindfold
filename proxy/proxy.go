package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
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
}

// Proxy tunnels CONNECT requests and forwards plain HTTP ones. It never looks
// inside a tunnel and never touches secrets.
type Proxy struct {
	record    func(Entry)
	dial      func(ctx context.Context, network, addr string) (net.Conn, error)
	forwarder *httputil.ReverseProxy
}

func NewProxy(record func(Entry)) *Proxy {
	dialer := &net.Dialer{Timeout: dialTimeout}
	return &Proxy{
		record: record,
		dial:   dialer.DialContext,
		forwarder: &httputil.ReverseProxy{
			// The outgoing request is already a copy of the absolute-URL one we got
			Rewrite: func(*httputil.ProxyRequest) {},
			// Proxy: nil, so the forwarder never sends traffic back through a proxy
			Transport: &http.Transport{
				DialContext:         dialer.DialContext,
				TLSHandshakeTimeout: dialTimeout,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
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
