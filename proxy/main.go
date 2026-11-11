// Command blindfold-proxy is the local proxy that sandboxed commands send
// their network traffic through. This version only tunnels and logs where
// traffic goes; see docs/design/destination-binding.md for what comes next.
package main

import (
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
	flag.Parse()

	ln, err := listenLoopback(*listen)
	if err != nil {
		log.Fatal(err)
	}
	record, err := openEgressLog(*logPath)
	if err != nil {
		log.Fatal(err)
	}
	if *portFile != "" {
		port := ln.Addr().(*net.TCPAddr).Port
		if err := writePortFile(*portFile, port); err != nil {
			log.Fatal(err)
		}
	}

	srv := &http.Server{
		Handler:           NewProxy(record, nil),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	log.Fatal(srv.Serve(ln))
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

// writePortFile writes atomically so a reader never sees a half-written port
func writePortFile(path string, port int) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".port-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	// os.CreateTemp already creates the file with mode 0600
	if _, err := tmp.WriteString(strconv.Itoa(port) + "\n"); err != nil {
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
