package main

import (
	"bytes"
	"io"
	"slices"
	"strings"
)

// minScrubLength is the shortest value worth scrubbing. Replacing every
// "abc" in a response would mangle it, and a secret that short isn't one.
const minScrubLength = 4

// scrubPair is one secret: its value, and the placeholder that replaces it
type scrubPair struct {
	name, value, placeholder string
}

// scrubber reads a body and replaces every copy of a secret's value with its
// placeholder, so an API that echoes a token back can't hand it to the agent.
// It holds back the last few bytes of each read, in case a value is split
// across two reads, and counts what it replaced for the audit log.
type scrubber struct {
	src    io.ReadCloser
	pairs  []scrubPair // longest value first, so a longer match wins
	keep   int         // bytes to hold back: longest value minus one
	raw    []byte      // read but not yet scanned
	out    []byte      // scanned and ready to hand out
	eof    bool
	found  map[string]int
	onDone func(found map[string]int)
	done   bool
}

func newScrubber(src io.ReadCloser, pairs []scrubPair, onDone func(map[string]int)) *scrubber {
	pairs = slices.Clone(pairs)
	slices.SortFunc(pairs, func(a, b scrubPair) int { return len(b.value) - len(a.value) })
	return &scrubber{src: src, pairs: pairs, keep: len(pairs[0].value) - 1, found: map[string]int{}, onDone: onDone}
}

func (s *scrubber) Read(p []byte) (int, error) {
	for len(s.out) == 0 {
		if s.eof {
			s.finish()
			return 0, io.EOF
		}
		chunk := make([]byte, 32*1024)
		n, err := s.src.Read(chunk)
		s.raw = append(s.raw, chunk[:n]...)
		switch {
		case err == io.EOF:
			s.eof = true
		case err != nil:
			return 0, err
		}
		s.scan()
	}
	n := copy(p, s.out)
	s.out = s.out[n:]
	return n, nil
}

// scan moves everything that can no longer be the start of a value from raw
// to out, replacing values on the way
func (s *scrubber) scan() {
	for {
		at, pair := s.earliest()
		if at < 0 {
			break
		}
		s.out = append(append(s.out, s.raw[:at]...), pair.placeholder...)
		s.raw = s.raw[at+len(pair.value):]
		s.found[pair.name]++
	}
	// A value can only start in the last keep bytes and still be incomplete
	cut := len(s.raw) - s.keep
	if s.eof {
		cut = len(s.raw)
	}
	if cut > 0 {
		s.out = append(s.out, s.raw[:cut]...)
		s.raw = s.raw[cut:]
	}
}

// earliest finds the first value in raw, the longest one if two start together
func (s *scrubber) earliest() (int, scrubPair) {
	at, best := -1, scrubPair{}
	for _, p := range s.pairs {
		if i := bytes.Index(s.raw, []byte(p.value)); i >= 0 && (at < 0 || i < at) {
			at, best = i, p
		}
	}
	return at, best
}

func (s *scrubber) finish() {
	if !s.done {
		s.done = true
		if s.onDone != nil {
			s.onDone(s.found)
		}
	}
}

func (s *scrubber) Close() error {
	s.finish()
	return s.src.Close()
}

// scrubString replaces values in a header value, counting what it replaced
func scrubString(v string, pairs []scrubPair, found map[string]int) string {
	for _, p := range pairs {
		if n := strings.Count(v, p.value); n > 0 {
			v = strings.ReplaceAll(v, p.value, p.placeholder)
			found[p.name] += n
		}
	}
	return v
}
