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
	name        string
	value       []byte
	placeholder []byte
}

func newScrubPair(name, value string) scrubPair {
	return scrubPair{name, []byte(value), []byte(placeholder(name))}
}

// sortScrubPairs puts longer values first, so where one value contains
// another the longer match wins, in headers and bodies alike
func sortScrubPairs(pairs []scrubPair) {
	slices.SortFunc(pairs, func(a, b scrubPair) int { return len(b.value) - len(a.value) })
}

// scrubber reads a body and replaces every copy of a secret's value with its
// placeholder, so an API that echoes a token back can't hand it to the agent.
// When a read ends partway into something that could be a value, it holds
// those bytes back until the next read settles it. Counts of what it
// replaced go into found, for the audit log.
type scrubber struct {
	src   io.ReadCloser
	pairs []scrubPair // sorted by sortScrubPairs
	raw   []byte      // read but not yet scanned
	out   []byte      // scanned and ready to hand out
	eof   bool
	found map[string]int
}

func newScrubber(src io.ReadCloser, pairs []scrubPair, found map[string]int) *scrubber {
	return &scrubber{src: src, pairs: pairs, found: found}
}

func (s *scrubber) Read(p []byte) (int, error) {
	for len(s.out) == 0 {
		if s.eof {
			return 0, io.EOF
		}
		// Read straight into spare room at the end of raw
		s.raw = slices.Grow(s.raw, 32<<10)
		n, err := s.src.Read(s.raw[len(s.raw):cap(s.raw)])
		s.raw = s.raw[:len(s.raw)+n]
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

// scan moves everything that can no longer be part of a value from raw to
// out, replacing values on the way
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
	cut := len(s.raw)
	if !s.eof {
		cut -= s.pendingPrefix()
	}
	s.out = append(s.out, s.raw[:cut]...)
	s.raw = s.raw[cut:]
}

// pendingPrefix is how many bytes at the end of raw could be the start of a
// value, which is usually none
func (s *scrubber) pendingPrefix() int {
	for k := min(len(s.raw), len(s.pairs[0].value)-1); k > 0; k-- {
		tail := s.raw[len(s.raw)-k:]
		for _, p := range s.pairs {
			if bytes.HasPrefix(p.value, tail) {
				return k
			}
		}
	}
	return 0
}

// earliest finds the first value in raw, the longest one if two start together
func (s *scrubber) earliest() (int, scrubPair) {
	at, best := -1, scrubPair{}
	for _, p := range s.pairs {
		if i := bytes.Index(s.raw, p.value); i >= 0 && (at < 0 || i < at) {
			at, best = i, p
		}
	}
	return at, best
}

func (s *scrubber) Close() error { return s.src.Close() }

// scrubString replaces values in a header value, counting what it replaced
func scrubString(v string, pairs []scrubPair, found map[string]int) string {
	for _, p := range pairs {
		if n := strings.Count(v, string(p.value)); n > 0 {
			v = strings.ReplaceAll(v, string(p.value), string(p.placeholder))
			found[p.name] += n
		}
	}
	return v
}
