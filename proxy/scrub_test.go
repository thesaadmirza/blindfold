package main

import (
	"io"
	"strings"
	"testing"
	"time"
)

var scrubPairs = func() []scrubPair {
	pairs := []scrubPair{newScrubPair("SHORT", "pass1234"), newScrubPair("TOKEN", "glpat-secret-value")}
	sortScrubPairs(pairs)
	return pairs
}()

// chunkReader hands a body over at most n bytes at a time, to split values
// across reads
type chunkReader struct {
	r io.Reader
	n int
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if len(p) > c.n {
		p = p[:c.n]
	}
	return c.r.Read(p)
}

func scrubAll(t *testing.T, body string, chunk int) (string, map[string]int) {
	t.Helper()
	var src io.Reader = strings.NewReader(body)
	if chunk > 0 {
		src = &chunkReader{r: src, n: chunk}
	}
	found := map[string]int{}
	out, err := io.ReadAll(newScrubber(io.NopCloser(src), scrubPairs, found))
	if err != nil {
		t.Fatal(err)
	}
	return string(out), found
}

func TestScrubberReplacesEveryCopy(t *testing.T) {
	body := `{"token":"glpat-secret-value","again":"glpat-secret-value","pw":"pass1234"}`
	want := `{"token":"{{TOKEN}}","again":"{{TOKEN}}","pw":"{{SHORT}}"}`

	for _, chunk := range []int{0, 1, 3, 7, 17} {
		got, found := scrubAll(t, body, chunk)
		if got != want {
			t.Fatalf("chunk %d: got %s", chunk, got)
		}
		if found["TOKEN"] != 2 || found["SHORT"] != 1 {
			t.Fatalf("chunk %d: found %v", chunk, found)
		}
	}
}

func TestScrubberLeavesOtherBytesAlone(t *testing.T) {
	// Starts of values that never complete, right up to the end
	body := "glpat-secret-valu glpat- pass123 nothing here glpat-secret-valu"

	for _, chunk := range []int{0, 1, 5} {
		if got, found := scrubAll(t, body, chunk); got != body || len(found) != 0 {
			t.Fatalf("chunk %d: got %q found %v", chunk, got, found)
		}
	}
}

func TestScrubberHandlesValueAtTheVeryEnd(t *testing.T) {
	for _, chunk := range []int{0, 1, 4} {
		if got, _ := scrubAll(t, "end:glpat-secret-value", chunk); got != "end:{{TOKEN}}" {
			t.Fatalf("chunk %d: got %q", chunk, got)
		}
	}
}

// A stream must not stall: a read that can't be the start of a value is
// handed on whole, without waiting for the next one
func TestScrubberHoldsBackOnlyWhatCouldBeAValue(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()
	s := newScrubber(pr, scrubPairs, map[string]int{})
	go pw.Write([]byte("data: event one\n\n"))

	got := make(chan string, 1)
	go func() {
		buf := make([]byte, 64)
		n, _ := s.Read(buf)
		got <- string(buf[:n])
	}()

	select {
	case out := <-got:
		if out != "data: event one\n\n" {
			t.Fatalf("got %q", out)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the event was held back waiting for more of the stream")
	}
}

func TestScrubStringCountsHeaderCopies(t *testing.T) {
	found := map[string]int{}

	got := scrubString("Bearer glpat-secret-value", scrubPairs, found)

	if got != "Bearer {{TOKEN}}" || found["TOKEN"] != 1 {
		t.Fatalf("got %q found %v", got, found)
	}
}
