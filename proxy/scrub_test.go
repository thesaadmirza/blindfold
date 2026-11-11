package main

import (
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

var scrubPairs = []scrubPair{
	{"TOKEN", "glpat-secret-value", "{{TOKEN}}"},
	{"SHORT", "pass1234", "{{SHORT}}"},
}

func scrubAll(t *testing.T, body string, chunk int) (string, map[string]int) {
	t.Helper()
	var src io.Reader = strings.NewReader(body)
	if chunk > 0 {
		// Hand the body over a few bytes at a time, to split values across reads
		src = iotest.OneByteReader(src)
		if chunk > 1 {
			src = &chunkReader{r: strings.NewReader(body), n: chunk}
		}
	}
	var found map[string]int
	s := newScrubber(io.NopCloser(src), scrubPairs, func(f map[string]int) { found = f })
	out, err := io.ReadAll(s)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	return string(out), found
}

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

func TestScrubStringCountsHeaderCopies(t *testing.T) {
	found := map[string]int{}

	got := scrubString("Bearer glpat-secret-value", scrubPairs, found)

	if got != "Bearer {{TOKEN}}" || found["TOKEN"] != 1 {
		t.Fatalf("got %q found %v", got, found)
	}
}
