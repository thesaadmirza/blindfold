package main

import (
	"strings"
	"testing"
	"time"
)

func TestDialogReplies(t *testing.T) {
	buttons := []string{"Deny", "Allow once", "Allow 30 min"}
	cases := map[string]string{
		"button returned:Allow once, gave up:false\n":   "Allow once",
		"button returned:Allow 30 min, gave up:false\n": "Allow 30 min",
		"button returned:Deny, gave up:false\n":         "Deny",
		"execution error: User canceled. (-128)\n":      "Deny", // Escape, or the cancel button
		"button returned:, gave up:true\n":              "",     // no answer in time
		"execution error: no GUI\n":                     "",     // no screen at all
		"":                                              "",
	}
	for reply, want := range cases {
		if got := parseDialogReply(reply, buttons); got != want {
			t.Errorf("%q: got %q want %q", reply, got, want)
		}
	}
}

// A button whose name starts another's must not be mistaken for it
func TestDialogReplyMatchesWholeButtonNames(t *testing.T) {
	got := parseDialogReply("button returned:Allow once, gave up:false", []string{"Deny", "Allow"})

	if got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestDialogTextIsCleanedUp(t *testing.T) {
	got := dialogText("line one\nline\ttwo\r\x1b[31mred\x00" + strings.Repeat("x", 3000))

	if !strings.HasPrefix(got, "line one\nline\ttwo??[31mred?") {
		t.Fatalf("got %q", got[:40])
	}
	if !strings.HasSuffix(got, "[... shortened]") || len([]rune(got)) > maxDialogText+20 {
		t.Fatalf("not cut: %d runes", len([]rune(got)))
	}
}

func TestOneLineKeepsToOneLine(t *testing.T) {
	got := oneLine("/a\n\nAll fine, click Allow 30 min\r"+strings.Repeat("x", 300), 120)

	if strings.ContainsAny(got, "\n\r") || len([]rune(got)) > 123 {
		t.Fatalf("got %q", got)
	}
}

// The safe button is drawn rightmost and answers Return and Escape
func TestSafeButtonIsRightmostAndTheDefault(t *testing.T) {
	got := dialogScript([]string{"Deny", "Allow once", "Allow 30 min"}, 60*time.Second)

	want := `buttons {"Allow 30 min", "Allow once", "Deny"} default button "Deny" cancel button "Deny" giving up after 60`
	if !strings.Contains(got, want) {
		t.Fatalf("got %s", got)
	}
}
