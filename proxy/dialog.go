package main

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
	"unicode"
)

// maxDialogText caps what a dialog shows. Some of the text comes from the
// agent, and a long enough message would push the buttons' meaning off screen.
const maxDialogText = 1800

// showDialog shows a native macOS dialog and returns the button clicked. The
// first button is the safe one: it's the default and the cancel button, so
// Return or Escape picks it, and it's drawn rightmost, where people click
// out of habit. No answer in time, no screen, or any other failure returns "".
// It is the only dialog Blindfold shows: secret-approve.sh calls it through
// the -dialog flag, so both read answers and clean up text the same way.
func showDialog(ctx context.Context, message string, buttons []string, timeout time.Duration) string {
	ctx, cancel := context.WithTimeout(ctx, timeout+5*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "osascript", "-e", "on run argv", "-e", dialogScript(buttons, timeout), "-e", "end run",
		dialogText(message)).CombinedOutput()
	return parseDialogReply(string(out), buttons)
}

// dialogScript is the AppleScript for showDialog. macOS draws buttons left to
// right in list order, so the safe one goes last.
func dialogScript(buttons []string, timeout time.Duration) string {
	quoted := make([]string, len(buttons))
	for i, b := range buttons {
		quoted[len(buttons)-1-i] = fmt.Sprintf("%q", b)
	}
	safe := quoted[len(quoted)-1]
	return fmt.Sprintf(`display dialog (item 1 of argv) with title "Blindfold" buttons {%s} default button %s cancel button %s giving up after %d with icon caution`,
		strings.Join(quoted, ", "), safe, safe, int(timeout.Seconds()))
}

// parseDialogReply turns osascript's output into the button clicked. The
// cancel button comes back as error -128, not as a reply.
func parseDialogReply(reply string, buttons []string) string {
	if strings.Contains(reply, "(-128)") {
		return buttons[0]
	}
	if !strings.Contains(reply, "gave up:false") {
		return ""
	}
	for _, b := range buttons {
		if strings.Contains(reply, "button returned:"+b+",") {
			return b
		}
	}
	return ""
}

// dialogText keeps line breaks and tabs but turns every other control
// character into "?", and cuts the text to maxDialogText
func dialogText(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return '?'
		}
		return r
	}, s)
	if r := []rune(s); len(r) > maxDialogText {
		s = string(r[:maxDialogText]) + "\n[... shortened]"
	}
	return s
}

// oneLine is dialogText for a single line, such as a request path: line
// breaks go too, and it's cut much shorter
func oneLine(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, s)
	if r := []rune(s); len(r) > max {
		s = string(r[:max]) + "..."
	}
	return s
}
