package main

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	grantLength   = 30 * time.Minute
	dialogTimeout = 60 * time.Second
)

// approvalRequest is what the person is asked about
type approvalRequest struct {
	Secret, Project, Method, Host, Path string
}

func (r approvalRequest) key() approvalRequest {
	r.Path = "" // a grant covers the secret, project, method and host
	return r
}

type answer int

const (
	deny answer = iota
	allowOnce
	allowForAWhile
)

// approver asks a person before a gated secret goes out, and remembers
// "allow for 30 minutes" answers so the same kind of request doesn't ask
// again. One dialog is on screen at a time. Identical requests that arrive
// while one is being asked about wait for that answer: a deny or a grant
// settles them all, "allow once" only the request it was asked for.
type approver struct {
	ask func(approvalRequest) answer // shows the dialog and waits for it
	now func() time.Time

	mu      sync.Mutex
	grants  map[approvalRequest]time.Time
	waiting map[approvalRequest]*pendingAnswer
	dialog  sync.Mutex
}

type pendingAnswer struct {
	done    chan struct{}
	ans     answer
	waiters int // requests waiting on this answer besides the one asking
}

func newApprover(ask func(approvalRequest) answer) *approver {
	return &approver{ask: ask, now: time.Now, grants: map[approvalRequest]time.Time{}, waiting: map[approvalRequest]*pendingAnswer{}}
}

// approve reports whether req may go ahead, and how it was decided, for the
// audit log
func (a *approver) approve(req approvalRequest) (bool, string) {
	key := req.key()
	for {
		a.mu.Lock()
		if until, ok := a.grants[key]; ok && a.now().Before(until) {
			a.mu.Unlock()
			return true, "within a 30-minute approval"
		}
		if w := a.waiting[key]; w != nil {
			w.waiters++
			a.mu.Unlock()
			<-w.done
			if w.ans == deny {
				return false, "denied"
			}
			continue // a grant covers this one; after "allow once", ask again
		}
		w := &pendingAnswer{done: make(chan struct{})}
		a.waiting[key] = w
		a.mu.Unlock()

		a.dialog.Lock()
		ans := a.ask(req)
		a.dialog.Unlock()

		a.mu.Lock()
		if ans == allowForAWhile {
			a.grants[key] = a.now().Add(grantLength)
		}
		delete(a.waiting, key)
		w.ans = ans
		close(w.done)
		a.mu.Unlock()

		switch ans {
		case allowOnce:
			return true, "approved once"
		case allowForAWhile:
			return true, "approved for 30 minutes"
		}
		return false, "denied"
	}
}

// dialogAsk shows a native macOS dialog. Deny is the default and the cancel
// button, so Return or Escape never allows. No answer in time, or no screen
// to show it on, is a deny.
func dialogAsk(req approvalRequest) answer {
	msg := fmt.Sprintf("An agent wants to use %s.\n\nRequest: %s https://%s\nRequest path: %s",
		req.Secret, req.Method, req.Host, shownText(req.Path))
	if req.Project != "" {
		msg += "\nProject: " + req.Project
	}
	msg += "\n\n\"Allow 30 min\" covers this secret, method and host for 30 minutes."

	ctx, cancel := context.WithTimeout(context.Background(), dialogTimeout+5*time.Second)
	defer cancel()
	script := fmt.Sprintf(`display dialog (item 1 of argv) with title "Blindfold" buttons {"Deny", "Allow once", "Allow 30 min"} default button "Deny" cancel button "Deny" giving up after %d with icon caution`, int(dialogTimeout.Seconds()))
	out, _ := exec.CommandContext(ctx, "osascript", "-e", "on run argv", "-e", script, "-e", "end run", msg).CombinedOutput()
	return parseDialogReply(string(out))
}

func parseDialogReply(reply string) answer {
	if !strings.Contains(reply, "gave up:false") {
		return deny
	}
	switch {
	case strings.Contains(reply, "button returned:Allow 30 min"):
		return allowForAWhile
	case strings.Contains(reply, "button returned:Allow once"):
		return allowOnce
	}
	return deny
}

// shownText makes text the agent controls safe to put in a dialog: control
// characters become "?", and it's cut to a length that can't push the
// buttons' meaning off screen
func shownText(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, s)
	if r := []rune(s); len(r) > 120 {
		s = string(r[:120]) + "..."
	}
	return s
}

// waitersFor reports how many requests are waiting on a dialog for req
func (a *approver) waitersFor(req approvalRequest) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	if w := a.waiting[req.key()]; w != nil {
		return w.waiters
	}
	return 0
}
