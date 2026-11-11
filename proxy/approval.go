package main

import (
	"context"
	"fmt"
	"sync"
	"time"
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

// dialogAsk asks in a native dialog. No answer in time, or no screen to show
// it on, is a deny.
func dialogAsk(req approvalRequest) answer {
	msg := fmt.Sprintf("An agent wants to use %s.\n\nRequest: %s https://%s\nRequest path: %s",
		req.Secret, req.Method, req.Host, oneLine(req.Path, 120))
	if req.Project != "" {
		msg += "\nProject: " + req.Project
	}
	msg += "\n\n\"Allow 30 min\" covers this secret, method and host for 30 minutes."

	switch showDialog(context.Background(), msg, []string{"Deny", "Allow once", "Allow 30 min"}, dialogTimeout) {
	case "Allow once":
		return allowOnce
	case "Allow 30 min":
		return allowForAWhile
	}
	return deny
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
