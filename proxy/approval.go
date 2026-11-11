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

// answer is how an approval was decided
type answer int

const (
	deny           answer = iota
	allowOnce             // this request only
	allowForAWhile        // this request, and a grant for grantLength
	granted               // covered by an earlier grant
	gaveUp                // the client went away before an answer
)

func (a answer) allowed() bool { return a == allowOnce || a == allowForAWhile || a == granted }

func (a answer) String() string {
	minutes := int(grantLength.Minutes())
	switch a {
	case allowOnce:
		return "approved once"
	case allowForAWhile:
		return fmt.Sprintf("approved for %d minutes", minutes)
	case granted:
		return fmt.Sprintf("within a %d-minute approval", minutes)
	case gaveUp:
		return "the client gave up waiting"
	}
	return "denied"
}

// approver asks a person before a gated secret goes out, and remembers
// "allow for a while" answers so the same kind of request doesn't ask again.
// One dialog is on screen at a time. Identical requests that arrive while one
// is being asked about wait for that answer: a deny or a grant settles them
// all, "allow once" only the request it was asked for.
type approver struct {
	ask func(context.Context, approvalRequest) answer // shows the dialog and waits for it
	now func() time.Time

	mu      sync.Mutex
	grants  map[approvalRequest]time.Time
	waiting map[approvalRequest]*pendingAnswer
	dialog  chan struct{} // holds a token while a dialog is on screen
}

type pendingAnswer struct {
	done chan struct{}
	ans  answer
}

func newApprover(ask func(context.Context, approvalRequest) answer) *approver {
	return &approver{
		ask: ask, now: time.Now,
		grants:  map[approvalRequest]time.Time{},
		waiting: map[approvalRequest]*pendingAnswer{},
		dialog:  make(chan struct{}, 1),
	}
}

// approve decides whether req may go ahead. It gives up when ctx ends, so a
// client that stops waiting doesn't leave a dialog or a queue behind.
func (a *approver) approve(ctx context.Context, req approvalRequest) answer {
	key := req.key()
	for {
		a.mu.Lock()
		if until, ok := a.grants[key]; ok {
			if a.now().Before(until) {
				a.mu.Unlock()
				return granted
			}
			delete(a.grants, key)
		}
		if w := a.waiting[key]; w != nil {
			a.mu.Unlock()
			select {
			case <-w.done:
			case <-ctx.Done():
				return gaveUp
			}
			if w.ans == deny {
				return deny
			}
			continue // a grant covers this one; after "allow once", ask again
		}
		w := &pendingAnswer{done: make(chan struct{})}
		a.waiting[key] = w
		a.mu.Unlock()

		ans := gaveUp
		select {
		case a.dialog <- struct{}{}:
			ans = a.ask(ctx, req)
			<-a.dialog
		case <-ctx.Done():
		}

		a.mu.Lock()
		if ans == allowForAWhile {
			a.grants[key] = a.now().Add(grantLength)
		}
		delete(a.waiting, key)
		w.ans = ans
		close(w.done)
		a.mu.Unlock()
		return ans
	}
}

// dialogAsk asks in a native dialog. No answer in time, or no screen to show
// it on, is a deny.
func dialogAsk(ctx context.Context, req approvalRequest) answer {
	msg := fmt.Sprintf("An agent wants to use %s.\n\nRequest: %s https://%s\nRequest path: %s",
		req.Secret, req.Method, req.Host, oneLine(req.Path, 120))
	if req.Project != "" {
		msg += "\nProject: " + req.Project
	}
	msg += fmt.Sprintf("\n\n\"Allow %d min\" covers this secret, method and host for %d minutes.",
		int(grantLength.Minutes()), int(grantLength.Minutes()))

	grant := fmt.Sprintf("Allow %d min", int(grantLength.Minutes()))
	switch showDialog(ctx, msg, []string{"Deny", "Allow once", grant}, dialogTimeout) {
	case "Allow once":
		return allowOnce
	case grant:
		return allowForAWhile
	}
	if ctx.Err() != nil {
		return gaveUp
	}
	return deny
}
